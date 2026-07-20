def authentication_failed(features: dict) -> bool:
    return (
        features.get("spf_fail", False)
        or features.get("dmarc_fail", False)
        or features.get("dkim_fail", False)
        or features.get("dkim_missing", False)
    )


def adjust_ml_probability(
    ml_probability: float,
    features: dict,
    rule_score: int
) -> dict:
    adjusted = ml_probability
    reasons = []

    trusted_domain_match = features.get("trusted_domain_match", False)
    trusted_sender_domain = features.get("trusted_sender_domain", False)
    trusted_return_path_domain = features.get("trusted_return_path_domain", False)
    unsubscribe_present = features.get("unsubscribe_present", False)
    marketing_email_score = features.get("marketing_email_score", 0)
    social_link_count = features.get("social_link_count", 0)

    auth_failed = authentication_failed(features)

    if trusted_domain_match and not auth_failed and rule_score <= 10:
        adjusted *= 0.40
        reasons.append(
            "Reduced ML phishing confidence because trusted sender alignment, clean authentication, and low rule score were detected."
        )

    if trusted_sender_domain and trusted_return_path_domain and not auth_failed:
        adjusted *= 0.70
        reasons.append(
            "Reduced ML phishing confidence because sender and return-path belong to trusted infrastructure."
        )

    # Validated against real labeled data: this trigger fires on real phishing
    # emails that mimic marketing formatting (unsubscribe link + promo language)
    # -- 2/44 real trigger hits were actual phishing, and risk_score does not
    # separate them from genuine marketing email (overlapping distributions).
    # Multiplier kept mild (0.90, not 0.75) so this alone can't pull a
    # high-confidence phishing score below the verdict threshold.
    if unsubscribe_present and marketing_email_score >= 2 and not auth_failed:
        adjusted *= 0.90
        reasons.append(
            "Slightly reduced ML phishing confidence because the email matches a marketing or notification pattern "
            "(kept mild since this pattern can also be mimicked by phishing)."
        )

    if social_link_count >= 5 and trusted_domain_match and not auth_failed:
        adjusted *= 0.80
        reasons.append(
            "Reduced ML phishing confidence because many links appear to belong to a trusted social platform notification."
        )

    adjusted = max(0.0, min(adjusted, 1.0))

    return {
        "original_probability": round(ml_probability, 4),
        "adjusted_probability": round(adjusted, 4),
        "adjustment_reasons": reasons
    }


def label_from_probability(probability: float) -> str:
    if probability >= 0.80:
        return "phishing"

    if probability >= 0.55:
        return "suspicious"

    return "benign"


def make_final_decision(
    rule_result: dict,
    ml_result: dict,
    features: dict
) -> dict:
    rule_score = rule_result.get("score", 0)
    rule_verdict = rule_result.get("verdict", "unknown")

    raw_probability = float(ml_result.get("phishing_probability", 0.0))

    adjustment = adjust_ml_probability(
        ml_probability=raw_probability,
        features=features,
        rule_score=rule_score
    )

    adjusted_probability = adjustment["adjusted_probability"]
    adjusted_label = label_from_probability(adjusted_probability)

    trusted_domain_match = features.get("trusted_domain_match", False)
    trusted_sender_domain = features.get("trusted_sender_domain", False)
    trusted_return_path_domain = features.get("trusted_return_path_domain", False)
    auth_failed = authentication_failed(features)

    # TODO(founder decision): define when the ML model is "confidently benign"
    # enough that rule_score alone should NOT escalate a message to "suspicious".
    #
    # This single threshold encodes PhishScope's false-positive vs false-negative
    # risk appetite. On the observed false positives the ML probabilities were
    # 0.21-0.28 (legit marketing), while borderline/needs-review mail tends to
    # sit around 0.4-0.55. So a ceiling somewhere in 0.30-0.40 clears the
    # marketing false positives while still letting rules speak on anything the
    # ML is even mildly unsure about.
    #
    #   Lower ceiling (e.g. 0.30) = more cautious: rules keep escalating unless
    #     ML is very sure it's safe. Fewer missed phishing, more false positives.
    #   Higher ceiling (e.g. 0.45) = more trusting of the ML: quieter inbox,
    #     but rules are silenced on more mail.
    #
    ML_BENIGN_CEILING = 0.35
    ml_confidently_benign = adjusted_probability < ML_BENIGN_CEILING

    if (
        trusted_domain_match
        and trusted_sender_domain
        and trusted_return_path_domain
        and not auth_failed
        and rule_score <= 10
        and adjusted_probability < 0.55
    ):
        final = {
            "final_verdict": "benign_or_low_risk",
            "confidence": 90,
            "risk_reason_type": "trusted_legitimate_notification",
            "reason": (
                "The email appears to be a legitimate trusted notification. "
                "Sender and return-path infrastructure are trusted, authentication did not fail, "
                "rule score is low, and adjusted ML phishing probability is low."
            )
        }

    elif adjusted_probability >= 0.80 and rule_score >= 40:
        final = {
            "final_verdict": "phishing",
            "confidence": 95,
            "risk_reason_type": "ml_and_rules_agree",
            "reason": (
                "Both the ML model and rule-based engine indicate phishing risk."
            )
        }

    # Requiring rule_score>=40 here as well (as the branch above does) makes the
    # "phishing" verdict nearly unreachable: rule_score rarely clears 40 even for
    # confirmed phishing emails, while the calibrated ML probability alone is a
    # reliable signal (validated via threshold ablation: p>=0.5 alone reaches
    # F1=0.99 on held-out data). So a high-confidence ML score is sufficient on
    # its own, with rule_score only affecting the confidence/verdict label.
    elif adjusted_probability >= 0.80:
        final = {
            "final_verdict": "phishing",
            "confidence": 85,
            "risk_reason_type": "ml_high_confidence",
            "reason": (
                "The ML model detected strong phishing indicators with high confidence, "
                "even though rule-based evidence alone was limited."
            )
        }

    elif rule_score >= 60:
        final = {
            "final_verdict": "phishing",
            "confidence": 80,
            "risk_reason_type": "strong_rule_evidence",
            "reason": (
                "The rule engine found strong phishing indicators, though the ML model "
                "was less confident. Recommend review."
            )
        }

    elif adjusted_probability >= 0.55 and rule_score < 15:
        final = {
            "final_verdict": "needs_review",
            "confidence": 60,
            "risk_reason_type": "ml_rule_conflict",
            "reason": (
                "The ML model detected phishing-like patterns, but rule-based evidence is weak. "
                "Manual review is recommended."
            )
        }

    # A confidently-benign ML verdict with passing authentication should not be
    # escalated to "suspicious" by rule_score alone. Several rules (many_urls,
    # tracking_pixel, html_obfuscation) fire on essentially all legitimate bulk
    # marketing mail, so on their own they produce false positives the ML model
    # already correctly rates as benign. Real phishing is unaffected: it carries
    # a high ML probability or fails authentication, so it never reaches here.
    elif (rule_score >= 25 and not (ml_confidently_benign and not auth_failed)) or adjusted_probability >= 0.55:
        final = {
            "final_verdict": "suspicious",
            "confidence": 70,
            "risk_reason_type": "moderate_risk",
            "reason": (
                "The email contains moderate risk indicators and should be reviewed carefully."
            )
        }

    else:
        final = {
            "final_verdict": "benign_or_low_risk",
            "confidence": 80,
            "risk_reason_type": "low_combined_risk",
            "reason": (
                "No strong phishing indicators were detected by either the rule engine or adjusted ML decision layer."
            )
        }

    final.update({
        "rule_verdict": rule_verdict,
        "rule_score": rule_score,
        "ml_raw_label": ml_result.get("label"),
        "ml_raw_probability": raw_probability,
        "ml_adjusted_label": adjusted_label,
        "ml_adjusted_probability": adjusted_probability,
        "ml_adjustment_reasons": adjustment["adjustment_reasons"],
        "trusted_domain_match": trusted_domain_match,
        "trusted_sender_domain": trusted_sender_domain,
        "trusted_return_path_domain": trusted_return_path_domain,
        "authentication_failed": auth_failed
    })

    return final