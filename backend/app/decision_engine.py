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

    if unsubscribe_present and marketing_email_score >= 2 and not auth_failed:
        adjusted *= 0.75
        reasons.append(
            "Reduced ML phishing confidence because the email matches a legitimate marketing or notification pattern."
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

    elif rule_score >= 60:
        final = {
            "final_verdict": "phishing",
            "confidence": 85,
            "risk_reason_type": "strong_rule_evidence",
            "reason": (
                "The rule engine found strong phishing indicators."
            )
        }

    elif adjusted_probability >= 0.55 and rule_score < 25:
        final = {
            "final_verdict": "needs_review",
            "confidence": 65,
            "risk_reason_type": "ml_rule_conflict",
            "reason": (
                "The ML model detected phishing-like patterns, but rule-based evidence is weak. "
                "Manual review is recommended."
            )
        }

    elif rule_score >= 25 or adjusted_probability >= 0.55:
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