from app.decision_engine import make_final_decision, adjust_ml_probability


def _features(**overrides):
    base = {
        "trusted_domain_match": False,
        "trusted_sender_domain": False,
        "trusted_return_path_domain": False,
        "spf_fail": False,
        "dmarc_fail": False,
        "dkim_missing": False,
        "unsubscribe_present": False,
        "marketing_email_score": 0,
        "social_link_count": 0,
    }
    base.update(overrides)
    return base


def _rule_result(score, verdict="benign_or_low_risk"):
    return {"score": score, "verdict": verdict}


def _ml_result(probability, prediction=1, label="phishing"):
    return {"prediction": prediction, "label": label, "phishing_probability": probability}


def test_high_ml_confidence_alone_yields_phishing_verdict():
    """Regression test: previously the 'phishing' verdict required rule_score>=40
    even when ML confidence was very high, which was empirically unreachable for
    most real emails (validated: flag rate was 0.0% before the fix)."""
    final = make_final_decision(
        rule_result=_rule_result(score=15),
        ml_result=_ml_result(probability=0.90),
        features=_features(),
    )
    assert final["final_verdict"] == "phishing"
    assert final["risk_reason_type"] == "ml_high_confidence"


def test_high_ml_confidence_and_high_rule_score_agree():
    final = make_final_decision(
        rule_result=_rule_result(score=45),
        ml_result=_ml_result(probability=0.90),
        features=_features(),
    )
    assert final["final_verdict"] == "phishing"
    assert final["risk_reason_type"] == "ml_and_rules_agree"
    assert final["confidence"] == 95


def test_strong_rule_evidence_alone_yields_phishing():
    final = make_final_decision(
        rule_result=_rule_result(score=65),
        ml_result=_ml_result(probability=0.10, prediction=0, label="benign"),
        features=_features(),
    )
    assert final["final_verdict"] == "phishing"
    assert final["risk_reason_type"] == "strong_rule_evidence"


def test_low_signals_yield_benign():
    final = make_final_decision(
        rule_result=_rule_result(score=5),
        ml_result=_ml_result(probability=0.10, prediction=0, label="benign"),
        features=_features(),
    )
    assert final["final_verdict"] == "benign_or_low_risk"


def test_trusted_domain_safeguard_overrides_to_benign():
    final = make_final_decision(
        rule_result=_rule_result(score=5),
        ml_result=_ml_result(probability=0.30, prediction=0, label="benign"),
        features=_features(
            trusted_domain_match=True,
            trusted_sender_domain=True,
            trusted_return_path_domain=True,
        ),
    )
    assert final["final_verdict"] == "benign_or_low_risk"
    assert final["risk_reason_type"] == "trusted_legitimate_notification"


def test_marketing_pattern_adjustment_is_mild_not_aggressive():
    """Regression test: the marketing-pattern multiplier was 0.75, which could pull
    a high-confidence phishing score (e.g. 0.995) below the 0.80 verdict threshold.
    Validated against real labeled data that this pattern is also used by real
    phishing (2/44 real trigger hits). Multiplier softened to 0.90 so a strong raw
    ML score still clears 0.80 after adjustment."""
    adjustment = adjust_ml_probability(
        ml_probability=0.995,
        features=_features(unsubscribe_present=True, marketing_email_score=3),
        rule_score=0,
    )
    assert adjustment["adjusted_probability"] >= 0.80

    final = make_final_decision(
        rule_result=_rule_result(score=0),
        ml_result=_ml_result(probability=0.995),
        features=_features(unsubscribe_present=True, marketing_email_score=3),
    )
    assert final["final_verdict"] == "phishing"


def test_ml_rule_conflict_flagged_for_review():
    final = make_final_decision(
        rule_result=_rule_result(score=5),
        ml_result=_ml_result(probability=0.60),
        features=_features(),
    )
    assert final["final_verdict"] == "needs_review"
    assert final["risk_reason_type"] == "ml_rule_conflict"
