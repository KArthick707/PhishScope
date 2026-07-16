from app.ml_predictor import predict_email


def test_predict_email_returns_expected_shape():
    result = predict_email(
        "Urgent: verify your account password immediately",
        rule_features={"url_count": 1, "urgency_keyword_count": 2, "credential_keyword_count": 2, "risk_score": 30},
    )
    assert set(result.keys()) == {"prediction", "label", "phishing_probability"}
    assert result["prediction"] in (0, 1)
    assert result["label"] in ("phishing", "benign")
    assert 0.0 <= result["phishing_probability"] <= 1.0


def test_predict_email_probability_is_not_the_old_hardcoded_fallback():
    """Regression test: the model used to be unreachable (wrong path) and fall back
    to hardcoded 0.85/0.15 constants. Two different inputs should now produce two
    different, real probabilities rather than always landing on those constants."""
    r1 = predict_email("free money click now", rule_features={"url_count": 5, "urgency_keyword_count": 3, "credential_keyword_count": 3, "risk_score": 50})
    r2 = predict_email("please find attached the quarterly report", rule_features={"url_count": 0, "urgency_keyword_count": 0, "credential_keyword_count": 0, "risk_score": 0})
    assert r1["phishing_probability"] != r2["phishing_probability"]
