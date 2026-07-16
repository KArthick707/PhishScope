from app.parser import parse_eml_bytes
from app.features import extract_features
from app.scorer import score_email
from app.explainer import explain_prediction, explain_ml_prediction


def test_explain_prediction_lists_triggered_evidence(phishing_eml_bytes):
    parsed = parse_eml_bytes(phishing_eml_bytes)
    features = extract_features(parsed)
    rule_result = score_email(features)

    explanation = explain_prediction(features=features, rule_result=rule_result, ml_prediction=1)

    assert explanation["evidence_count"] == len(explanation["evidence"])
    evidence_types = {item["type"] for item in explanation["evidence"]}
    assert "urgency_language" in evidence_types
    assert "credential_request" in evidence_types


def test_explain_ml_prediction_returns_tokens_and_intercept():
    result = explain_ml_prediction(
        "Urgent: verify your account password immediately or it will be suspended",
        {"url_count": 1, "urgency_keyword_count": 2, "credential_keyword_count": 2, "risk_score": 30},
    )
    assert "top_tokens" in result
    assert "rule_feature_contributions" in result
    assert "intercept" in result
    assert len(result["rule_feature_contributions"]) == 5
