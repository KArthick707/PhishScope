from app.parser import parse_eml_bytes
from app.features import extract_features
from app.scorer import score_email


def test_phishing_email_scores_higher_than_legitimate(phishing_eml_bytes, legitimate_eml_bytes):
    phishing_score = score_email(extract_features(parse_eml_bytes(phishing_eml_bytes)))
    legit_score = score_email(extract_features(parse_eml_bytes(legitimate_eml_bytes)))

    assert phishing_score["score"] > legit_score["score"]
    assert phishing_score["verdict"] in ("suspicious", "likely_phishing")
    assert legit_score["verdict"] == "benign_or_low_risk"


def test_evidence_lists_triggered_rules(phishing_eml_bytes):
    result = score_email(extract_features(parse_eml_bytes(phishing_eml_bytes)))
    rule_names = {item["rule"] for item in result["evidence"]}
    assert "url_shortener" in rule_names
    assert "urgency_language" in rule_names
    assert "credential_request" in rule_names


def test_score_never_exceeds_100(phishing_eml_bytes):
    result = score_email(extract_features(parse_eml_bytes(phishing_eml_bytes)))
    assert 0 <= result["score"] <= 100
