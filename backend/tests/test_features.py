from app.parser import parse_eml_bytes
from app.features import extract_features


def test_phishing_email_flags_expected_signals(phishing_eml_bytes):
    parsed = parse_eml_bytes(phishing_eml_bytes)
    features = extract_features(parsed)

    assert features["spf_fail"] is True
    assert features["dkim_missing"] is True
    assert features["reply_to_mismatch"] is True
    assert features["return_path_mismatch"] is True
    assert features["urgency_keyword_count"] > 0
    assert features["credential_keyword_count"] > 0
    assert features["shortener_count"] > 0


def test_legitimate_email_does_not_flag_auth_failures(legitimate_eml_bytes):
    parsed = parse_eml_bytes(legitimate_eml_bytes)
    features = extract_features(parsed)

    assert features["spf_fail"] is False
    assert features["dkim_missing"] is False
    assert features["reply_to_mismatch"] is False
    assert features["return_path_mismatch"] is False


def test_marketing_signals_detected(legitimate_eml_bytes):
    parsed = parse_eml_bytes(legitimate_eml_bytes)
    features = extract_features(parsed)

    assert features["unsubscribe_present"] is True
    assert features["copyright_present"] is True
    assert features["marketing_email_score"] >= 2
