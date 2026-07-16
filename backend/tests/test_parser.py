from app.parser import parse_eml_bytes


def test_parses_basic_fields(legitimate_eml_bytes):
    parsed = parse_eml_bytes(legitimate_eml_bytes)
    assert parsed["email"]["subject"] == "Your weekly newsletter"
    assert "newsletter@example.com" in parsed["email"]["from"]


def test_extracts_urls(phishing_eml_bytes):
    parsed = parse_eml_bytes(phishing_eml_bytes)
    assert any("bit.ly" in url for url in parsed["urls"])
    assert parsed["url_count"] == len(parsed["urls"])


def test_no_urls_when_absent(legitimate_eml_bytes):
    parsed = parse_eml_bytes(legitimate_eml_bytes)
    assert parsed["urls"] == []


def test_body_preview_is_capped():
    from tests.conftest import build_eml
    long_body = "a" * 5000
    parsed = parse_eml_bytes(build_eml(body_text=long_body))
    assert len(parsed["body"]["preview"]) <= 1000
