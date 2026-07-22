"""Tests for the four enrichment tools. WHOIS/DNS/HTTP are mocked at the tool
seams; every tool must return a dict carrying ``signal`` and ``summary`` and must
never raise into the agent loop."""

from datetime import datetime, timedelta, timezone

from app.investigator import net_guard, tools
from app.investigator.schemas import SIGNAL_BENIGN, SIGNAL_MALICIOUS, SIGNAL_NEUTRAL


class _FakeWhois:
    def __init__(self, creation_date, registrar="Test Registrar"):
        self.creation_date = creation_date
        self.registrar = registrar


def test_whois_fresh_domain_is_malicious(monkeypatch):
    monkeypatch.setattr(tools, "_whois_raw",
                        lambda d: _FakeWhois(datetime.now(timezone.utc) - timedelta(days=3)))
    result = tools.whois_domain_age("brand-new-login.tk")
    assert result["signal"] == SIGNAL_MALICIOUS
    assert result["age_days"] == 3


def test_whois_old_domain_is_benign(monkeypatch):
    monkeypatch.setattr(tools, "_whois_raw",
                        lambda d: _FakeWhois(datetime.now(timezone.utc) - timedelta(days=4000)))
    result = tools.whois_domain_age("github.com")
    assert result["signal"] == SIGNAL_BENIGN


def test_whois_lookup_failure_is_neutral_not_raising(monkeypatch):
    def _boom(domain):
        raise RuntimeError("whois server timed out")
    monkeypatch.setattr(tools, "_whois_raw", _boom)
    result = tools.whois_domain_age("example.com")
    assert result["signal"] == SIGNAL_NEUTRAL
    assert result["age_days"] is None


def test_whois_ip_address_is_neutral():
    result = tools.whois_domain_age("203.0.113.7")
    assert result["signal"] == SIGNAL_NEUTRAL
    assert result["error"] == "not_a_registrable_domain"


def test_dns_private_a_record_is_malicious(monkeypatch):
    monkeypatch.setattr(tools, "_dns_query",
                        lambda d, t: ["10.0.0.9"] if t == "A" else [])
    result = tools.dns_lookup("sneaky.example")
    assert result["signal"] == SIGNAL_MALICIOUS
    assert result["a_records"] == ["10.0.0.9"]


def test_dns_resolves_with_mx_is_benign(monkeypatch):
    monkeypatch.setattr(tools, "_dns_query",
                        lambda d, t: ["93.184.216.34"] if t == "A" else ["mx1"])
    result = tools.dns_lookup("example.com")
    assert result["signal"] == SIGNAL_BENIGN
    assert result["mx_present"] is True


def test_follow_redirects_cross_domain_is_malicious(monkeypatch):
    monkeypatch.setattr(net_guard, "follow_redirect_chain", lambda url, **kw: {
        "chain": [{"url": url, "status": 302}, {"url": "http://evil.ru/login", "status": 200}],
        "final_url": "http://evil.ru/login", "final_domain": "evil.ru",
        "hops": 2, "blocked_reason": None,
    })
    result = tools.follow_redirects("http://bit.ly/abc")
    assert result["signal"] == SIGNAL_MALICIOUS


def test_follow_redirects_blocked_private_is_malicious(monkeypatch):
    monkeypatch.setattr(net_guard, "follow_redirect_chain", lambda url, **kw: {
        "chain": [], "final_url": url, "final_domain": "",
        "hops": 0, "blocked_reason": "resolves_to_private_ip:internal->10.0.0.1",
    })
    result = tools.follow_redirects("http://internal.example/")
    assert result["signal"] == SIGNAL_MALICIOUS


def test_follow_redirects_same_domain_is_benign(monkeypatch):
    monkeypatch.setattr(net_guard, "follow_redirect_chain", lambda url, **kw: {
        "chain": [{"url": url, "status": 200}],
        "final_url": "http://example.com/home", "final_domain": "example.com",
        "hops": 1, "blocked_reason": None,
    })
    result = tools.follow_redirects("http://example.com/")
    assert result["signal"] == SIGNAL_BENIGN


def _parsed_and_analysis(sender_domain, body, *, spf_fail=False, dkim_missing=False,
                         return_path_mismatch=False):
    parsed = {"email": {"from": f"x@{sender_domain}"}, "body": {"text": body, "preview": body, "html": ""}}
    analysis = {"features": {
        "sender_domain": sender_domain, "spf_fail": spf_fail, "dkim_missing": dkim_missing,
        "dmarc_fail": False, "return_path_mismatch": return_path_mismatch, "reply_to_mismatch": False,
    }}
    return parsed, analysis


def test_cross_check_headers_brand_impersonation_is_malicious():
    parsed, analysis = _parsed_and_analysis(
        "totally-legit-verify.tk", "Please sign in to your Microsoft account to continue."
    )
    result = tools.cross_check_headers(parsed, analysis)
    assert result["signal"] == SIGNAL_MALICIOUS
    assert "microsoft" in result["impersonated_brands"]


def test_cross_check_headers_aligned_brand_is_benign():
    parsed, analysis = _parsed_and_analysis(
        "microsoft.com", "Your Microsoft account security info was updated."
    )
    result = tools.cross_check_headers(parsed, analysis)
    assert result["signal"] == SIGNAL_BENIGN
    assert result["impersonated_brands"] == []


def test_cross_check_headers_auth_failure_is_malicious():
    parsed, analysis = _parsed_and_analysis(
        "newsletter.example", "Here is your weekly update.", spf_fail=True
    )
    result = tools.cross_check_headers(parsed, analysis)
    assert result["signal"] == SIGNAL_MALICIOUS
    assert result["spf_fail"] is True
