"""Agent-loop tests. The Anthropic client is replaced with a fake that yields a
scripted tool_use -> text sequence, so no real LLM or network is touched. The
tool the agent 'calls' is cross_check_headers, which itself does no network I/O."""

import pytest

from app.investigator import agent, config
from app.investigator.agent import InvestigatorNotConfigured, fuse_recommendation
from app.investigator.schemas import (
    SIGNAL_BENIGN,
    SIGNAL_MALICIOUS,
    VERDICT_BENIGN,
    VERDICT_PHISHING,
    VERDICT_SUSPICIOUS,
    VERDICT_UNCHANGED,
)


class _Block:
    def __init__(self, type, text=None, id=None, name=None, input=None):
        self.type = type
        self.text = text
        self.id = id
        self.name = name
        self.input = input


class _Resp:
    def __init__(self, content):
        self.content = content


class _FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def create(self, **kwargs):
        resp = self._responses[min(self.calls, len(self._responses) - 1)]
        self.calls += 1
        return resp


class _FakeClient:
    def __init__(self, responses):
        self.messages = _FakeMessages(responses)


def _borderline_email():
    parsed = {
        "email": {"from": "Security <security@totally-legit-verify.tk>", "return_path": "", "reply_to": ""},
        "body": {"text": "Sign in to your Microsoft account to avoid suspension.",
                 "preview": "Sign in to your Microsoft account to avoid suspension.", "html": ""},
        "urls": [],
    }
    analysis = {
        "final_decision": {"final_verdict": "suspicious", "confidence": 70,
                           "rule_score": 20, "ml_adjusted_probability": 0.5},
        "features": {"sender_domain": "totally-legit-verify.tk", "spf_fail": True,
                     "dkim_missing": True, "dmarc_fail": False,
                     "return_path_mismatch": False, "reply_to_mismatch": False},
    }
    return parsed, analysis


def test_run_investigation_executes_tools_and_summarizes(monkeypatch):
    monkeypatch.setattr(config, "has_api_key", lambda: True)
    scripted = [
        _Resp([_Block("tool_use", id="t1", name="cross_check_headers", input={})]),
        _Resp([_Block("text", text="The body impersonates Microsoft from an untrusted .tk domain with failing SPF/DKIM.")]),
    ]
    monkeypatch.setattr(agent, "_build_client", lambda: _FakeClient(scripted))

    parsed, analysis = _borderline_email()
    result = agent.run_investigation(parsed, analysis)

    assert result["investigated"] is True
    assert result["tools_used"] == ["cross_check_headers"]
    assert len(result["evidence_trail"]) == 1
    assert result["evidence_trail"][0]["signal"] == SIGNAL_MALICIOUS
    assert "Microsoft" in result["agent_summary"]
    assert result["budget"]["stopped_reason"] == "completed"
    # One malicious signal -> suspicious (see fuse_recommendation).
    assert result["recommended_verdict"] == VERDICT_SUSPICIOUS


def test_run_investigation_enforces_tool_budget(monkeypatch):
    monkeypatch.setattr(config, "has_api_key", lambda: True)
    monkeypatch.setattr(config, "get_max_tool_calls", lambda: 2)
    # The model never stops calling tools; the budget must stop the loop.
    always_tool = _Resp([_Block("tool_use", id="t", name="cross_check_headers", input={})])
    monkeypatch.setattr(agent, "_build_client", lambda: _FakeClient([always_tool]))

    parsed, analysis = _borderline_email()
    result = agent.run_investigation(parsed, analysis)

    assert result["budget"]["tool_calls"] == 2
    assert result["budget"]["stopped_reason"] == "max_tool_calls"


def test_run_investigation_requires_api_key(monkeypatch):
    monkeypatch.setattr(config, "has_api_key", lambda: False)
    parsed, analysis = _borderline_email()
    with pytest.raises(InvestigatorNotConfigured):
        agent.run_investigation(parsed, analysis)


# --- fuse_recommendation (the deterministic sanity layer over the LLM) --------

def _step(tool, signal, finding=None):
    return {"tool": tool, "signal": signal, "finding": finding or {}}


def test_fuse_two_malicious_signals_is_phishing():
    trail = [_step("dns_lookup", SIGNAL_MALICIOUS), _step("cross_check_headers", SIGNAL_MALICIOUS)]
    assert fuse_recommendation(trail, {}) == VERDICT_PHISHING


def test_fuse_fresh_domain_plus_impersonation_is_phishing():
    trail = [
        _step("whois_domain_age", SIGNAL_MALICIOUS, {"age_days": 3}),
        _step("cross_check_headers", SIGNAL_MALICIOUS, {"impersonated_brands": ["microsoft"]}),
    ]
    assert fuse_recommendation(trail, {}) == VERDICT_PHISHING


def test_fuse_single_malicious_is_suspicious():
    assert fuse_recommendation([_step("dns_lookup", SIGNAL_MALICIOUS)], {}) == VERDICT_SUSPICIOUS


def test_fuse_multiple_benign_is_benign():
    trail = [_step("whois_domain_age", SIGNAL_BENIGN), _step("dns_lookup", SIGNAL_BENIGN)]
    assert fuse_recommendation(trail, {}) == VERDICT_BENIGN


def test_fuse_no_evidence_is_unchanged():
    assert fuse_recommendation([], {}) == VERDICT_UNCHANGED
