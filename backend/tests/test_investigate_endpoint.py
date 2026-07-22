"""Endpoint tests for /investigate (and the /analyze/eml gate side-fix). The
investigator agent is stubbed via monkeypatch -- no real LLM/network -- except in
the 503 path, which exercises the real 'no API key' guard."""

import base64

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()


def _stub_investigation(parsed, analysis):
    return {
        "investigated": True, "agent_summary": "stub", "recommended_verdict": "phishing",
        "evidence_trail": [], "tools_used": [], "budget": {"stopped_reason": "completed"}, "reason": "",
    }


def test_investigate_runs_when_forced(monkeypatch, phishing_eml_bytes):
    monkeypatch.delenv("PHISHSCOPE_API_KEY", raising=False)
    monkeypatch.setattr("app.main.run_investigation", _stub_investigation)
    resp = client.post("/investigate", json={"raw_base64": _b64(phishing_eml_bytes), "force": True})
    assert resp.status_code == 200
    body = resp.json()
    assert body["investigation"]["investigated"] is True
    assert "final_decision" in body  # the full analysis is returned alongside


def test_investigate_runs_when_gate_says_borderline(monkeypatch, phishing_eml_bytes):
    monkeypatch.delenv("PHISHSCOPE_API_KEY", raising=False)
    monkeypatch.setattr("app.main.should_investigate", lambda decision: True)
    monkeypatch.setattr("app.main.run_investigation", _stub_investigation)
    resp = client.post("/investigate", json={"raw_base64": _b64(phishing_eml_bytes)})
    assert resp.status_code == 200
    assert resp.json()["investigation"]["investigated"] is True


def test_investigate_skips_non_borderline(monkeypatch, legitimate_eml_bytes):
    monkeypatch.delenv("PHISHSCOPE_API_KEY", raising=False)
    monkeypatch.setattr("app.main.should_investigate", lambda decision: False)
    resp = client.post("/investigate", json={"raw_base64": _b64(legitimate_eml_bytes)})
    assert resp.status_code == 200
    inv = resp.json()["investigation"]
    assert inv["investigated"] is False
    assert "borderline" in inv["reason"]


def test_investigate_503_without_anthropic_key(monkeypatch, phishing_eml_bytes):
    # Real agent path: no ANTHROPIC_API_KEY -> InvestigatorNotConfigured -> 503.
    monkeypatch.delenv("PHISHSCOPE_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    resp = client.post("/investigate", json={"raw_base64": _b64(phishing_eml_bytes), "force": True})
    assert resp.status_code == 503


def test_investigate_api_key_gate(monkeypatch, phishing_eml_bytes):
    monkeypatch.setenv("PHISHSCOPE_API_KEY", "sekrit")
    resp = client.post("/investigate", json={"raw_base64": _b64(phishing_eml_bytes), "force": True})
    assert resp.status_code == 401  # missing X-API-Key


def test_investigate_requires_some_input(monkeypatch):
    monkeypatch.delenv("PHISHSCOPE_API_KEY", raising=False)
    resp = client.post("/investigate", json={"force": True})
    assert resp.status_code == 400


def test_analyze_eml_now_gated(monkeypatch, phishing_eml_bytes):
    # Side-fix: /analyze/eml previously had no API-key gate.
    monkeypatch.setenv("PHISHSCOPE_API_KEY", "sekrit")
    resp = client.post("/analyze/eml", files={"file": ("m.eml", phishing_eml_bytes, "message/rfc822")})
    assert resp.status_code == 401
