import base64

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import build_eml

client = TestClient(app)


def _b64url(raw_bytes: bytes) -> str:
    # Gmail's format=raw returns unpadded base64url; mimic that exactly.
    return base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")


def test_analyze_raw_phishing_email(phishing_eml_bytes):
    response = client.post("/analyze/raw", json={"raw_base64": _b64url(phishing_eml_bytes)})
    assert response.status_code == 200
    body = response.json()
    assert body["final_decision"]["final_verdict"] in (
        "phishing", "suspicious", "needs_review"
    )
    assert body["email"]["subject"] == "Urgent: Verify your account now"


def test_analyze_raw_legitimate_email(legitimate_eml_bytes):
    response = client.post("/analyze/raw", json={"raw_base64": _b64url(legitimate_eml_bytes)})
    assert response.status_code == 200
    assert response.json()["final_decision"]["final_verdict"] == "benign_or_low_risk"


def test_analyze_raw_accepts_standard_base64(legitimate_eml_bytes):
    standard = base64.b64encode(legitimate_eml_bytes).decode("ascii")
    response = client.post("/analyze/raw", json={"raw_base64": standard})
    assert response.status_code == 200


def test_analyze_raw_rejects_empty_payload():
    response = client.post("/analyze/raw", json={"raw_base64": ""})
    assert response.status_code == 400


def test_api_key_enforced_when_configured(monkeypatch, legitimate_eml_bytes):
    monkeypatch.setenv("PHISHSCOPE_API_KEY", "sekrit")
    payload = {"raw_base64": _b64url(legitimate_eml_bytes)}

    assert client.post("/analyze/raw", json=payload).status_code == 401
    assert client.post(
        "/analyze/raw", json=payload, headers={"X-API-Key": "wrong"}
    ).status_code == 401
    assert client.post(
        "/analyze/raw", json=payload, headers={"X-API-Key": "sekrit"}
    ).status_code == 200
