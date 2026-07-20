from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


PHISHING_HEADERS = "\r\n".join([
    "Subject: Urgent: Verify your account now",
    "From: Bank Security <security@totally-legit-bank-verify.tk>",
    "To: victim@example.com",
    "Reply-To: attacker@different-domain.ru",
    "Return-Path: <bounce@yet-another-domain.xyz>",
    "Received-SPF: fail (sender IP is 203.0.113.7)",
    "Date: Mon, 1 Jan 2026 12:00:00 +0000",
])

LEGIT_HEADERS = "\r\n".join([
    "Subject: Your weekly newsletter",
    "From: Newsletter <newsletter@example.com>",
    "To: reader@example.com",
    "Return-Path: <newsletter@example.com>",
    "Received-SPF: pass",
    "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=default;",
    "Date: Mon, 1 Jan 2026 12:00:00 +0000",
])


def test_outlook_phishing_headers_and_body():
    response = client.post("/analyze/outlook", json={
        "headers": PHISHING_HEADERS,
        "body_html": (
            "<p>Urgent action required! Your account has been suspended. "
            "Verify your password and login credentials immediately at "
            "<a href='http://bit.ly/fake-login'>this link</a> or your account "
            "will be closed. Confirm your account now.</p>"
        ),
    })
    assert response.status_code == 200
    body = response.json()

    # Header-derived signals must survive the headers/body split -- this is
    # the whole reason the Outlook path uses parse_headers_and_body().
    assert body["features"]["spf_fail"] is True
    assert body["features"]["dkim_missing"] is True
    assert body["features"]["reply_to_mismatch"] is True
    assert body["features"]["return_path_mismatch"] is True
    assert body["features"]["shortener_count"] > 0
    assert body["final_decision"]["final_verdict"] in ("phishing", "suspicious", "needs_review")


def test_outlook_legitimate_message():
    response = client.post("/analyze/outlook", json={
        "headers": LEGIT_HEADERS,
        "body_html": "<p>Here is your weekly newsletter. Unsubscribe anytime. "
                     "Copyright 2026 Example Inc. All rights reserved.</p>",
    })
    assert response.status_code == 200
    body = response.json()
    assert body["features"]["spf_fail"] is False
    assert body["features"]["dkim_missing"] is False
    assert body["final_decision"]["final_verdict"] == "benign_or_low_risk"


def test_outlook_attachments_counted():
    response = client.post("/analyze/outlook", json={
        "headers": LEGIT_HEADERS,
        "body_html": "<p>See attached.</p>",
        "attachments": [
            {"name": "invoice.pdf", "content_type": "application/pdf"},
            {"name": "photo.png", "content_type": "image/png"},
        ],
    })
    assert response.status_code == 200
    assert response.json()["features"]["attachment_count"] == 2


def test_outlook_empty_headers_rejected():
    response = client.post("/analyze/outlook", json={"headers": "  ", "body_html": "<p>hi</p>"})
    assert response.status_code == 400


def test_outlook_respects_api_key(monkeypatch):
    monkeypatch.setenv("PHISHSCOPE_API_KEY", "sekrit")
    payload = {"headers": LEGIT_HEADERS, "body_html": "<p>hello</p>"}

    assert client.post("/analyze/outlook", json=payload).status_code == 401
    assert client.post(
        "/analyze/outlook", json=payload, headers={"X-API-Key": "sekrit"}
    ).status_code == 200
