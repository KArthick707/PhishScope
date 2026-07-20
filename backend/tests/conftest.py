import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


def build_eml(
    subject="Test subject",
    sender="sender@example.com",
    to="recipient@example.com",
    reply_to="",
    return_path="",
    spf="",
    dkim=True,
    authentication_results="",
    body_text="Hello, this is a test email.",
    body_html="",
):
    headers = [
        f"Subject: {subject}",
        f"From: {sender}",
        f"To: {to}",
        "Date: Mon, 1 Jan 2026 12:00:00 +0000",
    ]
    if reply_to:
        headers.append(f"Reply-To: {reply_to}")
    if return_path:
        headers.append(f"Return-Path: <{return_path}>")
    if spf:
        headers.append(f"Received-SPF: {spf}")
    if authentication_results:
        headers.append(f"Authentication-Results: {authentication_results}")
    if dkim:
        headers.append("DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=default;")

    if body_html:
        headers.append('Content-Type: text/html; charset="utf-8"')
        headers.append("")
        body = body_html
    else:
        headers.append('Content-Type: text/plain; charset="utf-8"')
        headers.append("")
        body = body_text

    return ("\r\n".join(headers) + "\r\n" + body).encode("utf-8")


@pytest.fixture
def phishing_eml_bytes():
    return build_eml(
        subject="Urgent: Verify your account now",
        sender="Bank Security <security@totally-legit-bank-verify.tk>",
        reply_to="attacker@different-domain.ru",
        return_path="bounce@yet-another-domain.xyz",
        spf="fail",
        dkim=False,
        body_text=(
            "Urgent action required! Your account has been suspended. "
            "Verify your password and login credentials immediately at "
            "http://bit.ly/fake-login-link or your account will be closed. "
            "Confirm your account now."
        ),
    )


@pytest.fixture
def legitimate_eml_bytes():
    return build_eml(
        subject="Your weekly newsletter",
        sender="Newsletter <newsletter@example.com>",
        return_path="newsletter@example.com",
        spf="pass",
        dkim=True,
        body_text=(
            "Hi there, here is your weekly newsletter with the latest updates. "
            "Unsubscribe at any time. Copyright 2026 Example Inc. All rights reserved."
        ),
    )
