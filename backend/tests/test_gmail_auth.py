import json

from app import gmail_auth


def test_has_required_scope_false_when_not_connected(monkeypatch, tmp_path):
    monkeypatch.setattr(gmail_auth, "TOKEN_FILE", str(tmp_path / "missing.json"))
    assert gmail_auth.is_connected() is False
    assert gmail_auth.has_required_scope() is False


def test_has_required_scope_false_for_stale_readonly_token(monkeypatch, tmp_path):
    """Regression test: SCOPES was broadened from gmail.readonly to
    gmail.modify to support label-based triage. A token saved under the old
    scope must be detected as insufficient, not silently treated as valid
    (which would surface as an opaque 403 deep inside the triage worker)."""
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({
        "token": "x", "refresh_token": "y", "token_uri": "z",
        "client_id": "a", "client_secret": "b",
        "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
    }))
    monkeypatch.setattr(gmail_auth, "TOKEN_FILE", str(token_file))

    assert gmail_auth.is_connected() is True
    assert gmail_auth.has_required_scope() is False


def test_has_required_scope_true_for_current_token(monkeypatch, tmp_path):
    token_file = tmp_path / "token.json"
    token_file.write_text(json.dumps({
        "token": "x", "refresh_token": "y", "token_uri": "z",
        "client_id": "a", "client_secret": "b",
        "scopes": gmail_auth.SCOPES,
    }))
    monkeypatch.setattr(gmail_auth, "TOKEN_FILE", str(token_file))

    assert gmail_auth.has_required_scope() is True
