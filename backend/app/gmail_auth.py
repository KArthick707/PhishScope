import os
import json

from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleAuthRequest

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# MVP simplification: single local user, token kept in a gitignored file next to
# the backend. A hosted multi-user version would need per-user encrypted storage
# in a real database instead.
TOKEN_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".gmail_token.json")

REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")

# oauthlib refuses token exchanges over plain http (tokens must not transit a
# network unencrypted). Localhost never touches the network, so allow the
# documented exception -- but only when the redirect really is localhost, so a
# production https deployment keeps strict transport checks.
if REDIRECT_URI.startswith(("http://localhost", "http://127.0.0.1")):
    os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")

# Holds the OAuth `state` and PKCE code verifier between the /login redirect
# and the /callback request. The library enables PKCE by default: the Flow that
# builds the auth URL generates a code_verifier that MUST be replayed at token
# exchange, so it has to survive across the two requests (we construct a fresh
# Flow in each). Only correct for a single concurrent login -- fine for the
# single-user MVP.
_pending_state = {"value": None, "code_verifier": None}


def _client_config():
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise RuntimeError(
            "GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are not set. "
            "Create OAuth credentials in Google Cloud Console and set them as env vars."
        )
    return {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [REDIRECT_URI],
        }
    }


def build_authorization_url() -> str:
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES, redirect_uri=REDIRECT_URI)
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    _pending_state["value"] = state
    _pending_state["code_verifier"] = flow.code_verifier
    return auth_url


def exchange_code_for_token(callback_url: str) -> None:
    flow = Flow.from_client_config(
        _client_config(), scopes=SCOPES, redirect_uri=REDIRECT_URI, state=_pending_state["value"]
    )
    if _pending_state.get("code_verifier"):
        flow.code_verifier = _pending_state["code_verifier"]
    flow.fetch_token(authorization_response=callback_url)
    _save_credentials(flow.credentials)


def _save_credentials(credentials: Credentials) -> None:
    data = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
    }
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)


def is_connected() -> bool:
    return os.path.exists(TOKEN_FILE)


def get_credentials() -> Credentials:
    if not is_connected():
        raise RuntimeError("Gmail is not connected yet. Visit /auth/google/login first.")

    with open(TOKEN_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    credentials = Credentials(
        token=data["token"],
        refresh_token=data["refresh_token"],
        token_uri=data["token_uri"],
        client_id=data["client_id"],
        client_secret=data["client_secret"],
        scopes=data["scopes"],
    )

    if credentials.expired and credentials.refresh_token:
        credentials.refresh(GoogleAuthRequest())
        _save_credentials(credentials)

    return credentials


def disconnect() -> None:
    if os.path.exists(TOKEN_FILE):
        os.remove(TOKEN_FILE)
