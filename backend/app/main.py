import asyncio
import base64
import binascii
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from fastapi.middleware.cors import CORSMiddleware

from app.parser import parse_eml_bytes, parse_headers_and_body
from app.pipeline import analyze_parsed_email
from app import gmail_auth
from app.gmail_client import fetch_recent_raw_messages
from app import triage_worker
from app.investigator import (
    InvestigatorNotConfigured,
    run_investigation,
    should_investigate,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Always launched; the loop itself is a no-op each cycle until Gmail is
    # connected with the required scope (see triage_worker._run_one_cycle),
    # so there's nothing to gate here at startup time.
    task = asyncio.create_task(triage_worker.run_triage_loop())
    yield
    task.cancel()


app = FastAPI(
    title="PhishScope API",
    description="Explainable conflict-aware hybrid phishing email detection system.",
    version="0.4.1",
    lifespan=lifespan,
)

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates"))

# The Outlook add-in taskpane is browser JavaScript served from its own origin
# (e.g. https://localhost:3000 in dev), so its calls to this API are cross-origin.
# Origins are opt-in via env var; unset means no CORS headers at all (the Gmail
# add-on doesn't need any -- Apps Script calls server-to-server).
_cors_origins = [o.strip() for o in os.environ.get("PHISHSCOPE_CORS_ORIGINS", "").split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=["POST"],
        allow_headers=["Content-Type", "X-API-Key"],
    )


@app.get("/")
def root():
    return {
        "project": "PhishScope",
        "message": "Explainable hybrid phishing email detection API is running.",
        "docs": "/docs"
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/triage/status")
def triage_status():
    return triage_worker.get_status()


@app.post("/analyze/eml")
async def analyze_eml(request: Request, file: UploadFile = File(...)):
    # Gate this the same way /analyze/raw and /analyze/outlook are gated -- it
    # reaches the same pipeline, so leaving it open let a public deployment be
    # used as a free analysis API (and now, indirectly, a way to trigger costly
    # networked investigations).
    require_api_key(request)

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported."
        )

    try:
        file_bytes = await file.read()
        parsed = parse_eml_bytes(file_bytes)
        result = analyze_parsed_email(parsed)
        result["meta"]["filename"] = file.filename
        return result

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Email analysis failed: {str(exc)}"
        )


class RawEmailRequest(BaseModel):
    raw_base64: str


def require_api_key(request: Request) -> None:
    """When PHISHSCOPE_API_KEY is set, callers must send it as X-API-Key.
    Unset means open access (local development). The Gmail Add-on runs on
    Google's servers, so the backend must be publicly reachable -- this is
    the minimal gate that keeps a public deployment from being an open
    email-analysis API for anyone who finds the URL."""
    expected = os.environ.get("PHISHSCOPE_API_KEY")
    if not expected:
        return
    provided = request.headers.get("X-API-Key", "")
    if not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key.")


@app.post("/analyze/raw")
def analyze_raw(payload: RawEmailRequest, request: Request):
    """Analyzes a raw RFC822 message passed as base64url (the exact encoding
    Gmail's REST API returns for format=raw), so the Gmail Add-on can forward
    messages without any re-encoding. Standard base64 is accepted too."""
    require_api_key(request)

    encoded = payload.raw_base64.strip()
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        raw_bytes = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        try:
            raw_bytes = base64.b64decode(padded)
        except (binascii.Error, ValueError):
            raise HTTPException(status_code=400, detail="raw_base64 is not valid base64/base64url.")

    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Decoded message is empty.")

    try:
        parsed = parse_eml_bytes(raw_bytes)
        return analyze_parsed_email(parsed)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Email analysis failed: {str(exc)}")


class OutlookAttachment(BaseModel):
    name: str = ""
    content_type: str = ""


class OutlookEmailRequest(BaseModel):
    headers: str
    body_html: str = ""
    body_text: str = ""
    attachments: list[OutlookAttachment] = []


@app.post("/analyze/outlook")
def analyze_outlook(payload: OutlookEmailRequest, request: Request):
    """Analyzes a message delivered as separate headers + body, the only form
    an Outlook add-in taskpane can access (no raw MIME in office.js)."""
    require_api_key(request)

    if not payload.headers.strip():
        raise HTTPException(status_code=400, detail="headers must not be empty.")

    try:
        parsed = parse_headers_and_body(
            headers_text=payload.headers,
            html_body=payload.body_html,
            text_body=payload.body_text,
            attachments=[
                {"filename": a.name, "content_type": a.content_type}
                for a in payload.attachments
            ],
        )
        return analyze_parsed_email(parsed)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Email analysis failed: {str(exc)}")


class InvestigateRequest(BaseModel):
    raw_base64: str | None = None          # Gmail add-on surface (primary)
    headers: str | None = None             # Outlook surface
    body_html: str = ""
    body_text: str = ""
    force: bool = False                    # analyst override of the borderline gate


@app.post("/investigate")
async def investigate(payload: InvestigateRequest, request: Request):
    """Runs the SOC-analyst investigator agent on a borderline email and returns
    the standard analysis dict with an added `investigation` evidence trail.

    Accepts the same inputs as the analyze endpoints (raw_base64 for Gmail, or
    headers+body for Outlook). The verdict is re-derived here rather than trusted
    from the client -- the pipeline is fast (rules + local model, no network), so
    this stays stateless. The (slow, networked) agent runs only for borderline
    verdicts unless `force` is set, and only when an Anthropic API key is present.
    """
    require_api_key(request)

    if payload.raw_base64:
        encoded = payload.raw_base64.strip()
        padded = encoded + "=" * (-len(encoded) % 4)
        try:
            raw_bytes = base64.urlsafe_b64decode(padded)
        except (binascii.Error, ValueError):
            try:
                raw_bytes = base64.b64decode(padded)
            except (binascii.Error, ValueError):
                raise HTTPException(status_code=400, detail="raw_base64 is not valid base64/base64url.")
        if not raw_bytes:
            raise HTTPException(status_code=400, detail="Decoded message is empty.")
        try:
            parsed = parse_eml_bytes(raw_bytes)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Email parsing failed: {str(exc)}")
    elif payload.headers and payload.headers.strip():
        try:
            parsed = parse_headers_and_body(
                headers_text=payload.headers,
                html_body=payload.body_html,
                text_body=payload.body_text,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Email parsing failed: {str(exc)}")
    else:
        raise HTTPException(status_code=400, detail="Provide either raw_base64 or headers.")

    try:
        analysis = analyze_parsed_email(parsed)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Email analysis failed: {str(exc)}")

    if not (payload.force or should_investigate(analysis["final_decision"])):
        analysis["investigation"] = {
            "investigated": False,
            "reason": "Verdict is not borderline; pass force=true to investigate anyway.",
        }
        return analysis

    try:
        # Blocking WHOIS/DNS/HTTP + LLM I/O -- run off the event loop, the same
        # reasoning triage_worker applies to its synchronous pipeline work.
        analysis["investigation"] = await asyncio.to_thread(
            run_investigation, parsed, analysis
        )
    except InvestigatorNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(exc)}")

    return analysis


@app.get("/dashboard")
def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "connected": gmail_auth.is_connected(),
            "needs_reconnect": gmail_auth.is_connected() and not gmail_auth.has_required_scope(),
        }
    )


@app.get("/auth/google/login")
def google_login():
    try:
        auth_url = gmail_auth.build_authorization_url()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    return RedirectResponse(auth_url)


@app.get("/auth/google/callback")
def google_callback(request: Request):
    try:
        gmail_auth.exchange_code_for_token(str(request.url))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Google sign-in failed: {str(exc)}")
    return RedirectResponse("/dashboard")


@app.post("/auth/google/disconnect")
def google_disconnect():
    gmail_auth.disconnect()
    return {"status": "disconnected"}


@app.post("/scan/inbox")
def scan_inbox(max_results: int = 10):
    if not gmail_auth.is_connected():
        raise HTTPException(status_code=401, detail="Gmail is not connected. Visit /auth/google/login first.")
    if not gmail_auth.has_required_scope():
        raise HTTPException(
            status_code=401,
            detail="Gmail is connected with an outdated permission scope. Disconnect and reconnect to continue."
        )

    try:
        messages = fetch_recent_raw_messages(max_results=max_results)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch Gmail messages: {str(exc)}")

    results = []
    for message in messages:
        try:
            parsed = parse_eml_bytes(message["raw_bytes"])
            result = analyze_parsed_email(parsed)
            result["meta"]["gmail_id"] = message["gmail_id"]
            results.append(result)
        except Exception as exc:
            results.append({"meta": {"gmail_id": message["gmail_id"]}, "error": str(exc)})

    return {"scanned_count": len(results), "results": results}