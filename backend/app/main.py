import base64
import binascii
import os
import secrets

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from fastapi.middleware.cors import CORSMiddleware

from app.parser import parse_eml_bytes, parse_headers_and_body
from app.features import extract_features
from app.scorer import score_email
from app.explainer import explain_prediction, explain_ml_prediction
from app.ml_predictor import predict_email
from app.decision_engine import make_final_decision
from app import gmail_auth
from app.gmail_client import fetch_recent_raw_messages


app = FastAPI(
    title="PhishScope API",
    description="Explainable conflict-aware hybrid phishing email detection system.",
    version="0.4.1"
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


def safe_get_preview(parsed: dict) -> str:
    """
    Safely extracts email text from parsed email.
    Prevents crashes if preview/text/body fields are missing.
    """

    body = parsed.get("body", {})

    if isinstance(body, dict):
        return (
            body.get("preview")
            or body.get("text")
            or body.get("plain")
            or ""
        )

    if isinstance(body, str):
        return body

    return ""


def normalize_ml_result(ml_result: dict) -> dict:
    """
    Ensures the ML result always contains:
    - prediction
    - label
    - phishing_probability

    This protects the API even if the current ML model only returns prediction/label.
    """

    if ml_result is None:
        ml_result = {}

    prediction = int(ml_result.get("prediction", 0))

    label = ml_result.get("label")
    if not label:
        label = "phishing" if prediction == 1 else "benign"

    phishing_probability = ml_result.get("phishing_probability")

    if phishing_probability is None:
        phishing_probability = ml_result.get("probability")

    if phishing_probability is None:
        phishing_probability = 0.85 if prediction == 1 else 0.15

    phishing_probability = float(phishing_probability)

    return {
        "prediction": prediction,
        "label": label,
        "phishing_probability": round(phishing_probability, 4)
    }


def analyze_parsed_email(parsed: dict) -> dict:
    """Runs the full rule+ML+decision+explanation pipeline on an already-parsed
    email dict. Shared by /analyze/eml (uploaded file) and /scan/inbox (Gmail)
    so both entry points stay in sync with the same pipeline."""
    features = extract_features(parsed)
    scoring = score_email(features)

    email_text = safe_get_preview(parsed)

    rule_feature_values = {
        "url_count": features.get("url_count", 0),
        "urgency_keyword_count": features.get("urgency_keyword_count", 0),
        "credential_keyword_count": features.get("credential_keyword_count", 0),
        "risk_score": scoring.get("score", 0),
    }

    ml_result = predict_email(email_text, rule_features=rule_feature_values)
    ml_result = normalize_ml_result(ml_result)

    final_decision = make_final_decision(
        rule_result=scoring,
        ml_result=ml_result,
        features=features
    )

    explanation = explain_prediction(
        features=features,
        rule_result=scoring,
        ml_prediction=ml_result["prediction"]
    )

    try:
        ml_explanation = explain_ml_prediction(email_text, rule_feature_values)
    except Exception:
        ml_explanation = None

    return {
        "meta": {
            "rule_score": scoring.get("score"),
            "rule_verdict": scoring.get("verdict")
        },
        "ml": {
            "prediction": ml_result.get("prediction"),
            "raw_label": ml_result.get("label"),
            "raw_probability": ml_result.get("phishing_probability"),
            "adjusted_label": final_decision.get("ml_adjusted_label"),
            "adjusted_probability": final_decision.get("ml_adjusted_probability"),
            "adjustment_reasons": final_decision.get(
                "ml_adjustment_reasons",
                []
            )
        },
        "final_decision": final_decision,
        "email": parsed.get("email", {}),
        "urls": parsed.get("urls", []),
        "url_count": parsed.get(
            "url_count",
            len(parsed.get("urls", []))
        ),
        "attachments": parsed.get("attachments", []),
        "features": features,
        "evidence": scoring.get("evidence", []),
        "explanation": explanation,
        "ml_explanation": ml_explanation,
        "previews": parsed.get("body", {})
    }


@app.post("/analyze/eml")
async def analyze_eml(file: UploadFile = File(...)):
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


@app.get("/dashboard")
def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"connected": gmail_auth.is_connected()}
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