import os

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.parser import parse_eml_bytes
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