import os

import joblib
import pandas as pd


BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(BASE_DIR, "models", "hybrid_linear_svm_2026.pkl")

RULE_FEATURES = [
    "url_count",
    "urgency_keyword_count",
    "credential_keyword_count",
    "risk_score",
    "text_length",
]


_model = None


def load_model():
    global _model

    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model not found at {MODEL_PATH}")

        _model = joblib.load(MODEL_PATH)

    return _model


def predict_email(text: str, rule_features: dict = None):
    model = load_model()

    text = text or ""
    rule_features = rule_features or {}

    row = pd.DataFrame([{
        "text": text,
        "url_count": rule_features.get("url_count", 0),
        "urgency_keyword_count": rule_features.get("urgency_keyword_count", 0),
        "credential_keyword_count": rule_features.get("credential_keyword_count", 0),
        "risk_score": rule_features.get("risk_score", 0),
        "text_length": len(text),
    }])[["text"] + RULE_FEATURES]

    prediction = int(model.predict(row)[0])

    if hasattr(model, "predict_proba"):
        probability = float(model.predict_proba(row)[0][1])
    else:
        probability = 0.85 if prediction == 1 else 0.15

    label = "phishing" if prediction == 1 else "benign"

    return {
        "prediction": prediction,
        "label": label,
        "phishing_probability": round(probability, 4)
    }
