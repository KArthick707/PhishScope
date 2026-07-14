import numpy as np
import pandas as pd

from app.ml_predictor import load_model, RULE_FEATURES


def _get_averaged_coefficients(classifier):
    """CalibratedClassifierCV fits one base estimator per CV fold; average their
    coefficients/intercepts to get a single linear-SVM weight vector for explanation purposes."""
    coefs = [cc.estimator.coef_[0] for cc in classifier.calibrated_classifiers_]
    intercepts = [cc.estimator.intercept_[0] for cc in classifier.calibrated_classifiers_]
    return np.mean(coefs, axis=0), float(np.mean(intercepts))


def explain_ml_prediction(text: str, rule_feature_values: dict, top_k: int = 8) -> dict:
    """Explains the hybrid linear-SVM's own decision (not the rule engine) by
    surfacing the most influential text tokens and rule features for this
    specific prediction, using coefficient x feature-value contributions."""
    model = load_model()

    row = pd.DataFrame([{
        "text": text or "",
        "url_count": rule_feature_values.get("url_count", 0),
        "urgency_keyword_count": rule_feature_values.get("urgency_keyword_count", 0),
        "credential_keyword_count": rule_feature_values.get("credential_keyword_count", 0),
        "risk_score": rule_feature_values.get("risk_score", 0),
        "text_length": len(text or ""),
    }])[["text"] + RULE_FEATURES]

    preprocessor = model.named_steps["features"]
    classifier = model.named_steps["model"]

    X = preprocessor.transform(row)
    feature_names = preprocessor.get_feature_names_out()
    coef, intercept = _get_averaged_coefficients(classifier)

    contributions = np.asarray(X.multiply(coef).todense()).ravel()

    nonzero_idx = np.nonzero(contributions)[0]
    ranked_idx = nonzero_idx[np.argsort(-np.abs(contributions[nonzero_idx]))]

    tokens = []
    rules = []

    for idx in ranked_idx:
        name = feature_names[idx]
        weight = float(contributions[idx])
        direction = "toward_phishing" if weight > 0 else "toward_legitimate"

        if name.startswith("text__"):
            if len(tokens) >= top_k:
                continue
            tokens.append({
                "token": name.removeprefix("text__"),
                "weight": round(weight, 4),
                "direction": direction
            })
        elif name.startswith("rules__"):
            rules.append({
                "feature": name.removeprefix("rules__"),
                "weight": round(weight, 4),
                "direction": direction
            })

    decision_value = float(np.sum(contributions)) + intercept

    return {
        "top_tokens": tokens,
        "rule_feature_contributions": rules,
        "intercept": round(intercept, 4),
        "decision_value": round(decision_value, 4)
    }


def explain_prediction(features: dict, rule_result: dict, ml_prediction=None, ml_confidence=None) -> dict:
    evidence = []

    if features.get("url_count", 0) > 0:
        evidence.append({
            "type": "url_indicator",
            "severity": "medium",
            "message": f"Email contains {features.get('url_count')} URL(s)."
        })

    if features.get("urgency_keyword_count", 0) > 0:
        evidence.append({
            "type": "urgency_language",
            "severity": "high",
            "message": "Urgency or pressure-based language was detected."
        })

    if features.get("credential_keyword_count", 0) > 0:
        evidence.append({
            "type": "credential_request",
            "severity": "high",
            "message": "Credential or login-related language was detected."
        })

    if features.get("reply_to_mismatch"):
        evidence.append({
            "type": "reply_to_mismatch",
            "severity": "high",
            "message": "Reply-To domain differs from sender domain."
        })

    if features.get("return_path_mismatch"):
        evidence.append({
            "type": "return_path_mismatch",
            "severity": "medium",
            "message": "Return-Path domain differs from sender domain."
        })

    if features.get("spf_fail"):
        evidence.append({
            "type": "spf_fail",
            "severity": "high",
            "message": "SPF authentication failed."
        })

    if features.get("dmarc_fail"):
        evidence.append({
            "type": "dmarc_fail",
            "severity": "high",
            "message": "DMARC authentication failed."
        })

    if features.get("dkim_missing"):
        evidence.append({
            "type": "dkim_missing",
            "severity": "low",
            "message": "DKIM signature missing."
        })

    summary = (
        f"The email was classified as "
        f"{rule_result.get('verdict', 'unknown')} "
        f"with a risk score of "
        f"{rule_result.get('score', 0)}/100."
    )
    return {
        "summary": summary,
        "evidence_count": len(evidence),
        "evidence": evidence
    }