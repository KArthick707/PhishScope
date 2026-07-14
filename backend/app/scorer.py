def score_email(features: dict) -> dict:
    score = 0
    evidence = []

    def add(rule: str, points: int, detail: str):
        nonlocal score
        score += points
        evidence.append({
            "rule": rule,
            "points": points,
            "detail": detail
        })

    if features.get("dkim_missing"):
        add("dkim_missing", 5, "DKIM signature is missing.")

    if features.get("return_path_mismatch"):
        add("return_path_mismatch", 10, "Return-Path domain differs from sender domain.")

    if features.get("url_count", 0) >= 5:
        add("many_urls", 5, "Email contains many URLs.")

    if features.get("shortener_count", 0) > 0:
        add("url_shortener", 10, "Email contains shortened URL.")

    if features.get("urgency_keyword_count", 0) >= 2:
        add("urgency_language", 10, "Email contains urgency or pressure language.")

    if features.get("credential_keyword_count", 0) >= 2:
        add("credential_request", 15, "Email contains credential/login-related language.")

    if features.get("tracking_pixel_count", 0) > 0:
        add("tracking_pixel", 5, "Email contains image-based tracking indicators.")

    if features.get("html_noise_score", 0) >= 2:
        add("html_obfuscation", 15, "Email contains noisy or hidden HTML structures.")

    if features.get("marketing_email_score", 0) >= 3:
        score = max(score - 25, 0)
        evidence.append({
            "rule": "marketing_context_adjustment",
            "points": -25,
            "detail": "Marketing/newsletter context detected."
        })

    if features.get("trusted_domain_match"):
        score = max(score - 30, 0)
        evidence.append({
            "rule": "trusted_domain_adjustment",
            "points": -30,
            "detail": "Trusted sender and return-path alignment detected."
        })

    score = min(score, 100)

    if score >= 60:
        verdict = "likely_phishing"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "benign_or_low_risk"

    return {
        "score": score,
        "verdict": verdict,
        "evidence": evidence
    }