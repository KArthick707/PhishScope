import re
from urllib.parse import urlparse


URGENCY_KEYWORDS = [
    "urgent", "immediately", "verify", "suspend", "restricted",
    "limited time", "action required", "confirm", "security alert",
    "act now", "before the day ends", "don't miss out"
]

CREDENTIAL_KEYWORDS = [
    "password", "login", "sign in", "credential", "account",
    "mfa", "2fa", "authentication", "reset", "verify account",
    "confirm your email"
]

MODERN_PHISHING_KEYWORDS = [
    "claim", "reward", "complimentary", "free", "gift",
    "before the day ends", "don't miss out", "act now",
    "limited", "depleted", "winner", "selected", "congratulations"
]

CLOUD_ABUSE_DOMAINS = [
    "storage.googleapis.com", "docs.google.com", "drive.google.com",
    "sharepoint.com", "onedrive.live.com", "dropbox.com"
]

SUSPICIOUS_TLDS = [
    ".ru", ".cn", ".tk", ".top", ".xyz", ".club", ".click", ".work",
    ".pp.ua", ".icu", ".cam", ".quest", ".rest"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"
]

BRAND_KEYWORDS = [
    "microsoft", "office365", "outlook", "onedrive", "sharepoint",
    "paypal", "dhl", "fedex", "state farm", "amazon", "apple",
    "netflix", "bank", "security team", "duolingo"
]

MFA_KEYWORDS = [
    "mfa", "2fa", "multi-factor", "authentication request",
    "approve sign in", "security verification", "verification code"
]

QR_PHISHING_KEYWORDS = [
    "scan qr", "qr code", "scan the code", "mobile verification"
]

MARKETING_KEYWORDS = [
    "newsletter", "unsubscribe", "all rights reserved", "copyright",
    "mailing address", "manage subscription", "preferences",
    "job offers", "new jobs", "promotion", "apply now"
]

SOCIAL_DOMAINS = [
    "linkedin.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "tiktok.com"
]

TRUSTED_DOMAINS = [
    "duolingo.com", "github.com", "linkedin.com", "google.com",
    "microsoft.com", "apple.com", "amazon.com", "zoom.us",
    "slack.com", "notion.so"
]


def domain_from_email(email_value: str) -> str:
    if not email_value:
        return ""

    match = re.search(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", email_value)
    return match.group(1).lower() if match else ""


def domain_from_url(url: str) -> str:
    try:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def is_ip_domain(domain: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))


def is_trusted_domain(domain: str) -> bool:
    if not domain:
        return False

    return any(
        domain == trusted or domain.endswith("." + trusted)
        for trusted in TRUSTED_DOMAINS
    )


def extract_features(parsed: dict) -> dict:
    email = parsed.get("email", {})
    headers = parsed.get("headers", {})
    body = parsed.get("body", {})
    urls = parsed.get("urls", [])

    sender_domain = domain_from_email(email.get("from", ""))
    reply_to_domain = domain_from_email(email.get("reply_to", ""))
    return_path_domain = domain_from_email(email.get("return_path", ""))

    full_text = (
        email.get("subject", "") + " " +
        body.get("preview", "") + " " +
        body.get("text", "")
    ).lower()

    html_body = body.get("html", "").lower()
    url_domains = [domain_from_url(url) for url in urls]

    modern_phishing_keyword_count = sum(
        1 for word in MODERN_PHISHING_KEYWORDS if word in full_text
    )

    cloud_abuse_url_count = sum(
        1 for domain in url_domains
        if any(cloud in domain for cloud in CLOUD_ABUSE_DOMAINS)
    )

    brand_impersonation_count = sum(
        1 for brand in BRAND_KEYWORDS if brand in full_text
    )

    mfa_keyword_count = sum(
        1 for word in MFA_KEYWORDS if word in full_text
    )

    qr_phishing_count = sum(
        1 for word in QR_PHISHING_KEYWORDS if word in full_text
    )

    tracking_pixel_count = html_body.count("<img")

    html_noise_score = 0
    if len(html_body) > 5000:
        html_noise_score += 1
    if html_body.count("<span") > 20:
        html_noise_score += 1
    if html_body.count("<object") > 0:
        html_noise_score += 1
    if html_body.count("display:none") > 0:
        html_noise_score += 1

    trusted_sender_domain = is_trusted_domain(sender_domain)
    trusted_return_path_domain = is_trusted_domain(return_path_domain)
    trusted_domain_match = trusted_sender_domain and trusted_return_path_domain

    unsubscribe_present = "unsubscribe" in full_text

    copyright_present = (
        "copyright" in full_text
        or "all rights reserved" in full_text
    )

    support_link_present = (
        "support" in full_text
        or "help center" in full_text
        or "contact our support" in full_text
    )

    social_link_count = sum(
        1 for url in urls
        if any(domain in url.lower() for domain in SOCIAL_DOMAINS)
    )

    marketing_keyword_count = sum(
        1 for keyword in MARKETING_KEYWORDS
        if keyword in full_text
    )

    marketing_email_score = 0

    if unsubscribe_present:
        marketing_email_score += 1

    if copyright_present:
        marketing_email_score += 1

    if support_link_present:
        marketing_email_score += 1

    if social_link_count >= 1:
        marketing_email_score += 1

    if marketing_keyword_count >= 2:
        marketing_email_score += 1

    features = {
        "sender_domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,

        "reply_to_mismatch": bool(
            reply_to_domain and sender_domain and reply_to_domain != sender_domain
        ),

        "return_path_mismatch": bool(
            return_path_domain and sender_domain and return_path_domain != sender_domain
        ),

        "spf_fail": (
            "fail" in headers.get("received_spf", "").lower()
            or "spf=fail" in headers.get("authentication_results", "").lower()
        ),

        "dkim_missing": not bool(headers.get("dkim_signature", "")),

        "dmarc_fail": "dmarc=fail" in headers.get("authentication_results", "").lower(),

        "url_count": len(urls),

        "ip_url_count": sum(
            1 for domain in url_domains
            if is_ip_domain(domain)
        ),

        "shortener_count": sum(
            1 for domain in url_domains
            if any(short in domain for short in SHORTENERS)
        ),

        "suspicious_tld_count": sum(
            1 for domain in url_domains
            if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
        ),

        "urgency_keyword_count": sum(
            1 for word in URGENCY_KEYWORDS
            if word in full_text
        ),

        "credential_keyword_count": sum(
            1 for word in CREDENTIAL_KEYWORDS
            if word in full_text
        ),

        "modern_phishing_keyword_count": modern_phishing_keyword_count,
        "cloud_abuse_url_count": cloud_abuse_url_count,
        "brand_impersonation_count": brand_impersonation_count,
        "mfa_keyword_count": mfa_keyword_count,
        "qr_phishing_count": qr_phishing_count,
        "tracking_pixel_count": tracking_pixel_count,
        "html_noise_score": html_noise_score,

        "trusted_sender_domain": trusted_sender_domain,
        "trusted_return_path_domain": trusted_return_path_domain,
        "trusted_domain_match": trusted_domain_match,

        "unsubscribe_present": unsubscribe_present,
        "copyright_present": copyright_present,
        "support_link_present": support_link_present,
        "social_link_count": social_link_count,
        "marketing_keyword_count": marketing_keyword_count,
        "marketing_email_score": marketing_email_score,

        "attachment_count": parsed.get("attachment_count", 0),
    }

    return features