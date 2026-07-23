"""The investigator agent's tool belt: four deterministic enrichment functions
the LLM can call, plus their Anthropic tool schemas and a dispatcher.

Design notes:
  * Every tool returns a plain dict that always carries a ``signal`` (one of
    SIGNAL_*) and a one-line ``summary``. The *tool* decides the signal, never
    the LLM -- so the evidence trail the agent assembles is verifiable.
  * The two networked tools (whois, dns, redirects) route through net_guard or
    fail closed to a neutral signal; they never raise into the agent loop.
  * cross_check_headers does no network I/O -- it reuses fields already extracted
    by app.features and adds the missing "body claims vs header says" comparison.
"""

from datetime import datetime, timezone
from urllib.parse import urlparse

from app.features import domain_from_url, is_ip_domain

from . import config, net_guard
from .schemas import SIGNAL_BENIGN, SIGNAL_MALICIOUS, SIGNAL_NEUTRAL

# Impersonation-prone brands and the domain a legitimate sender would actually
# use. Used by cross_check_headers to turn "body says Microsoft, From: is a .tk
# domain" into a first-class structured signal.
ORG_BRAND_DOMAINS = {
    "microsoft": "microsoft.com",
    "office365": "microsoft.com",
    "outlook": "microsoft.com",
    "onedrive": "microsoft.com",
    "sharepoint": "microsoft.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "google": "google.com",
}


def _registrable(host: str) -> str:
    """Cheap eTLD+1 approximation (last two labels). Good enough to tell
    'paypal.com' from 'paypal.com.evil.ru' for a cross-domain-redirect check;
    not a substitute for a real public-suffix list."""
    host = (host or "").lower().strip().rstrip(".")
    labels = host.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


# --------------------------------------------------------------------------- #
# Tool 1: WHOIS domain age
# --------------------------------------------------------------------------- #

def _whois_raw(domain: str):
    """Test seam: the actual WHOIS call. python-whois parsing is flaky per-TLD,
    so callers wrap this in try/except and degrade to a neutral 'unknown' signal
    rather than crash. Timeout is explicit (not the library's implicit default)
    because agent.py's total wall-clock budget only checks *between* tool calls
    -- it can't interrupt a single hanging WHOIS lookup already in progress."""
    import whois

    return whois.whois(domain, timeout=int(config.get_whois_timeout_seconds()))


def _earliest_datetime(value) -> datetime | None:
    """python-whois returns creation_date as a datetime, a list of them, or
    None. Normalize to the earliest timezone-aware (UTC) datetime; naive values
    are assumed to already be UTC."""
    if value is None:
        return None
    candidates = value if isinstance(value, (list, tuple)) else [value]
    parsed = []
    for item in candidates:
        if isinstance(item, datetime):
            parsed.append(item.astimezone(timezone.utc) if item.tzinfo
                          else item.replace(tzinfo=timezone.utc))
    return min(parsed) if parsed else None


def whois_domain_age(domain: str) -> dict:
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain or is_ip_domain(domain) or "." not in domain:
        return {
            "domain": domain, "age_days": None, "created": None, "registrar": None,
            "error": "not_a_registrable_domain", "signal": SIGNAL_NEUTRAL,
            "summary": f"'{domain}' is not a domain that can be aged via WHOIS.",
        }

    try:
        record = _whois_raw(domain)
    except Exception as exc:  # noqa: BLE001 -- WHOIS libraries raise many types
        return {
            "domain": domain, "age_days": None, "created": None, "registrar": None,
            "error": f"whois_failed:{type(exc).__name__}", "signal": SIGNAL_NEUTRAL,
            "summary": f"WHOIS lookup for '{domain}' failed; age unknown.",
        }

    created = _earliest_datetime(getattr(record, "creation_date", None))
    registrar = getattr(record, "registrar", None)

    if created is None:
        return {
            "domain": domain, "age_days": None, "created": None, "registrar": registrar,
            "error": "no_creation_date", "signal": SIGNAL_NEUTRAL,
            "summary": f"WHOIS returned no creation date for '{domain}'; age unknown.",
        }

    age_days = max(0, (datetime.now(timezone.utc) - created).days)
    if age_days < 30:
        signal = SIGNAL_MALICIOUS
        summary = f"'{domain}' was registered only {age_days} day(s) ago -- freshly-registered domains strongly correlate with phishing."
    elif age_days >= 180:
        signal = SIGNAL_BENIGN
        summary = f"'{domain}' has been registered for {age_days} day(s), consistent with an established sender."
    else:
        signal = SIGNAL_NEUTRAL
        summary = f"'{domain}' is {age_days} day(s) old -- neither clearly fresh nor clearly established."

    return {
        "domain": domain, "age_days": age_days, "created": created.isoformat(),
        "registrar": registrar, "error": None, "signal": signal, "summary": summary,
    }


# --------------------------------------------------------------------------- #
# Tool 2: DNS lookup
# --------------------------------------------------------------------------- #

def _dns_query(domain: str, rdtype: str):
    """Test seam: a single DNS query. Isolated so tests never hit real DNS."""
    import dns.resolver

    return dns.resolver.resolve(domain, rdtype)


def dns_lookup(domain: str) -> dict:
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain or is_ip_domain(domain) or "." not in domain:
        return {
            "domain": domain, "resolves": False, "a_records": [], "mx_present": False,
            "signal": SIGNAL_NEUTRAL, "summary": f"'{domain}' is not a resolvable domain.",
        }

    a_records: list[str] = []
    mx_present = False
    try:
        a_records = [str(r) for r in _dns_query(domain, "A")]
    except Exception:  # noqa: BLE001 -- NXDOMAIN, NoAnswer, timeouts, etc.
        pass
    try:
        mx_present = len(list(_dns_query(domain, "MX"))) > 0
    except Exception:  # noqa: BLE001
        pass

    resolves = bool(a_records)
    # An A record inside private space (from an attacker-controlled domain) is a
    # red flag in its own right -- reuse the same public-IP test the fetch path uses.
    private_a = [ip for ip in a_records if not net_guard.is_public_ip(ip)]

    if private_a:
        signal = SIGNAL_MALICIOUS
        summary = f"'{domain}' resolves into private/internal IP space ({', '.join(private_a)}) -- abnormal for a public sender."
    elif resolves and mx_present:
        signal = SIGNAL_BENIGN
        summary = f"'{domain}' resolves and publishes MX records, consistent with a real mail-sending domain."
    elif resolves and not mx_present:
        signal = SIGNAL_NEUTRAL
        summary = f"'{domain}' resolves but publishes no MX records -- it can host links but isn't set up to send mail."
    else:
        signal = SIGNAL_NEUTRAL
        summary = f"'{domain}' does not currently resolve to an A record."

    return {
        "domain": domain, "resolves": resolves, "a_records": a_records,
        "mx_present": mx_present, "signal": signal, "summary": summary,
    }


# --------------------------------------------------------------------------- #
# Tool 3: Follow redirect chain
# --------------------------------------------------------------------------- #

def follow_redirects(url: str) -> dict:
    url = (url or "").strip()
    if not url:
        return {"chain": [], "final_url": "", "final_domain": "", "hops": 0,
                "blocked_reason": "empty_url", "signal": SIGNAL_NEUTRAL,
                "summary": "No URL provided to follow."}

    if "://" not in url:
        url = "http://" + url

    max_redirects = config.get_max_redirects()
    per_request = config.get_http_timeout_seconds()
    trace = net_guard.follow_redirect_chain(
        url,
        max_redirects=max_redirects,
        total_timeout=per_request * (max_redirects + 1),
        per_request_timeout=per_request,
    )

    blocked = trace["blocked_reason"]
    start_domain = _registrable(urlparse(url).hostname or "")
    final_domain = _registrable(trace["final_domain"])
    cross_domain = bool(final_domain) and bool(start_domain) and final_domain != start_domain

    if blocked and (blocked.startswith(("resolves_to_private", "private_or_reserved", "disallowed_scheme"))):
        signal = SIGNAL_MALICIOUS
        summary = f"Following '{url}' was blocked ({blocked}) -- the link points at internal/non-web infrastructure."
    elif blocked:
        signal = SIGNAL_NEUTRAL
        summary = f"Could not fully resolve the redirect chain for '{url}' ({blocked})."
    elif cross_domain:
        signal = SIGNAL_MALICIOUS
        summary = f"'{start_domain}' redirects to a different domain '{final_domain}' after {trace['hops']} hop(s) -- a common phishing cloaking pattern."
    else:
        signal = SIGNAL_BENIGN
        summary = f"'{url}' resolves within its own domain ('{final_domain or start_domain}') without cross-domain redirection."

    trace["signal"] = signal
    trace["summary"] = summary
    return trace


# --------------------------------------------------------------------------- #
# Tool 4: Cross-check header claims against body claims (no network)
# --------------------------------------------------------------------------- #

def cross_check_headers(parsed: dict, analysis: dict) -> dict:
    features = analysis.get("features", {}) or {}
    body = parsed.get("body", {}) or {}

    sender_domain = (features.get("sender_domain") or "").lower()
    blob = " ".join([
        str(body.get("text", "")), str(body.get("preview", "")), str(body.get("html", "")),
    ]).lower()

    claimed_brands = [brand for brand in ORG_BRAND_DOMAINS if brand in blob]
    mismatched_brands = [
        brand for brand in claimed_brands
        if not sender_domain.endswith(ORG_BRAND_DOMAINS[brand])
    ]

    dkim_missing = bool(features.get("dkim_missing"))
    header_mismatch = bool(
        features.get("return_path_mismatch") or features.get("reply_to_mismatch")
    )
    # SPF/DMARC failure is rare and specific (0% on a 528-email real-corpus
    # backtest) -- a strong standalone signal. dkim_missing alone is not: it was
    # true for 99.2% of that same corpus (real mail, both phishing and
    # legitimate, plus historical mail that predates DKIM), so on its own it
    # carries ~no discriminating power and drowns out the tools that do.
    # decision_engine.py never uses its own authentication_failed() standalone
    # to escalate risk either -- only as one AND-condition alongside a
    # trusted-domain match. Mirroring that: dkim_missing only counts here when
    # corroborated by an actual header mismatch.
    strong_auth_failure = bool(features.get("spf_fail") or features.get("dmarc_fail"))
    auth_failed = strong_auth_failure or (dkim_missing and header_mismatch)

    finding = {
        "sender_domain": sender_domain,
        "body_claimed_brands": claimed_brands,
        "impersonated_brands": mismatched_brands,
        "spf_fail": bool(features.get("spf_fail")),
        "dkim_missing": dkim_missing,
        "dmarc_fail": bool(features.get("dmarc_fail")),
        "return_path_mismatch": bool(features.get("return_path_mismatch")),
        "reply_to_mismatch": bool(features.get("reply_to_mismatch")),
    }

    if mismatched_brands:
        finding["signal"] = SIGNAL_MALICIOUS
        finding["summary"] = (
            f"The body impersonates {', '.join(mismatched_brands)} but was sent from "
            f"'{sender_domain or 'an unknown domain'}', which is not their real domain."
        )
    elif auth_failed or header_mismatch:
        reasons = []
        if strong_auth_failure:
            reasons.append("sender authentication (SPF/DMARC) failed")
        if header_mismatch:
            reasons.append("the Return-Path/Reply-To domain differs from the From domain")
        finding["signal"] = SIGNAL_MALICIOUS
        finding["summary"] = "Header inconsistency: " + "; ".join(reasons) + "."
    elif not claimed_brands:
        finding["signal"] = SIGNAL_NEUTRAL
        finding["summary"] = "The body names no well-known brand to cross-check against the headers."
    else:
        finding["signal"] = SIGNAL_BENIGN
        finding["summary"] = (
            f"The body references {', '.join(claimed_brands)} and the sender domain "
            f"'{sender_domain}' is consistent with that, with no header mismatch."
        )

    return finding


# --------------------------------------------------------------------------- #
# Anthropic tool schemas + dispatch
# --------------------------------------------------------------------------- #

TOOL_SCHEMAS = [
    {
        "name": "whois_domain_age",
        "description": (
            "Look up how long ago a domain was registered via WHOIS. Call this to "
            "check the age of the sender's domain or any domain a link resolves to -- "
            "domains registered within the last few weeks are a strong phishing signal."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "A registrable domain, e.g. 'example.com' (no scheme, no path)."},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "dns_lookup",
        "description": (
            "Resolve a domain's A and MX records. Call this to check whether a domain "
            "actually resolves and whether it is set up to send mail (MX). A domain that "
            "claims to be a mail sender but has no MX, or that resolves into private IP "
            "space, is suspicious."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "A registrable domain, e.g. 'example.com'."},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "follow_redirects",
        "description": (
            "Follow a URL's HTTP redirect chain safely and report where it actually "
            "lands. Call this on links found in the email body to reveal cloaked "
            "destinations -- e.g. a link that appears to point to a shortener but "
            "redirects to an attacker domain. Never fetches internal/private targets."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "A full URL from the email body, e.g. 'http://bit.ly/abc'."},
            },
            "required": ["url"],
        },
    },
    {
        "name": "cross_check_headers",
        "description": (
            "Compare what the visible email body claims (e.g. 'from Microsoft') against "
            "what the headers actually say (From/Return-Path/Reply-To domains and "
            "SPF/DKIM/DMARC results). Call this to detect brand impersonation and header "
            "spoofing. Operates on the email currently under investigation; takes no arguments."
        ),
        "input_schema": {"type": "object", "properties": {}},
    },
]


def execute_tool(name: str, tool_input: dict, *, parsed: dict, analysis: dict) -> dict:
    """Route a tool_use call from the agent to the matching deterministic tool.
    Always returns a dict carrying ``signal`` and ``summary``."""
    tool_input = tool_input or {}
    if name == "whois_domain_age":
        return whois_domain_age(tool_input.get("domain", ""))
    if name == "dns_lookup":
        return dns_lookup(tool_input.get("domain", ""))
    if name == "follow_redirects":
        return follow_redirects(tool_input.get("url", ""))
    if name == "cross_check_headers":
        return cross_check_headers(parsed, analysis)
    return {
        "error": f"unknown_tool:{name}", "signal": SIGNAL_NEUTRAL,
        "summary": f"Unknown tool '{name}'.",
    }
