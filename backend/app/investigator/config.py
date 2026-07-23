"""Environment configuration for the investigator agent.

Follows the repo's bare-``os.environ`` convention (see main.py's PHISHSCOPE_API_KEY /
PHISHSCOPE_CORS_ORIGINS handling) rather than introducing a settings layer. Every
knob here bounds either cost (LLM calls) or blast radius (outbound network), so the
defaults are deliberately conservative.
"""

import os

# The skill guidance is to default to the most capable model and treat downgrading
# for cost as an explicit operator decision -- so the default is Opus, overridable to
# a cheaper model (e.g. claude-haiku-4-5) via the env var.
DEFAULT_MODEL = "claude-opus-4-8"


def get_model() -> str:
    return os.environ.get("PHISHSCOPE_INVESTIGATOR_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL


def get_max_tool_calls() -> int:
    """Hard cap on how many enrichment tools the agent may run per investigation.
    Bounds both LLM round-trips and outbound network requests so a crafted email
    can't steer the agent into unbounded lookups."""
    return _int_env("PHISHSCOPE_INVESTIGATOR_MAX_TOOL_CALLS", 8, minimum=1)


def get_total_timeout_seconds() -> float:
    """Wall-clock budget for the whole investigation (LLM + network)."""
    return _float_env("PHISHSCOPE_INVESTIGATOR_TIMEOUT_SECONDS", 25.0, minimum=1.0)


def get_max_redirects() -> int:
    """Cap on redirect hops when following a link found in the email body."""
    return _int_env("PHISHSCOPE_INVESTIGATOR_MAX_REDIRECTS", 5, minimum=0)


def get_http_timeout_seconds() -> float:
    """Per-request timeout for a single outbound HTTP hop."""
    return _float_env("PHISHSCOPE_INVESTIGATOR_HTTP_TIMEOUT_SECONDS", 6.0, minimum=0.5)


def get_whois_timeout_seconds() -> float:
    """Timeout for a single WHOIS (port-43) lookup. python-whois defaults this
    to 10s internally, but leaving it as an implicit library default means the
    agent's own total wall-clock budget (get_total_timeout_seconds) can't
    actually bound an in-progress WHOIS call -- that check only runs between
    tool calls, not inside one. Passing this explicitly makes the bound
    deliberate and consistent with the rest of this module's config."""
    return _float_env("PHISHSCOPE_INVESTIGATOR_WHOIS_TIMEOUT_SECONDS", 10.0, minimum=1.0)


def has_api_key() -> bool:
    """Whether an Anthropic API key is configured. Absent it, the /investigate
    endpoint returns a clean 503 rather than letting the SDK 401 mid-agent-loop.
    Matches the repo's bare-env-var convention (a real deployment sets the env
    var; the SDK's other credential sources are out of scope here)."""
    return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())


def _int_env(name: str, default: int, *, minimum: int) -> int:
    try:
        return max(minimum, int(os.environ[name]))
    except (KeyError, ValueError):
        return default


def _float_env(name: str, default: float, *, minimum: float) -> float:
    try:
        return max(minimum, float(os.environ[name]))
    except (KeyError, ValueError):
        return default
