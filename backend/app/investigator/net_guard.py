"""SSRF defenses for the investigator agent's outbound network calls.

This is the first code in PhishScope that makes network requests driven by
attacker-controlled input (URLs and domains lifted from an email body). Nothing
in the existing codebase guards that class of request, so the guardrails are
built here from scratch, deny-by-default:

  * scheme allowlist (http/https only)
  * every hostname is resolved and *every resolved IP* is checked against a
    private/loopback/link-local/metadata blocklist BEFORE any connection
  * redirects are followed manually so each hop is re-validated (a redirect to
    http://169.254.169.254/ is blocked just like a first-hop one)
  * per-request and total wall-clock timeouts, and a hard redirect cap

Known limitation (documented, not hidden): resolve-then-connect has a small
TOCTOU window -- httpx re-resolves the host when it connects, so a DNS-rebinding
attacker could in principle answer "public" to our check and "private" to the
connect. Closing it fully requires pinning the validated IP into the connection
(a custom httpx transport). The per-hop re-validation here is the baseline; IP
pinning is the hardening step.
"""

import ipaddress
import socket
import time
from urllib.parse import urljoin, urlparse

import httpx

ALLOWED_SCHEMES = ("http", "https")


class BlockedTarget(Exception):
    """Raised when a host resolves into non-public IP space (or can't be resolved
    to anything public). Carries a short machine-readable reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def is_public_ip(ip: str) -> bool:
    """True only for a globally-routable unicast address. Rejects RFC1918,
    loopback, link-local (incl. the 169.254.169.254 cloud metadata endpoint),
    unique-local IPv6, multicast, reserved, and unspecified addresses. Also
    unwraps IPv4-mapped IPv6 (::ffff:a.b.c.d) so it can't smuggle a private v4."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    # ::ffff:169.254.169.254 must be judged on its embedded v4 address.
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped

    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _resolve_ips(host: str) -> list[str]:
    """Resolve a hostname to every A/AAAA address. Isolated so tests can
    monkeypatch it without real DNS (nothing in this repo does real network I/O
    in tests)."""
    infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def resolve_and_validate(host: str) -> list[str]:
    """Resolve ``host`` and return its public IPs. Deny-by-default: if resolution
    fails, returns nothing, or returns *any* non-public IP, raises BlockedTarget.
    Blocking on *any* private answer (not just an all-private one) also defeats
    the split-horizon / DNS-rebinding trick of resolving to one public and one
    private address."""
    # A bare IP literal is validated directly (no DNS needed, and getaddrinfo
    # would just echo it back).
    try:
        ipaddress.ip_address(host)
        is_literal = True
    except ValueError:
        is_literal = False

    if is_literal:
        if not is_public_ip(host):
            raise BlockedTarget(f"private_or_reserved_ip:{host}")
        return [host]

    try:
        ips = _resolve_ips(host)
    except (socket.gaierror, socket.timeout, UnicodeError, OSError):
        raise BlockedTarget(f"dns_resolution_failed:{host}")

    if not ips:
        raise BlockedTarget(f"dns_no_records:{host}")

    for ip in ips:
        if not is_public_ip(ip):
            raise BlockedTarget(f"resolves_to_private_ip:{host}->{ip}")

    return ips


def follow_redirect_chain(
    url: str,
    *,
    max_redirects: int,
    total_timeout: float,
    per_request_timeout: float,
) -> dict:
    """Follow a URL's redirect chain safely, returning a structured trace.

    Never raises for an SSRF/timeout/HTTP problem -- those come back as
    ``blocked_reason`` so the caller (a tool) can record them as evidence rather
    than crash. Returns:
        {
          "chain": [{"url": ..., "status": ...}, ...],
          "final_url": str,
          "final_domain": str,
          "hops": int,
          "blocked_reason": str | None,
        }
    """
    chain: list[dict] = []
    current = url
    deadline = time.monotonic() + total_timeout
    blocked_reason = None

    # Manual loop with follow_redirects=False so we validate every hop ourselves.
    with httpx.Client(follow_redirects=False, timeout=per_request_timeout) as client:
        for _ in range(max_redirects + 1):
            if time.monotonic() > deadline:
                blocked_reason = "total_timeout_exceeded"
                break

            parsed = urlparse(current)
            if parsed.scheme not in ALLOWED_SCHEMES:
                blocked_reason = f"disallowed_scheme:{parsed.scheme or 'none'}"
                break

            host = parsed.hostname
            if not host:
                blocked_reason = "missing_host"
                break

            try:
                resolve_and_validate(host)
            except BlockedTarget as exc:
                blocked_reason = exc.reason
                break

            try:
                # Stream so we read status + headers without pulling a
                # potentially large attacker-controlled body.
                with client.stream("GET", current) as response:
                    status = response.status_code
                    location = response.headers.get("location")
            except httpx.HTTPError as exc:
                blocked_reason = f"request_failed:{type(exc).__name__}"
                break

            chain.append({"url": current, "status": status})

            if 300 <= status < 400 and location:
                current = urljoin(current, location)
                continue

            # Terminal (non-redirect) response.
            return {
                "chain": chain,
                "final_url": current,
                "final_domain": (urlparse(current).hostname or ""),
                "hops": len(chain),
                "blocked_reason": None,
            }
        else:
            blocked_reason = "too_many_redirects"

    return {
        "chain": chain,
        "final_url": current,
        "final_domain": (urlparse(current).hostname or ""),
        "hops": len(chain),
        "blocked_reason": blocked_reason,
    }
