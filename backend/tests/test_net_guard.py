"""SSRF-guard tests. No real DNS or HTTP -- resolution is monkeypatched at the
net_guard._resolve_ips seam, and the private-target checks short-circuit before
any httpx call is made."""

import socket

import pytest

from app.investigator import net_guard
from app.investigator.net_guard import BlockedTarget


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
def test_is_public_ip_allows_public(ip):
    assert net_guard.is_public_ip(ip) is True


@pytest.mark.parametrize("ip", [
    "10.0.0.1", "192.168.1.1", "172.16.0.1",   # RFC1918
    "127.0.0.1",                                # loopback
    "169.254.169.254",                          # link-local / cloud metadata
    "0.0.0.0",                                  # unspecified
    "::1", "fc00::1",                           # IPv6 loopback / ULA
    "::ffff:127.0.0.1",                         # IPv4-mapped IPv6 smuggling a loopback
    "not-an-ip",
])
def test_is_public_ip_rejects_non_public(ip):
    assert net_guard.is_public_ip(ip) is False


def test_resolve_and_validate_public_literal():
    assert net_guard.resolve_and_validate("8.8.8.8") == ["8.8.8.8"]


def test_resolve_and_validate_private_literal_blocked():
    with pytest.raises(BlockedTarget):
        net_guard.resolve_and_validate("127.0.0.1")


def test_resolve_and_validate_public_hostname(monkeypatch):
    monkeypatch.setattr(net_guard, "_resolve_ips", lambda host: ["93.184.216.34"])
    assert net_guard.resolve_and_validate("example.com") == ["93.184.216.34"]


def test_resolve_and_validate_rebinding_any_private_blocked(monkeypatch):
    # A hostname that resolves to one public AND one private IP is the classic
    # DNS-rebinding split -- any private answer must block the whole host.
    monkeypatch.setattr(net_guard, "_resolve_ips", lambda host: ["1.2.3.4", "10.0.0.1"])
    with pytest.raises(BlockedTarget) as exc:
        net_guard.resolve_and_validate("evil.example")
    assert "resolves_to_private_ip" in exc.value.reason


def test_resolve_and_validate_dns_failure_blocked(monkeypatch):
    def _boom(host):
        raise socket.gaierror("nope")
    monkeypatch.setattr(net_guard, "_resolve_ips", _boom)
    with pytest.raises(BlockedTarget):
        net_guard.resolve_and_validate("nxdomain.example")


def test_follow_redirect_chain_blocks_private_host(monkeypatch):
    monkeypatch.setattr(net_guard, "_resolve_ips", lambda host: ["10.0.0.5"])
    trace = net_guard.follow_redirect_chain(
        "http://internal.example/x", max_redirects=3, total_timeout=5, per_request_timeout=2
    )
    assert trace["blocked_reason"].startswith("resolves_to_private_ip")
    assert trace["chain"] == []  # blocked before any request went out


def test_follow_redirect_chain_blocks_metadata_ip_literal():
    trace = net_guard.follow_redirect_chain(
        "http://169.254.169.254/latest/meta-data/",
        max_redirects=3, total_timeout=5, per_request_timeout=2,
    )
    assert trace["blocked_reason"].startswith("private_or_reserved_ip")


def test_follow_redirect_chain_rejects_disallowed_scheme():
    trace = net_guard.follow_redirect_chain(
        "ftp://example.com/x", max_redirects=3, total_timeout=5, per_request_timeout=2
    )
    assert trace["blocked_reason"] == "disallowed_scheme:ftp"
