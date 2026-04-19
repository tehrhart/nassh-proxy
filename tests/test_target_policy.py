"""Unit tests for the SSRF target allow/deny policy."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from ssh_relay.target_policy import TargetDenied, TargetPolicy


def _fake_getaddrinfo(ip: str):
    """Bypass real DNS so tests are deterministic offline."""

    async def _stub(host, port, **_):
        return [(0, 0, 0, "", (ip, port))]

    return _stub


@pytest.mark.asyncio
async def test_loopback_blocked_by_default():
    p = TargetPolicy()
    with patch("asyncio.get_running_loop") as m_loop:
        m_loop.return_value.getaddrinfo = _fake_getaddrinfo("127.0.0.1")
        with pytest.raises(TargetDenied, match="blocked"):
            await p.resolve_and_check("localhost", 22)


@pytest.mark.asyncio
async def test_cloud_metadata_blocked():
    p = TargetPolicy()
    with patch("asyncio.get_running_loop") as m_loop:
        m_loop.return_value.getaddrinfo = _fake_getaddrinfo("169.254.169.254")
        with pytest.raises(TargetDenied):
            await p.resolve_and_check("metadata.example", 80)


@pytest.mark.asyncio
async def test_rfc1918_allowed_by_default():
    p = TargetPolicy()
    with patch("asyncio.get_running_loop") as m_loop:
        m_loop.return_value.getaddrinfo = _fake_getaddrinfo("10.0.0.5")
        result = await p.resolve_and_check("internal.example", 22)
        assert result.ip == "10.0.0.5"


@pytest.mark.asyncio
async def test_ipv6_loopback_blocked():
    p = TargetPolicy()
    with patch("asyncio.get_running_loop") as m_loop:
        m_loop.return_value.getaddrinfo = _fake_getaddrinfo("::1")
        with pytest.raises(TargetDenied):
            await p.resolve_and_check("ip6-localhost", 22)


@pytest.mark.asyncio
async def test_allowlist_restricts_to_cidr():
    p = TargetPolicy(allowlist_cidrs=["192.0.2.0/24"])
    with patch("asyncio.get_running_loop") as m_loop:
        m_loop.return_value.getaddrinfo = _fake_getaddrinfo("10.0.0.5")
        with pytest.raises(TargetDenied, match="allowlist"):
            await p.resolve_and_check("internal.example", 22)


@pytest.mark.asyncio
async def test_allowlist_permits_matching_cidr():
    p = TargetPolicy(allowlist_cidrs=["192.0.2.0/24"])
    with patch("asyncio.get_running_loop") as m_loop:
        m_loop.return_value.getaddrinfo = _fake_getaddrinfo("192.0.2.5")
        result = await p.resolve_and_check("docs.example", 22)
        assert result.ip == "192.0.2.5"


@pytest.mark.asyncio
async def test_unsafe_allow_loopback_opens_127():
    p = TargetPolicy(unsafe_allow_loopback=True)
    with patch("asyncio.get_running_loop") as m_loop:
        m_loop.return_value.getaddrinfo = _fake_getaddrinfo("127.0.0.1")
        result = await p.resolve_and_check("localhost", 22)
        assert result.ip == "127.0.0.1"


@pytest.mark.asyncio
async def test_extra_deny_cidr():
    p = TargetPolicy(extra_deny_cidrs=["192.0.2.0/24"])
    with patch("asyncio.get_running_loop") as m_loop:
        m_loop.return_value.getaddrinfo = _fake_getaddrinfo("192.0.2.5")
        with pytest.raises(TargetDenied):
            await p.resolve_and_check("blocked.example", 22)
