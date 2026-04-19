"""Unit tests for trusted-proxy XFF handling."""

from __future__ import annotations

from ssh_relay.app import Settings, _peer_is_trusted_proxy


def _settings(trusted_proxies: str = ""):
    return Settings.model_construct(
        public_host="localhost",
        public_port=8080,
        identity_provider="none",
        auth_required=False,
        log_sinks="stderr",
        trusted_proxies=trusted_proxies,
    )


def test_empty_trust_list_rejects_all():
    s = _settings()
    assert _peer_is_trusted_proxy(s, "127.0.0.1") is False
    assert _peer_is_trusted_proxy(s, "203.0.113.9") is False


def test_cidr_match():
    s = _settings("127.0.0.1/32")
    assert _peer_is_trusted_proxy(s, "127.0.0.1") is True
    assert _peer_is_trusted_proxy(s, "127.0.0.2") is False


def test_multiple_cidrs():
    s = _settings("10.0.0.0/8, 192.168.1.5/32")
    assert _peer_is_trusted_proxy(s, "10.5.5.5") is True
    assert _peer_is_trusted_proxy(s, "192.168.1.5") is True
    assert _peer_is_trusted_proxy(s, "192.168.1.6") is False


def test_missing_peer_not_trusted():
    s = _settings("0.0.0.0/0")
    assert _peer_is_trusted_proxy(s, None) is False


def test_garbage_peer_not_trusted():
    s = _settings("127.0.0.1/32")
    assert _peer_is_trusted_proxy(s, "not-an-ip") is False
