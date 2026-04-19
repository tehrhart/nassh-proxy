"""Guard-rail tests for identity-provider misconfiguration.

These assert that provider credentials set without the matching
RELAY_IDENTITY_PROVIDER value cause the relay to refuse to start,
instead of silently falling through to the 'none' provider.
"""

from __future__ import annotations

import pytest

from ssh_relay.app import Settings, _build_identity


def _settings(**overrides):
    base = {
        "public_host": "localhost",
        "public_port": 8080,
        "identity_provider": "none",
        "auth_required": False,
        "log_sinks": "stderr",
    }
    base.update(overrides)
    return Settings.model_construct(**base)


def test_cf_credentials_without_provider_raises():
    s = _settings(cf_team_domain="acme", cf_audience="aud-123")
    with pytest.raises(RuntimeError, match="RELAY_IDENTITY_PROVIDER"):
        _build_identity(s)


def test_iap_audience_without_provider_raises():
    s = _settings(iap_audience="/projects/1/global/backendServices/2")
    with pytest.raises(RuntimeError, match="RELAY_IDENTITY_PROVIDER"):
        _build_identity(s)


def test_provider_cf_without_credentials_raises():
    s = _settings(identity_provider="cloudflare-access")
    with pytest.raises(RuntimeError, match="RELAY_CF_TEAM_DOMAIN"):
        _build_identity(s)


def test_provider_iap_without_audience_raises():
    s = _settings(identity_provider="gcp-iap")
    with pytest.raises(RuntimeError, match="RELAY_IAP_AUDIENCE"):
        _build_identity(s)


def test_none_provider_with_no_credentials_ok():
    s = _settings()
    provider = _build_identity(s)
    assert provider.name == "none"
