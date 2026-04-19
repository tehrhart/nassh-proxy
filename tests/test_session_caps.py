"""Unit tests for session-count cap logic (independent of live WebSockets)."""

from __future__ import annotations

from types import SimpleNamespace

from ssh_relay.app import Settings, _session_cap_reason


def _sess(identity_key: str | None):
    return SimpleNamespace(identity_key=identity_key)


def _settings(**overrides):
    base = {
        "public_host": "localhost",
        "public_port": 8080,
        "identity_provider": "none",
        "auth_required": False,
        "log_sinks": "stderr",
        "max_sessions_total": 3,
        "max_sessions_per_identity": 2,
    }
    base.update(overrides)
    return Settings.model_construct(**base)


def test_under_caps_returns_none():
    s = _settings()
    sessions = {"a": _sess("alice"), "b": _sess("bob")}
    assert _session_cap_reason(s, sessions, "charlie") is None


def test_global_cap_hit():
    s = _settings()
    sessions = {k: _sess(k) for k in ("a", "b", "c")}
    assert _session_cap_reason(s, sessions, "d") == "global_session_cap"


def test_per_identity_cap_hit():
    s = _settings(max_sessions_total=999)
    sessions = {"a": _sess("alice"), "b": _sess("alice")}
    assert _session_cap_reason(s, sessions, "alice") == "per_identity_session_cap"


def test_none_identity_skips_per_identity_check():
    s = _settings(max_sessions_total=999, max_sessions_per_identity=0)
    sessions = {"a": _sess(None)}
    # Per-identity cap is 0 but identity_key is None — not enforced.
    assert _session_cap_reason(s, sessions, None) is None
