"""Tests for the /cookie redirect-path allowlist."""

from __future__ import annotations

from ssh_relay.app import _is_safe_path


def test_known_good_paths_allowed():
    assert _is_safe_path("html/nassh.html")
    assert _is_safe_path("html/nassh_google_relay.html")


def test_traversal_rejected():
    assert not _is_safe_path("../etc/passwd")
    assert not _is_safe_path("html/../nassh.html")


def test_unknown_html_rejected():
    assert not _is_safe_path("html/attacker.html")


def test_empty_rejected():
    assert not _is_safe_path("")


def test_absolute_path_rejected():
    assert not _is_safe_path("/html/nassh.html")
