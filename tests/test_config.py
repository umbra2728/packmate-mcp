"""Tests for PackmateSettings env loading."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from packmate_mcp.config import PackmateSettings


def test_required_login_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKMATE_MCP_PASSWORD", "p")
    with pytest.raises(ValidationError) as exc:
        PackmateSettings()
    assert "login" in str(exc.value).lower()


def test_required_password_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKMATE_MCP_LOGIN", "u")
    with pytest.raises(ValidationError):
        PackmateSettings()


def test_defaults_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKMATE_MCP_LOGIN", "u")
    monkeypatch.setenv("PACKMATE_MCP_PASSWORD", "p")
    s = PackmateSettings()
    assert str(s.base_url) == "http://localhost:65000/"
    assert s.timeout_seconds == 30
    assert s.log_level == "INFO"


def test_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKMATE_MCP_LOGIN", "u")
    monkeypatch.setenv("PACKMATE_MCP_PASSWORD", "p")
    monkeypatch.setenv("PACKMATE_MCP_BASE_URL", "http://192.168.1.1:65000")
    monkeypatch.setenv("PACKMATE_MCP_TIMEOUT_SECONDS", "5")
    monkeypatch.setenv("PACKMATE_MCP_LOG_LEVEL", "DEBUG")
    s = PackmateSettings()
    assert str(s.base_url) == "http://192.168.1.1:65000/"
    assert s.timeout_seconds == 5
    assert s.log_level == "DEBUG"
