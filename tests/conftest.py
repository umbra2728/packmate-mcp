"""Shared pytest fixtures."""

import os

import pytest


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wipe PACKMATE_MCP_* env vars before each test so tests are deterministic."""
    for key in list(os.environ):
        if key.startswith("PACKMATE_MCP_"):
            monkeypatch.delenv(key, raising=False)
