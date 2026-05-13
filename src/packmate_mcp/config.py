"""Runtime configuration loaded from PACKMATE_MCP_* env vars."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class PackmateSettings(BaseSettings):
    """Settings for the Packmate MCP server.

    All variables use the PACKMATE_MCP_ prefix. LOGIN and PASSWORD are required.
    """

    model_config = SettingsConfigDict(
        env_prefix="PACKMATE_MCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    base_url: HttpUrl = Field(default=HttpUrl("http://localhost:65000"))
    login: str
    password: str
    timeout_seconds: float = Field(default=30.0, gt=0)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
