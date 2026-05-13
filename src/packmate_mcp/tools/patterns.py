"""MCP tools for Packmate pattern management."""

from __future__ import annotations

from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from packmate_mcp.client import PackmateClient
from packmate_mcp.models import (
    Pattern,
    PatternActionType,
    PatternCreate,
    PatternDirectionType,
    PatternSearchType,
    PatternUpdate,
)


def register(mcp: FastMCP, client: PackmateClient) -> None:
    @mcp.tool()
    async def list_patterns() -> list[Pattern]:
        """List all patterns (highlight + ignore)."""
        return await client.list_patterns()

    @mcp.tool()
    async def create_pattern(
        name: str,
        value: str,
        action_type: PatternActionType,
        search_type: PatternSearchType,
        direction_type: PatternDirectionType,
        color: str | None = None,
        service_port: int | None = None,
    ) -> Pattern:
        """Create a pattern.

        `action_type=FIND` highlights matches; `IGNORE` deletes streams that match.
        `search_type`: SUBSTRING (text), REGEX (Java regex), BINARY (hex bytes).
        `direction_type`: INPUT (client→server), OUTPUT (server→client), BOTH.
        `service_port`: scope to one service; leave None for all services.
        """
        return await client.create_pattern(
            PatternCreate(
                name=name,
                value=value,
                action_type=action_type,
                search_type=search_type,
                direction_type=direction_type,
                color=color,
                service=service_port,
            )
        )

    @mcp.tool()
    async def update_pattern(
        pattern_id: int,
        name: str | None = None,
        value: str | None = None,
        color: str | None = None,
        action_type: PatternActionType | None = None,
        search_type: PatternSearchType | None = None,
        direction_type: PatternDirectionType | None = None,
        service_port: int | None = None,
    ) -> Pattern:
        """Update a pattern. Only provided fields are changed."""
        return await client.update_pattern(
            pattern_id,
            PatternUpdate(
                name=name,
                value=value,
                color=color,
                action_type=action_type,
                search_type=search_type,
                direction_type=direction_type,
                service=service_port,
            ),
        )

    @mcp.tool()
    async def delete_pattern(pattern_id: int) -> None:
        """Delete a pattern."""
        await client.delete_pattern(pattern_id)

    @mcp.tool()
    async def set_pattern_enabled(pattern_id: int, enabled: bool) -> None:
        """Enable or disable a pattern without deleting it."""
        await client.set_pattern_enabled(pattern_id, enabled)

    @mcp.tool()
    async def pattern_lookback(
        pattern_id: int,
        minutes: Annotated[int, Field(ge=1)],
    ) -> None:
        """Apply a pattern to streams captured in the last N minutes (N >= 1).

        Useful after creating a new pattern to retroactively scan recent traffic.
        """
        # FastMCP enforces Field(ge=1) when called over JSON-RPC, but we also need
        # a runtime check here so direct callers and any path that bypasses FastMCP
        # validation cannot send minutes<1 (Packmate silently ignores those calls).
        if minutes < 1:
            raise ValueError(f"`minutes` must be >= 1 (got {minutes}).")
        await client.pattern_lookback(pattern_id, minutes)
