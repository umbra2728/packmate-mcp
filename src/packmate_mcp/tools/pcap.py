"""MCP tools for pcap-file processing lifecycle (FILE mode)."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from packmate_mcp.client import PackmateClient


def register(mcp: FastMCP, client: PackmateClient) -> None:
    @mcp.tool()
    async def pcap_status() -> dict[str, bool]:
        """Whether pcap-file processing has been started (FILE mode only)."""
        started = await client.pcap_status()
        return {"started": started}

    @mcp.tool()
    async def pcap_start() -> dict[str, Any]:
        """Begin processing the configured pcap file (FILE mode only).

        Packmate silently ignores this call outside FILE mode. The tool follows up
        with `pcap_status` and returns a `note` if processing did not start.
        """
        await client.pcap_start()
        started = await client.pcap_status()
        result: dict[str, Any] = {"started": started}
        if not started:
            result["note"] = (
                "Pcap did not start. Server may not be in FILE mode, "
                "or PACKMATE_PCAP_FILE is not configured."
            )
        return result
