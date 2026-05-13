"""Tool registration for MCP server.

Each submodule exposes a `register(mcp, client)` function that attaches its tools
to the FastMCP instance using the shared PackmateClient.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from packmate_mcp.client import PackmateClient
from packmate_mcp.tools import packets, patterns, pcap, services, streams


def register_all(mcp: FastMCP, client: PackmateClient) -> None:
    services.register(mcp, client)
    patterns.register(mcp, client)
    streams.register(mcp, client)
    packets.register(mcp, client)
    pcap.register(mcp, client)
