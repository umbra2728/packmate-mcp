"""MCP tools for Packmate service management."""

from __future__ import annotations

from typing import Optional

from mcp.server.fastmcp import FastMCP

from packmate_mcp.client import PackmateClient
from packmate_mcp.models import Service, ServiceCreate, ServiceUpdate


def register(mcp: FastMCP, client: PackmateClient) -> None:
    @mcp.tool()
    async def list_services() -> list[Service]:
        """List all configured Packmate services."""
        return await client.list_services()

    @mcp.tool()
    async def create_service(
        name: str,
        port: int,
        merge_adjacent_packets: bool = False,
        urldecode_http_requests: bool = False,
        decrypt_tls: bool = False,
        parse_web_sockets: bool = False,
        http: bool = False,
    ) -> Service:
        """Create a new service.

        For HTTP-like services, enable `urldecode_http_requests`, `merge_adjacent_packets`,
        and `http`. For binary services, leave them off.
        """
        payload = ServiceCreate(
            name=name,
            port=port,
            merge_adjacent_packets=merge_adjacent_packets,
            urldecode_http_requests=urldecode_http_requests,
            decrypt_tls=decrypt_tls,
            parse_web_sockets=parse_web_sockets,
            http=http,
        )
        return await client.create_service(payload)

    @mcp.tool()
    async def update_service(
        port: int,
        name: Optional[str] = None,
        merge_adjacent_packets: Optional[bool] = None,
        urldecode_http_requests: Optional[bool] = None,
        decrypt_tls: Optional[bool] = None,
        parse_web_sockets: Optional[bool] = None,
        http: Optional[bool] = None,
    ) -> Service:
        """Update a service. Only provided fields are changed."""
        payload = ServiceUpdate(
            name=name,
            merge_adjacent_packets=merge_adjacent_packets,
            urldecode_http_requests=urldecode_http_requests,
            decrypt_tls=decrypt_tls,
            parse_web_sockets=parse_web_sockets,
            http=http,
        )
        return await client.update_service(port, payload)

    @mcp.tool()
    async def delete_service(port: int) -> None:
        """Delete the service registered on `port`."""
        await client.delete_service(port)
