"""MCP tool for paged packet reads."""

from __future__ import annotations

from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from packmate_mcp.client import PackmateClient
from packmate_mcp.formatting import ContentFormat, format_content
from packmate_mcp.models import PacketPagination


def register(mcp: FastMCP, client: PackmateClient) -> None:
    @mcp.tool()
    async def get_packets(
        stream_id: int,
        starting_from: Optional[int] = None,
        page_size: int = 50,
        content_format: ContentFormat = ContentFormat.TRANSCRIPT,
        max_bytes_per_packet: int = 4096,
    ) -> dict[str, Any]:
        """Read a page of packets from a stream.

        Use this instead of `get_stream` when a stream is too large or you need to
        scroll past the first page. Set `starting_from` to a packet id (returned in
        the previous page) to continue scrolling.

        Returns `{packets: [<metadata>], content: <formatted string>}`.
        """
        packets = await client.get_packets(
            stream_id,
            PacketPagination(starting_from=starting_from, page_size=page_size),
        )
        formatted = format_content(
            packets,
            mode=content_format,
            max_bytes_per_packet=max_bytes_per_packet,
            total_max_bytes=max_bytes_per_packet * page_size,
            max_packets=page_size,
        )
        return {
            "packets": [p.model_dump(by_alias=True) for p in packets],
            "content": formatted,
        }
