"""MCP tools for stream listing and inspection."""

from __future__ import annotations

from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from packmate_mcp.client import PackmateClient, PackmateNotFoundError
from packmate_mcp.formatting import ContentFormat, format_content
from packmate_mcp.models import PacketPagination, Stream, StreamPagination


def register(mcp: FastMCP, client: PackmateClient) -> None:
    @mcp.tool()
    async def list_streams(
        port: Optional[int] = None,
        starting_from: Optional[int] = None,
        page_size: int = 20,
        favorites: bool = False,
        pattern_id: Optional[int] = None,
    ) -> list[Stream]:
        """List streams (newest first).

        - `port`: restrict to one service.
        - `starting_from`: return streams with id strictly less than this value (for pagination).
        - `favorites=True`: only favorited streams.
        - `pattern_id`: only streams that matched the given pattern. Combine with
          `create_pattern` + `pattern_lookback` to search content retroactively.
        """
        pattern = None
        if pattern_id is not None:
            patterns = await client.list_patterns()
            for p in patterns:
                if p.id == pattern_id:
                    pattern = p
                    break
            if pattern is None:
                raise PackmateNotFoundError(f"Pattern {pattern_id} not found.")
        pagination = StreamPagination(
            starting_from=starting_from,
            page_size=page_size,
            favorites=favorites,
            pattern=pattern,
        )
        return await client.list_streams(pagination, port=port)

    @mcp.tool()
    async def set_stream_favorite(stream_id: int, favorite: bool) -> None:
        """Mark or unmark a stream as favorite.

        Note: Packmate returns 200 even if the stream id does not exist (no row updated).
        """
        await client.set_stream_favorite(stream_id, favorite)

    @mcp.tool()
    async def get_stream(
        stream_id: int,
        content_format: ContentFormat = ContentFormat.TRANSCRIPT,
        max_bytes_per_packet: int = 4096,
        total_max_bytes: int = 64_000,
        max_packets: int = 200,
    ) -> dict[str, Any]:
        """Get one stream by id with its packets pre-formatted.

        Returns `{stream: <metadata>, content: <formatted string>}`.

        `content_format`: transcript (default), text, hex, python_bytes, base64.
        The three `max_*` parameters cap the output to fit within an LLM context window.
        Widen them if you need more detail; narrow them for large binary streams.
        """
        # startingFrom=id+1, pageSize=1 returns streams with id < id+1 in DESC order,
        # so the first row is `id` itself (if it still exists).
        metadata = await client.list_streams(
            StreamPagination(starting_from=stream_id + 1, page_size=1),
        )
        if not metadata or metadata[0].id != stream_id:
            raise PackmateNotFoundError(f"Stream {stream_id} not found.")
        stream = metadata[0]

        packets = await client.get_packets(
            stream_id,
            PacketPagination(page_size=max_packets),
        )
        formatted = format_content(
            packets,
            mode=content_format,
            max_bytes_per_packet=max_bytes_per_packet,
            total_max_bytes=total_max_bytes,
            max_packets=max_packets,
        )
        return {"stream": stream.model_dump(by_alias=True), "content": formatted}
