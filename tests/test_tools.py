"""Integration tests for MCP tools.

We don't go through FastMCP's protocol — we instead import the registered
callables directly and call them as async functions with mocked HTTP.
"""

from __future__ import annotations

import base64
from typing import AsyncIterator

import httpx
import pytest
import pytest_asyncio
import respx
from mcp.server.fastmcp import FastMCP

from packmate_mcp.client import PackmateClient, PackmateNotFoundError
from packmate_mcp.config import PackmateSettings


@pytest_asyncio.fixture
async def client() -> AsyncIterator[PackmateClient]:
    settings = PackmateSettings(login="u", password="p")
    async with PackmateClient(settings) as c:
        yield c


def _mcp() -> FastMCP:
    return FastMCP("packmate-test")


def _tool_fn(mcp: FastMCP, name: str):
    """Locate the underlying coroutine for a registered tool.

    FastMCP keeps registered tools in `_tool_manager._tools`. The dict value
    has a `.fn` attribute that holds the original async function.
    """
    return mcp._tool_manager._tools[name].fn


def _service_dict(port: int = 8080) -> dict:
    return {
        "id": 1,
        "name": "vuln",
        "port": port,
        "mergeAdjacentPackets": True,
        "urldecodeHttpRequests": False,
        "decryptTls": False,
        "parseWebSockets": False,
        "http": False,
    }


def _pattern_dict(pid: int = 1) -> dict:
    return {
        "id": pid,
        "name": "flag",
        "value": "CTF{",
        "color": None,
        "actionType": "FIND",
        "searchType": "SUBSTRING",
        "directionType": "BOTH",
        "service": None,
        "enabled": True,
    }


def _stream_dict(sid: int, port: int = 8080) -> dict:
    return {
        "id": sid,
        "service": port,
        "protocol": "TCP",
        "startTimestamp": 1_700_000_000_000,
        "endTimestamp": 1_700_000_000_100,
        "foundPatternsIds": [],
        "favorite": False,
        "ttl": 64,
        "userAgentHash": None,
        "sizeBytes": 5,
        "packetsCount": 1,
    }


def _packet_dict(pid: int, body: bytes = b"hello") -> dict:
    return {
        "id": pid,
        "matches": [],
        "timestamp": 1_700_000_000_000,
        "incoming": True,
        "ungzipped": False,
        "webSocketParsed": False,
        "tlsDecrypted": False,
        "hasHttpBody": False,
        "content": base64.b64encode(body).decode(),
    }


# ---------- services ----------


@pytest.mark.asyncio
async def test_list_services_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.services import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_services")

    with respx.mock(base_url="http://localhost:65000") as mock:
        mock.get("/api/service/").mock(
            return_value=httpx.Response(200, json=[_service_dict()])
        )
        result = await fn()
        assert len(result) == 1
        assert result[0].port == 8080


@pytest.mark.asyncio
async def test_create_service_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.services import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "create_service")

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post("/api/service/").mock(
            return_value=httpx.Response(200, json=_service_dict())
        )
        await fn(name="vuln", port=8080, merge_adjacent_packets=True)
        assert route.called


@pytest.mark.asyncio
async def test_delete_service_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.services import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "delete_service")

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.delete("/api/service/8080").mock(return_value=httpx.Response(200))
        await fn(port=8080)
        assert route.called


# ---------- patterns ----------


@pytest.mark.asyncio
async def test_create_pattern_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.patterns import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "create_pattern")

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post("/api/pattern/").mock(
            return_value=httpx.Response(200, json=_pattern_dict())
        )
        await fn(
            name="flag",
            value="CTF{",
            action_type="FIND",
            search_type="SUBSTRING",
            direction_type="BOTH",
        )
        assert route.called


@pytest.mark.asyncio
async def test_pattern_lookback_validates_minutes(client: PackmateClient) -> None:
    from packmate_mcp.tools.patterns import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "pattern_lookback")

    with pytest.raises(Exception):
        await fn(pattern_id=7, minutes=0)


@pytest.mark.asyncio
async def test_set_pattern_enabled_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.patterns import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_pattern_enabled")

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post(
            "/api/pattern/7/enable", params={"enabled": "false"}
        ).mock(return_value=httpx.Response(200))
        await fn(pattern_id=7, enabled=False)
        assert route.called


# ---------- streams ----------


@pytest.mark.asyncio
async def test_list_streams_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.streams import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_streams")

    with respx.mock(base_url="http://localhost:65000") as mock:
        mock.post("/api/stream/all").mock(
            return_value=httpx.Response(200, json=[_stream_dict(1), _stream_dict(2)])
        )
        streams = await fn(page_size=10)
        assert len(streams) == 2


@pytest.mark.asyncio
async def test_list_streams_by_port(client: PackmateClient) -> None:
    from packmate_mcp.tools.streams import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "list_streams")

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post("/api/stream/8080").mock(
            return_value=httpx.Response(200, json=[_stream_dict(1)])
        )
        await fn(port=8080)
        assert route.called


@pytest.mark.asyncio
async def test_set_stream_favorite_true(client: PackmateClient) -> None:
    from packmate_mcp.tools.streams import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_stream_favorite")

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post("/api/stream/42/favorite").mock(return_value=httpx.Response(200))
        await fn(stream_id=42, favorite=True)
        assert route.called


@pytest.mark.asyncio
async def test_set_stream_favorite_false(client: PackmateClient) -> None:
    from packmate_mcp.tools.streams import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "set_stream_favorite")

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post("/api/stream/42/unfavorite").mock(
            return_value=httpx.Response(200)
        )
        await fn(stream_id=42, favorite=False)
        assert route.called


@pytest.mark.asyncio
async def test_get_stream_combines_metadata_and_content(client: PackmateClient) -> None:
    from packmate_mcp.tools.streams import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "get_stream")

    with respx.mock(base_url="http://localhost:65000") as mock:
        list_route = mock.post("/api/stream/all").mock(
            return_value=httpx.Response(200, json=[_stream_dict(42)])
        )
        packets_route = mock.post("/api/packet/42").mock(
            return_value=httpx.Response(200, json=[_packet_dict(1, b"GET / HTTP/1.1\r\n")])
        )
        result = await fn(stream_id=42)
        assert list_route.called
        assert packets_route.called
        assert result["stream"]["id"] == 42
        assert "GET / HTTP/1.1" in result["content"]
        body = list_route.calls[0].request.read().decode()
        assert '"startingFrom":43' in body
        assert '"pageSize":1' in body


@pytest.mark.asyncio
async def test_get_stream_not_found_when_id_mismatch(client: PackmateClient) -> None:
    from packmate_mcp.tools.streams import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "get_stream")

    with respx.mock(base_url="http://localhost:65000") as mock:
        mock.post("/api/stream/all").mock(
            return_value=httpx.Response(200, json=[_stream_dict(41)])
        )
        with pytest.raises(PackmateNotFoundError) as exc:
            await fn(stream_id=42)
        assert "42" in str(exc.value)


@pytest.mark.asyncio
async def test_get_stream_not_found_when_empty(client: PackmateClient) -> None:
    from packmate_mcp.tools.streams import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "get_stream")

    with respx.mock(base_url="http://localhost:65000") as mock:
        mock.post("/api/stream/all").mock(return_value=httpx.Response(200, json=[]))
        with pytest.raises(PackmateNotFoundError):
            await fn(stream_id=42)


# ---------- packets ----------


@pytest.mark.asyncio
async def test_get_packets_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.packets import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "get_packets")

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post("/api/packet/42").mock(
            return_value=httpx.Response(200, json=[_packet_dict(1, b"hello")])
        )
        result = await fn(stream_id=42, content_format="text", page_size=10)
        body = route.calls[0].request.read().decode()
        assert '"pageSize":10' in body
        assert result["packets"][0]["id"] == 1
        assert result["content"] == "hello"


@pytest.mark.asyncio
async def test_get_packets_paginated(client: PackmateClient) -> None:
    from packmate_mcp.tools.packets import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "get_packets")

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post("/api/packet/42").mock(
            return_value=httpx.Response(200, json=[])
        )
        await fn(stream_id=42, starting_from=100, page_size=20)
        body = route.calls[0].request.read().decode()
        assert '"startingFrom":100' in body
        assert '"pageSize":20' in body


# ---------- pcap ----------


@pytest.mark.asyncio
async def test_pcap_status_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.pcap import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "pcap_status")

    with respx.mock(base_url="http://localhost:65000") as mock:
        mock.get("/api/pcap/started").mock(return_value=httpx.Response(200, json=True))
        result = await fn()
        assert result == {"started": True}


@pytest.mark.asyncio
async def test_pcap_start_tool_when_starts(client: PackmateClient) -> None:
    from packmate_mcp.tools.pcap import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "pcap_start")

    with respx.mock(base_url="http://localhost:65000") as mock:
        mock.post("/api/pcap/start").mock(return_value=httpx.Response(200))
        mock.get("/api/pcap/started").mock(return_value=httpx.Response(200, json=True))
        result = await fn()
        assert result == {"started": True}


@pytest.mark.asyncio
async def test_pcap_start_tool_silent_failure_adds_note(client: PackmateClient) -> None:
    from packmate_mcp.tools.pcap import register

    mcp = _mcp()
    register(mcp, client)
    fn = _tool_fn(mcp, "pcap_start")

    with respx.mock(base_url="http://localhost:65000") as mock:
        mock.post("/api/pcap/start").mock(return_value=httpx.Response(200))
        mock.get("/api/pcap/started").mock(return_value=httpx.Response(200, json=False))
        result = await fn()
        assert result["started"] is False
        assert "FILE mode" in result["note"]
