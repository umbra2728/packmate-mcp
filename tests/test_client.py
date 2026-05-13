"""Tests for PackmateClient HTTP layer."""

from __future__ import annotations

import base64

import httpx
import pytest
import respx

from packmate_mcp.client import (
    PackmateAuthError,
    PackmateClient,
    PackmateConnectionError,
    PackmateError,
    PackmateNotFoundError,
    PackmateServerError,
    PackmateValidationError,
)
from packmate_mcp.config import PackmateSettings
from packmate_mcp.models import (
    PacketPagination,
    Pattern,
    PatternActionType,
    PatternCreate,
    PatternDirectionType,
    PatternSearchType,
    PatternUpdate,
    Service,
    ServiceCreate,
    ServiceUpdate,
    Stream,
    StreamPagination,
)


def _settings() -> PackmateSettings:
    return PackmateSettings(login="u", password="p")


# ---------- exceptions ----------


def test_exception_hierarchy() -> None:
    assert issubclass(PackmateAuthError, PackmateError)
    assert issubclass(PackmateConnectionError, PackmateError)
    assert issubclass(PackmateNotFoundError, PackmateError)
    assert issubclass(PackmateValidationError, PackmateError)
    assert issubclass(PackmateServerError, PackmateError)


def test_exceptions_carry_messages() -> None:
    e = PackmateNotFoundError("Stream 42 not found.")
    assert str(e) == "Stream 42 not found."


# ---------- _request ----------


@pytest.mark.asyncio
async def test_request_sends_basic_auth() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.get("/api/service/").mock(
                return_value=httpx.Response(200, json=[])
            )
            await client._request("GET", "/api/service/")
            assert route.called
            assert route.calls[0].request.headers["Authorization"].startswith("Basic ")


@pytest.mark.asyncio
async def test_request_maps_401_to_auth_error() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            mock.get("/x").mock(return_value=httpx.Response(401))
            with pytest.raises(PackmateAuthError) as exc:
                await client._request("GET", "/x")
            assert "Authentication failed" in str(exc.value)


@pytest.mark.asyncio
async def test_request_maps_403_to_auth_error() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            mock.get("/x").mock(return_value=httpx.Response(403))
            with pytest.raises(PackmateAuthError):
                await client._request("GET", "/x")


@pytest.mark.asyncio
async def test_request_maps_404_to_not_found() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            mock.get("/x").mock(return_value=httpx.Response(404))
            with pytest.raises(PackmateNotFoundError):
                await client._request("GET", "/x")


@pytest.mark.asyncio
async def test_request_maps_400_to_validation_error_with_body() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            mock.post("/x").mock(return_value=httpx.Response(400, text="bad port"))
            with pytest.raises(PackmateValidationError) as exc:
                await client._request("POST", "/x")
            assert "bad port" in str(exc.value)


@pytest.mark.asyncio
async def test_request_maps_500_to_server_error() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            mock.get("/x").mock(return_value=httpx.Response(500, text="boom"))
            with pytest.raises(PackmateServerError) as exc:
                await client._request("GET", "/x")
            assert "500" in str(exc.value)
            assert "boom" in str(exc.value)


@pytest.mark.asyncio
async def test_request_maps_connection_error() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            mock.get("/x").mock(side_effect=httpx.ConnectError("refused"))
            with pytest.raises(PackmateConnectionError) as exc:
                await client._request("GET", "/x")
            assert "Cannot reach Packmate" in str(exc.value)


@pytest.mark.asyncio
async def test_request_maps_timeout() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            mock.get("/x").mock(side_effect=httpx.TimeoutException("slow"))
            with pytest.raises(PackmateConnectionError) as exc:
                await client._request("GET", "/x")
            assert "timed out" in str(exc.value).lower()


# ---------- services ----------


def _service_json(port: int = 8080) -> dict:
    return {
        "id": 1,
        "name": "vuln",
        "port": port,
        "mergeAdjacentPackets": True,
        "urldecodeHttpRequests": True,
        "decryptTls": False,
        "parseWebSockets": False,
        "http": True,
    }


@pytest.mark.asyncio
async def test_list_services_returns_models() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            mock.get("/api/service/").mock(
                return_value=httpx.Response(200, json=[_service_json()])
            )
            services = await client.list_services()
            assert len(services) == 1
            assert isinstance(services[0], Service)
            assert services[0].port == 8080


@pytest.mark.asyncio
async def test_create_service_posts_camelcase_body() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/service/").mock(
                return_value=httpx.Response(200, json=_service_json())
            )
            sc = ServiceCreate(name="vuln", port=8080, merge_adjacent_packets=True)
            result = await client.create_service(sc)
            assert result.port == 8080
            body = route.calls[0].request.read().decode()
            assert "mergeAdjacentPackets" in body


@pytest.mark.asyncio
async def test_update_service_posts_to_port_path() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/service/8080").mock(
                return_value=httpx.Response(200, json=_service_json())
            )
            su = ServiceUpdate(urldecode_http_requests=True)
            await client.update_service(8080, su)
            assert route.called
            body = route.calls[0].request.read().decode()
            assert body == '{"urldecodeHttpRequests":true}'


@pytest.mark.asyncio
async def test_delete_service() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.delete("/api/service/8080").mock(return_value=httpx.Response(200))
            await client.delete_service(8080)
            assert route.called


# ---------- patterns ----------


def _pattern_json(pid: int = 1) -> dict:
    return {
        "id": pid,
        "name": "flag",
        "value": "CTF{",
        "color": "#ff0000",
        "actionType": "FIND",
        "searchType": "SUBSTRING",
        "directionType": "BOTH",
        "service": None,
        "enabled": True,
    }


@pytest.mark.asyncio
async def test_list_patterns() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            mock.get("/api/pattern/").mock(
                return_value=httpx.Response(200, json=[_pattern_json()])
            )
            patterns = await client.list_patterns()
            assert len(patterns) == 1
            assert isinstance(patterns[0], Pattern)


@pytest.mark.asyncio
async def test_create_pattern() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/pattern/").mock(
                return_value=httpx.Response(200, json=_pattern_json())
            )
            pc = PatternCreate(
                name="flag",
                value="CTF{",
                action_type=PatternActionType.FIND,
                search_type=PatternSearchType.SUBSTRING,
                direction_type=PatternDirectionType.BOTH,
            )
            await client.create_pattern(pc)
            body = route.calls[0].request.read().decode()
            assert '"actionType":"FIND"' in body


@pytest.mark.asyncio
async def test_update_pattern() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/pattern/7").mock(
                return_value=httpx.Response(200, json=_pattern_json(7))
            )
            await client.update_pattern(7, PatternUpdate(name="new"))
            assert route.calls[0].request.read().decode() == '{"name":"new"}'


@pytest.mark.asyncio
async def test_delete_pattern() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.delete("/api/pattern/7").mock(return_value=httpx.Response(200))
            await client.delete_pattern(7)
            assert route.called


@pytest.mark.asyncio
async def test_set_pattern_enabled_with_query() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post(
                "/api/pattern/7/enable", params={"enabled": "true"}
            ).mock(return_value=httpx.Response(200))
            await client.set_pattern_enabled(7, enabled=True)
            assert route.called


@pytest.mark.asyncio
async def test_pattern_lookback() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/pattern/7/lookback").mock(
                return_value=httpx.Response(200)
            )
            await client.pattern_lookback(7, minutes=5)
            assert route.called
            assert route.calls[0].request.read().decode() == "5"


# ---------- streams + packets ----------


def _stream_json(sid: int = 1, port: int = 8080) -> dict:
    return {
        "id": sid,
        "service": port,
        "protocol": "TCP",
        "startTimestamp": 1_700_000_000_000,
        "endTimestamp": 1_700_000_000_500,
        "foundPatternsIds": [],
        "favorite": False,
        "ttl": 64,
        "userAgentHash": None,
        "sizeBytes": 100,
        "packetsCount": 2,
    }


def _packet_json(pid: int = 1) -> dict:
    return {
        "id": pid,
        "matches": [],
        "timestamp": 1_700_000_000_000,
        "incoming": True,
        "ungzipped": False,
        "webSocketParsed": False,
        "tlsDecrypted": False,
        "hasHttpBody": False,
        "content": base64.b64encode(b"hello").decode(),
    }


@pytest.mark.asyncio
async def test_list_streams_all() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/stream/all").mock(
                return_value=httpx.Response(200, json=[_stream_json()])
            )
            pagination = StreamPagination(page_size=10)
            streams = await client.list_streams(pagination)
            assert len(streams) == 1
            assert isinstance(streams[0], Stream)
            body = route.calls[0].request.read().decode()
            assert '"pageSize":10' in body


@pytest.mark.asyncio
async def test_list_streams_for_port() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/stream/8080").mock(
                return_value=httpx.Response(200, json=[_stream_json(port=8080)])
            )
            await client.list_streams(StreamPagination(), port=8080)
            assert route.called


@pytest.mark.asyncio
async def test_favorite_stream() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/stream/42/favorite").mock(
                return_value=httpx.Response(200)
            )
            await client.set_stream_favorite(42, favorite=True)
            assert route.called


@pytest.mark.asyncio
async def test_unfavorite_stream() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/stream/42/unfavorite").mock(
                return_value=httpx.Response(200)
            )
            await client.set_stream_favorite(42, favorite=False)
            assert route.called


@pytest.mark.asyncio
async def test_get_packets() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/packet/42").mock(
                return_value=httpx.Response(200, json=[_packet_json()])
            )
            packets = await client.get_packets(42, PacketPagination(page_size=10))
            assert len(packets) == 1
            assert packets[0].content == b"hello"
            assert '"pageSize":10' in route.calls[0].request.read().decode()


# ---------- pcap ----------


@pytest.mark.asyncio
async def test_pcap_status_true() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            mock.get("/api/pcap/started").mock(return_value=httpx.Response(200, json=True))
            assert await client.pcap_status() is True


@pytest.mark.asyncio
async def test_pcap_status_false() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            mock.get("/api/pcap/started").mock(return_value=httpx.Response(200, json=False))
            assert await client.pcap_status() is False


@pytest.mark.asyncio
async def test_pcap_start() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/pcap/start").mock(return_value=httpx.Response(200))
            await client.pcap_start()
            assert route.called
