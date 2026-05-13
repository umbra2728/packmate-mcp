"""Tests for pydantic models mirroring Packmate DTOs."""

from __future__ import annotations

import base64

from packmate_mcp.models import (
    FoundPattern,
    Packet,
    Pattern,
    PatternActionType,
    PatternCreate,
    PatternDirectionType,
    PatternSearchType,
    PatternUpdate,
    Protocol,
    Service,
    ServiceCreate,
    ServiceUpdate,
    Stream,
    StreamPagination,
)


# ---------- enums ----------


def test_protocol_values() -> None:
    assert Protocol.TCP.value == "TCP"
    assert Protocol.UDP.value == "UDP"


def test_pattern_action_values() -> None:
    assert PatternActionType.FIND.value == "FIND"
    assert PatternActionType.IGNORE.value == "IGNORE"


def test_pattern_search_values() -> None:
    assert {e.value for e in PatternSearchType} == {"SUBSTRING", "REGEX", "BINARY"}


def test_pattern_direction_values() -> None:
    assert {e.value for e in PatternDirectionType} == {"INPUT", "OUTPUT", "BOTH"}


# ---------- DTOs ----------


def test_service_round_trip() -> None:
    s = Service.model_validate(
        {
            "id": 1,
            "name": "vuln",
            "port": 8080,
            "mergeAdjacentPackets": True,
            "urldecodeHttpRequests": True,
            "decryptTls": False,
            "parseWebSockets": False,
            "http": True,
        }
    )
    assert s.port == 8080
    assert s.merge_adjacent_packets is True


def test_service_create_serializes_camel() -> None:
    sc = ServiceCreate(
        name="vuln",
        port=8080,
        merge_adjacent_packets=True,
        urldecode_http_requests=True,
        decrypt_tls=False,
        parse_web_sockets=False,
        http=True,
    )
    body = sc.model_dump(by_alias=True)
    assert body["mergeAdjacentPackets"] is True
    assert body["urldecodeHttpRequests"] is True


def test_service_update_omits_unset() -> None:
    su = ServiceUpdate(merge_adjacent_packets=True)
    body = su.model_dump(by_alias=True, exclude_unset=True)
    assert body == {"mergeAdjacentPackets": True}


def test_pattern_round_trip() -> None:
    p = Pattern.model_validate(
        {
            "id": 7,
            "name": "flag",
            "value": "CTF{",
            "color": "#ff0000",
            "actionType": "FIND",
            "searchType": "SUBSTRING",
            "directionType": "BOTH",
            "service": None,
            "enabled": True,
        }
    )
    assert p.action_type.value == "FIND"
    assert p.service is None


def test_pattern_create_serializes_camel() -> None:
    pc = PatternCreate(
        name="flag",
        value="CTF{",
        action_type=PatternActionType.FIND,
        search_type=PatternSearchType.SUBSTRING,
        direction_type=PatternDirectionType.BOTH,
    )
    body = pc.model_dump(by_alias=True, exclude_none=True, mode="json")
    assert body["actionType"] == "FIND"
    assert body["searchType"] == "SUBSTRING"
    assert body["directionType"] == "BOTH"


def test_pattern_update_omits_unset() -> None:
    pu = PatternUpdate(name="new")
    assert pu.model_dump(by_alias=True, exclude_unset=True) == {"name": "new"}


def test_stream_round_trip() -> None:
    s = Stream.model_validate(
        {
            "id": 42,
            "service": 8080,
            "protocol": "TCP",
            "startTimestamp": 1_700_000_000_000,
            "endTimestamp": 1_700_000_001_000,
            "foundPatternsIds": [1, 2],
            "favorite": True,
            "ttl": 64,
            "userAgentHash": "abc",
            "sizeBytes": 1024,
            "packetsCount": 4,
        }
    )
    assert s.id == 42
    assert s.found_patterns_ids == [1, 2]


def test_packet_decodes_base64_content() -> None:
    content_b64 = base64.b64encode(b"hello").decode()
    p = Packet.model_validate(
        {
            "id": 1,
            "matches": [],
            "timestamp": 1_700_000_000_000,
            "incoming": True,
            "ungzipped": False,
            "webSocketParsed": False,
            "tlsDecrypted": False,
            "hasHttpBody": False,
            "content": content_b64,
        }
    )
    assert p.content == b"hello"
    assert p.incoming is True


def test_found_pattern_round_trip() -> None:
    fp = FoundPattern.model_validate({"patternId": 3, "startPosition": 0, "endPosition": 5})
    assert fp.pattern_id == 3


def test_stream_pagination_serialization() -> None:
    sp = StreamPagination(starting_from=10, page_size=20, favorites=False, pattern=None)
    body = sp.model_dump(by_alias=True)
    assert body["startingFrom"] == 10
    assert body["pageSize"] == 20
