"""Pydantic models matching Packmate REST DTOs.

Sources:
- src/main/java/ru/serega6531/packmate/model/enums/*.java
- src/main/java/ru/serega6531/packmate/model/pojo/*.java
"""

from __future__ import annotations

import base64
from enum import Enum
from typing import Annotated, Any, Optional

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field
from pydantic.alias_generators import to_camel


# ---------- enums ----------


class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"


class PatternActionType(str, Enum):
    FIND = "FIND"
    IGNORE = "IGNORE"


class PatternSearchType(str, Enum):
    SUBSTRING = "SUBSTRING"
    REGEX = "REGEX"
    BINARY = "BINARY"


class PatternDirectionType(str, Enum):
    INPUT = "INPUT"
    OUTPUT = "OUTPUT"
    BOTH = "BOTH"


class CaptureMode(str, Enum):
    LIVE = "LIVE"
    FILE = "FILE"
    VIEW = "VIEW"


# ---------- DTOs ----------


def _b64_to_bytes(value: Any) -> Any:
    """Accept base64 string (from JSON), pass-through bytes."""
    if isinstance(value, str):
        return base64.b64decode(value)
    return value


Base64Bytes = Annotated[bytes, BeforeValidator(_b64_to_bytes)]


class _Camel(BaseModel):
    """Base model that aliases snake_case fields to camelCase for JSON I/O."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        use_enum_values=False,
    )


class Service(_Camel):
    id: int
    name: str
    port: int = Field(ge=1, le=65535)
    merge_adjacent_packets: bool = False
    urldecode_http_requests: bool = False
    decrypt_tls: bool = False
    parse_web_sockets: bool = False
    http: bool = False


class ServiceCreate(_Camel):
    name: str
    port: int = Field(ge=1, le=65535)
    merge_adjacent_packets: bool = False
    urldecode_http_requests: bool = False
    decrypt_tls: bool = False
    parse_web_sockets: bool = False
    http: bool = False


class ServiceUpdate(_Camel):
    name: Optional[str] = None
    merge_adjacent_packets: Optional[bool] = None
    urldecode_http_requests: Optional[bool] = None
    decrypt_tls: Optional[bool] = None
    parse_web_sockets: Optional[bool] = None
    http: Optional[bool] = None


class Pattern(_Camel):
    id: int
    name: str
    value: str
    color: Optional[str] = None
    action_type: PatternActionType
    search_type: PatternSearchType
    direction_type: PatternDirectionType
    service: Optional[int] = None
    enabled: bool = True


class PatternCreate(_Camel):
    name: str
    value: str
    action_type: PatternActionType
    search_type: PatternSearchType
    direction_type: PatternDirectionType
    color: Optional[str] = None
    service: Optional[int] = Field(default=None, ge=1, le=65535)


class PatternUpdate(_Camel):
    name: Optional[str] = None
    value: Optional[str] = None
    color: Optional[str] = None
    action_type: Optional[PatternActionType] = None
    search_type: Optional[PatternSearchType] = None
    direction_type: Optional[PatternDirectionType] = None
    service: Optional[int] = Field(default=None, ge=1, le=65535)


class Stream(_Camel):
    id: int
    service: int
    protocol: Protocol
    start_timestamp: int
    end_timestamp: int
    found_patterns_ids: list[int] = Field(default_factory=list)
    favorite: bool = False
    ttl: int = 0
    user_agent_hash: Optional[str] = None
    size_bytes: int = 0
    packets_count: int = 0


class FoundPattern(_Camel):
    pattern_id: int
    start_position: int
    end_position: int


class Packet(_Camel):
    id: int
    matches: list[FoundPattern] = Field(default_factory=list)
    timestamp: int
    incoming: bool
    ungzipped: bool = False
    web_socket_parsed: bool = False
    tls_decrypted: bool = False
    has_http_body: bool = False
    content: Base64Bytes


class StreamPagination(_Camel):
    starting_from: Optional[int] = None
    page_size: int = Field(default=20, ge=1, le=500)
    favorites: bool = False
    pattern: Optional[Pattern] = None


class PacketPagination(_Camel):
    starting_from: Optional[int] = None
    page_size: int = Field(default=50, ge=1, le=500)
