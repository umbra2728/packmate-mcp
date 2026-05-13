# Packmate MCP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python MCP server (`packmate-mcp`) that wraps Packmate's REST API with 16 stdio tools, formats packet content for LLM consumption, and ships to PyPI via Trusted Publishing.

**Architecture:** FastMCP server + httpx async client + pydantic models. Layers: `client.py` (HTTP + typed errors) → `tools/*.py` (one tool per Packmate operation, pure pydantic validation) → `formatting.py` (pure packet-content renderer). Config via `pydantic-settings` env vars. Spec: `docs/superpowers/specs/2026-05-13-packmate-mcp-design.md`.

**Tech Stack:** Python 3.10+, `mcp[cli]>=1.2.0`, `httpx>=0.27`, `pydantic>=2.0`, `pydantic-settings>=2.0`. Tests: `pytest`, `pytest-asyncio`, `respx`. Build: `hatchling`. CI: GitHub Actions.

---

## Working directory & conventions

All paths in this plan are relative to the repo root `/Users/ismailgaleev/0xb00b5/packmate-mcp/`.

The existing scaffold (`main.py`, current `pyproject.toml`, empty `README.md`) was created by `uv init` and will be replaced/rewritten in Task 1.

**Commits**: Conventional Commits style (`feat:`, `test:`, `chore:`, `docs:`, `ci:`). One concept per commit.

**Branch**: working on `main` (no commits exist beyond the spec commit).

---

## File Structure

After all tasks, the repo will contain:

```
packmate-mcp/
├── pyproject.toml                          # Task 1
├── README.md                               # Task 23
├── CHANGELOG.md                            # Task 23
├── .gitignore                              # Task 1 (extend existing)
├── .env.example                            # Task 23
├── .github/workflows/
│   ├── ci.yml                              # Task 24
│   └── release.yml                         # Task 25
├── docs/superpowers/                       # already exists
├── src/packmate_mcp/
│   ├── __init__.py                         # Task 1
│   ├── __main__.py                         # Task 22
│   ├── server.py                           # Task 22
│   ├── config.py                           # Task 2
│   ├── models.py                           # Tasks 3-4
│   ├── client.py                           # Tasks 11-16
│   ├── formatting.py                       # Tasks 5-10
│   └── tools/
│       ├── __init__.py                     # Task 17
│       ├── services.py                     # Task 17
│       ├── patterns.py                     # Task 18
│       ├── streams.py                      # Task 19
│       ├── packets.py                      # Task 20
│       └── pcap.py                         # Task 21
└── tests/
    ├── __init__.py                         # Task 1
    ├── conftest.py                         # Task 1
    ├── test_config.py                      # Task 2
    ├── test_models.py                      # Tasks 3-4
    ├── test_formatting.py                  # Tasks 5-10
    ├── test_client.py                      # Tasks 11-16
    └── test_tools.py                       # Tasks 17-21
```

`main.py` is deleted in Task 1.

---

## Task 1: Project scaffold

**Files:**
- Delete: `main.py`
- Rewrite: `pyproject.toml`
- Extend: `.gitignore`
- Create: `src/packmate_mcp/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1.1: Delete the placeholder `main.py`**

```bash
rm main.py
```

- [ ] **Step 1.2: Rewrite `pyproject.toml`**

Replace the file contents with:

```toml
[project]
name = "packmate-mcp"
version = "0.1.0"
description = "MCP server for Packmate — CTF network traffic analyzer"
readme = "README.md"
requires-python = ">=3.10"
license = { text = "MIT" }
authors = [{ name = "Ismail Galeev" }]
keywords = ["mcp", "packmate", "ctf", "network", "traffic-analysis"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Security",
]
dependencies = [
    "mcp[cli]>=1.2.0",
    "httpx>=0.27",
    "pydantic>=2.0",
    "pydantic-settings>=2.0",
]

[project.scripts]
packmate-mcp = "packmate_mcp.__main__:main"

[project.urls]
Homepage = "https://github.com/umbra2728/packmate-mcp"
Issues = "https://github.com/umbra2728/packmate-mcp/issues"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/packmate_mcp"]

[dependency-groups]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-cov>=5.0",
    "respx>=0.21",
    "ruff>=0.6",
    "mypy>=1.10",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "I", "W", "UP", "B", "ASYNC"]

[tool.mypy]
python_version = "3.10"
strict = true
files = ["src/packmate_mcp"]
```

- [ ] **Step 1.3: Extend `.gitignore`**

Replace contents of `.gitignore` with:

```
# Python
__pycache__/
*.py[oc]
*.egg-info/
build/
dist/

# Virtual environments
.venv/
.env

# Tooling
.coverage
.coverage.*
.pytest_cache/
.mypy_cache/
.ruff_cache/

# IDE
.idea/
.vscode/

# OS
.DS_Store
```

- [ ] **Step 1.4: Create package init files**

Create `src/packmate_mcp/__init__.py` with:

```python
"""Packmate MCP server."""

from importlib.metadata import version

__version__ = version("packmate-mcp")
```

Create empty `tests/__init__.py` (zero bytes).

- [ ] **Step 1.5: Create `tests/conftest.py`**

```python
"""Shared pytest fixtures."""

import os

import pytest


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wipe PACKMATE_MCP_* env vars before each test so tests are deterministic."""
    for key in list(os.environ):
        if key.startswith("PACKMATE_MCP_"):
            monkeypatch.delenv(key, raising=False)
```

- [ ] **Step 1.6: Install dependencies and verify pytest collects nothing yet**

```bash
uv sync --dev
uv run pytest --collect-only
```

Expected: pytest reports `collected 0 items` and exits 5 (no tests). That's fine.

- [ ] **Step 1.7: Commit**

```bash
git add pyproject.toml .gitignore src/ tests/
git rm main.py
git commit -m "chore: scaffold packmate-mcp package layout"
```

---

## Task 2: Configuration (`config.py`)

**Files:**
- Create: `src/packmate_mcp/config.py`
- Create: `tests/test_config.py`

- [ ] **Step 2.1: Write failing tests**

Create `tests/test_config.py`:

```python
"""Tests for PackmateSettings env loading."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from packmate_mcp.config import PackmateSettings


def test_required_login_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKMATE_MCP_PASSWORD", "p")
    with pytest.raises(ValidationError) as exc:
        PackmateSettings()
    assert "login" in str(exc.value).lower()


def test_required_password_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKMATE_MCP_LOGIN", "u")
    with pytest.raises(ValidationError):
        PackmateSettings()


def test_defaults_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKMATE_MCP_LOGIN", "u")
    monkeypatch.setenv("PACKMATE_MCP_PASSWORD", "p")
    s = PackmateSettings()
    assert str(s.base_url) == "http://localhost:65000/"
    assert s.timeout_seconds == 30
    assert s.log_level == "INFO"


def test_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PACKMATE_MCP_LOGIN", "u")
    monkeypatch.setenv("PACKMATE_MCP_PASSWORD", "p")
    monkeypatch.setenv("PACKMATE_MCP_BASE_URL", "http://192.168.1.1:65000")
    monkeypatch.setenv("PACKMATE_MCP_TIMEOUT_SECONDS", "5")
    monkeypatch.setenv("PACKMATE_MCP_LOG_LEVEL", "DEBUG")
    s = PackmateSettings()
    assert str(s.base_url) == "http://192.168.1.1:65000/"
    assert s.timeout_seconds == 5
    assert s.log_level == "DEBUG"
```

- [ ] **Step 2.2: Run test to verify it fails**

```bash
uv run pytest tests/test_config.py -v
```

Expected: `ModuleNotFoundError: No module named 'packmate_mcp.config'`

- [ ] **Step 2.3: Implement `config.py`**

Create `src/packmate_mcp/config.py`:

```python
"""Runtime configuration loaded from PACKMATE_MCP_* env vars."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


class PackmateSettings(BaseSettings):
    """Settings for the Packmate MCP server.

    All variables use the PACKMATE_MCP_ prefix. LOGIN and PASSWORD are required.
    """

    model_config = SettingsConfigDict(
        env_prefix="PACKMATE_MCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    base_url: HttpUrl = Field(default=HttpUrl("http://localhost:65000"))
    login: str
    password: str
    timeout_seconds: float = Field(default=30.0, gt=0)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
```

- [ ] **Step 2.4: Run tests to verify they pass**

```bash
uv run pytest tests/test_config.py -v
```

Expected: 4 passed.

- [ ] **Step 2.5: Commit**

```bash
git add src/packmate_mcp/config.py tests/test_config.py
git commit -m "feat(config): add PackmateSettings env loader"
```

---

## Task 3: Enum models

**Files:**
- Create: `src/packmate_mcp/models.py` (enums section)
- Create: `tests/test_models.py`

- [ ] **Step 3.1: Write failing test**

Create `tests/test_models.py`:

```python
"""Tests for pydantic models mirroring Packmate DTOs."""

from __future__ import annotations

from packmate_mcp.models import (
    PatternActionType,
    PatternDirectionType,
    PatternSearchType,
    Protocol,
)


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
```

- [ ] **Step 3.2: Run test to verify it fails**

```bash
uv run pytest tests/test_models.py -v
```

Expected: `ModuleNotFoundError: No module named 'packmate_mcp.models'`

- [ ] **Step 3.3: Implement enums in `models.py`**

Create `src/packmate_mcp/models.py`:

```python
"""Pydantic models matching Packmate REST DTOs.

Sources:
- src/main/java/ru/serega6531/packmate/model/enums/*.java
- src/main/java/ru/serega6531/packmate/model/pojo/*.java
"""

from __future__ import annotations

from enum import Enum


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
```

- [ ] **Step 3.4: Run tests to verify they pass**

```bash
uv run pytest tests/test_models.py -v
```

Expected: 4 passed.

- [ ] **Step 3.5: Commit**

```bash
git add src/packmate_mcp/models.py tests/test_models.py
git commit -m "feat(models): add Packmate enum types"
```

---

## Task 4: DTO models (Service, Pattern, Stream, Packet)

**Files:**
- Modify: `src/packmate_mcp/models.py` (append DTOs)
- Modify: `tests/test_models.py`

- [ ] **Step 4.1: Write failing tests**

Append to `tests/test_models.py`:

```python
import base64

from packmate_mcp.models import (
    FoundPattern,
    Packet,
    Pattern,
    PatternCreate,
    PatternUpdate,
    Service,
    ServiceCreate,
    ServiceUpdate,
    Stream,
    StreamPagination,
)


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
        action_type="FIND",
        search_type="SUBSTRING",
        direction_type="BOTH",
    )
    body = pc.model_dump(by_alias=True, exclude_none=True)
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
```

- [ ] **Step 4.2: Run test to verify it fails**

```bash
uv run pytest tests/test_models.py -v
```

Expected: ImportError on `Service`, `Pattern`, etc.

- [ ] **Step 4.3: Implement DTO models**

Append to `src/packmate_mcp/models.py`:

```python
from typing import Annotated, Any, Optional

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field
from pydantic.alias_generators import to_camel


def _b64_to_bytes(value: Any) -> Any:
    """Accept base64 string (from JSON), pass-through bytes."""
    if isinstance(value, str):
        import base64

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
```

The `_Camel` mixin (alias_generator=to_camel, populate_by_name=True) is the single mechanism the codebase uses to bridge Python snake_case ↔ JSON camelCase. Every Packmate-facing model inherits from it.

`StreamPagination.pattern` accepts a full `Pattern` object because that's what the Java DTO does — the controller wires it to JPA. In practice the MCP layer only ever sends `None` or a freshly listed `Pattern`.

`Base64Bytes` decodes the JSON string at validation time so callers see `bytes`.

- [ ] **Step 4.4: Run tests to verify they pass**

```bash
uv run pytest tests/test_models.py -v
```

Expected: 14 passed.

- [ ] **Step 4.5: Commit**

```bash
git add src/packmate_mcp/models.py tests/test_models.py
git commit -m "feat(models): add Service/Pattern/Stream/Packet DTOs"
```

---

## Task 5: Formatting — `hex` mode

**Files:**
- Create: `src/packmate_mcp/formatting.py`
- Create: `tests/test_formatting.py`

- [ ] **Step 5.1: Write failing test**

Create `tests/test_formatting.py`:

```python
"""Tests for packet content formatting."""

from __future__ import annotations

from packmate_mcp.formatting import ContentFormat, format_content
from packmate_mcp.models import Packet


def _packet(content: bytes, incoming: bool = True, ts: int = 1_700_000_000_000) -> Packet:
    return Packet.model_validate(
        {
            "id": 1,
            "matches": [],
            "timestamp": ts,
            "incoming": incoming,
            "ungzipped": False,
            "webSocketParsed": False,
            "tlsDecrypted": False,
            "hasHttpBody": False,
            "content": __import__("base64").b64encode(content).decode(),
        }
    )


def test_hex_canonical_layout() -> None:
    p = _packet(b"Hello, world!\n\x00\xff")
    out = format_content([p], ContentFormat.HEX)
    # canonical hexdump: offset (8 hex digits), 16 bytes per row, ASCII gutter
    assert "00000000:" in out
    assert "48 65 6c 6c 6f" in out  # "Hello"
    assert "Hello, world!" in out  # ASCII gutter rendering


def test_hex_multiline() -> None:
    p = _packet(bytes(range(20)))
    out = format_content([p], ContentFormat.HEX)
    assert "00000000:" in out
    assert "00000010:" in out  # second row at offset 16


def test_hex_replaces_non_printable_in_ascii_gutter() -> None:
    p = _packet(b"\x01\x02\x03A")
    out = format_content([p], ContentFormat.HEX)
    # non-printable bytes should appear as '.' in the ASCII gutter, 'A' preserved
    assert "...A" in out
```

- [ ] **Step 5.2: Run test to verify it fails**

```bash
uv run pytest tests/test_formatting.py -v
```

Expected: `ModuleNotFoundError: No module named 'packmate_mcp.formatting'`

- [ ] **Step 5.3: Implement skeleton + `hex` mode**

Create `src/packmate_mcp/formatting.py`:

```python
"""Pure functions for rendering packet content for an LLM.

All formatting is deterministic, side-effect free, and operates on
already-fetched Packet objects.
"""

from __future__ import annotations

from enum import Enum
from typing import Sequence

from packmate_mcp.models import Packet


class ContentFormat(str, Enum):
    TRANSCRIPT = "transcript"
    TEXT = "text"
    HEX = "hex"
    PYTHON_BYTES = "python_bytes"
    BASE64 = "base64"


_HEXDUMP_BYTES_PER_ROW = 16


def _hexdump(data: bytes) -> str:
    """Render bytes as a canonical hexdump string.

    Layout: 8-digit offset, 16 hex pairs (two columns of 8 separated by extra space),
    ASCII gutter with '.' for non-printable bytes.
    """
    rows: list[str] = []
    for offset in range(0, len(data), _HEXDUMP_BYTES_PER_ROW):
        chunk = data[offset : offset + _HEXDUMP_BYTES_PER_ROW]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(_HEXDUMP_BYTES_PER_ROW * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        rows.append(f"{offset:08x}: {hex_part}  {ascii_part}")
    return "\n".join(rows)


def format_content(
    packets: Sequence[Packet],
    mode: ContentFormat = ContentFormat.TRANSCRIPT,
    max_bytes_per_packet: int = 4096,
    total_max_bytes: int = 64_000,
    max_packets: int = 200,
) -> str:
    """Render a sequence of packets as a single string in the requested mode.

    The remaining formatting modes are added in later tasks.
    """
    if mode is ContentFormat.HEX:
        return "\n\n".join(_hexdump(p.content) for p in packets)
    raise NotImplementedError(f"mode {mode} not implemented yet")
```

- [ ] **Step 5.4: Run tests to verify they pass**

```bash
uv run pytest tests/test_formatting.py -v
```

Expected: 3 passed.

- [ ] **Step 5.5: Commit**

```bash
git add src/packmate_mcp/formatting.py tests/test_formatting.py
git commit -m "feat(formatting): add canonical hexdump mode"
```

---

## Task 6: Formatting — `python_bytes` mode

**Files:**
- Modify: `src/packmate_mcp/formatting.py`
- Modify: `tests/test_formatting.py`

- [ ] **Step 6.1: Write failing test**

Append to `tests/test_formatting.py`:

```python
def test_python_bytes_basic() -> None:
    p = _packet(b"GET")
    out = format_content([p], ContentFormat.PYTHON_BYTES)
    assert out == "b'\\x47\\x45\\x54'"


def test_python_bytes_special_chars() -> None:
    p = _packet(b"\x00\n\\'\"a")
    out = format_content([p], ContentFormat.PYTHON_BYTES)
    # every byte is escaped to \xNN form for determinism
    assert out == "b'\\x00\\x0a\\x5c\\x27\\x22\\x61'"


def test_python_bytes_multiple_packets_separated() -> None:
    out = format_content([_packet(b"A"), _packet(b"B")], ContentFormat.PYTHON_BYTES)
    assert out == "b'\\x41'\nb'\\x42'"
```

- [ ] **Step 6.2: Run test to verify it fails**

```bash
uv run pytest tests/test_formatting.py::test_python_bytes_basic -v
```

Expected: `NotImplementedError`.

- [ ] **Step 6.3: Implement `python_bytes` mode**

In `src/packmate_mcp/formatting.py`, add this helper after `_hexdump`:

```python
def _python_bytes_literal(data: bytes) -> str:
    """Render bytes as a Python bytes literal using \\xNN escapes for every byte.

    Uses full escape form unconditionally for determinism — no special-case for
    printable bytes.
    """
    return "b'" + "".join(f"\\x{b:02x}" for b in data) + "'"
```

Replace the body of `format_content` to handle `PYTHON_BYTES`:

```python
def format_content(
    packets: Sequence[Packet],
    mode: ContentFormat = ContentFormat.TRANSCRIPT,
    max_bytes_per_packet: int = 4096,
    total_max_bytes: int = 64_000,
    max_packets: int = 200,
) -> str:
    if mode is ContentFormat.HEX:
        return "\n\n".join(_hexdump(p.content) for p in packets)
    if mode is ContentFormat.PYTHON_BYTES:
        return "\n".join(_python_bytes_literal(p.content) for p in packets)
    raise NotImplementedError(f"mode {mode} not implemented yet")
```

- [ ] **Step 6.4: Run tests**

```bash
uv run pytest tests/test_formatting.py -v
```

Expected: 6 passed.

- [ ] **Step 6.5: Commit**

```bash
git add src/packmate_mcp/formatting.py tests/test_formatting.py
git commit -m "feat(formatting): add python_bytes literal mode"
```

---

## Task 7: Formatting — `base64` mode

**Files:**
- Modify: `src/packmate_mcp/formatting.py`
- Modify: `tests/test_formatting.py`

- [ ] **Step 7.1: Write failing test**

Append to `tests/test_formatting.py`:

```python
def test_base64_round_trip() -> None:
    import base64

    p = _packet(b"\x01\x02\x03\xff")
    out = format_content([p], ContentFormat.BASE64)
    assert base64.b64decode(out) == b"\x01\x02\x03\xff"


def test_base64_multiple_packets_newline_separated() -> None:
    p1 = _packet(b"A")
    p2 = _packet(b"B")
    out = format_content([p1, p2], ContentFormat.BASE64)
    lines = out.split("\n")
    assert len(lines) == 2
    import base64

    assert base64.b64decode(lines[0]) == b"A"
    assert base64.b64decode(lines[1]) == b"B"
```

- [ ] **Step 7.2: Run test, verify failure**

```bash
uv run pytest tests/test_formatting.py::test_base64_round_trip -v
```

Expected: `NotImplementedError`.

- [ ] **Step 7.3: Implement `base64` mode**

In `src/packmate_mcp/formatting.py`, add at top of file:

```python
import base64 as _base64
```

Extend `format_content`:

```python
    if mode is ContentFormat.BASE64:
        return "\n".join(_base64.b64encode(p.content).decode("ascii") for p in packets)
```

- [ ] **Step 7.4: Run tests**

```bash
uv run pytest tests/test_formatting.py -v
```

Expected: 8 passed.

- [ ] **Step 7.5: Commit**

```bash
git add src/packmate_mcp/formatting.py tests/test_formatting.py
git commit -m "feat(formatting): add base64 passthrough mode"
```

---

## Task 8: Formatting — `text` mode

**Files:**
- Modify: `src/packmate_mcp/formatting.py`
- Modify: `tests/test_formatting.py`

- [ ] **Step 8.1: Write failing test**

Append to `tests/test_formatting.py`:

```python
def test_text_utf8() -> None:
    p = _packet("héllo".encode("utf-8"))
    out = format_content([p], ContentFormat.TEXT)
    assert out == "héllo"


def test_text_invalid_utf8_backslashreplace() -> None:
    p = _packet(b"\xff\xfe\x00A")
    out = format_content([p], ContentFormat.TEXT)
    # invalid UTF-8 sequences become \xNN escapes
    assert "\\xff" in out
    assert "A" in out


def test_text_multiple_packets_joined_with_double_newline() -> None:
    out = format_content([_packet(b"hello"), _packet(b"world")], ContentFormat.TEXT)
    assert out == "hello\n\nworld"
```

- [ ] **Step 8.2: Verify failure**

```bash
uv run pytest tests/test_formatting.py::test_text_utf8 -v
```

Expected: `NotImplementedError`.

- [ ] **Step 8.3: Implement `text` mode**

Extend `format_content`:

```python
    if mode is ContentFormat.TEXT:
        return "\n\n".join(p.content.decode("utf-8", errors="backslashreplace") for p in packets)
```

- [ ] **Step 8.4: Run tests**

```bash
uv run pytest tests/test_formatting.py -v
```

Expected: 11 passed.

- [ ] **Step 8.5: Commit**

```bash
git add src/packmate_mcp/formatting.py tests/test_formatting.py
git commit -m "feat(formatting): add text mode"
```

---

## Task 9: Formatting — `transcript` mode

**Files:**
- Modify: `src/packmate_mcp/formatting.py`
- Modify: `tests/test_formatting.py`

- [ ] **Step 9.1: Write failing tests**

Append to `tests/test_formatting.py`:

```python
def test_transcript_text_packet_uses_text_body() -> None:
    p = _packet(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", incoming=True)
    p.id = 142
    out = format_content([p], ContentFormat.TRANSCRIPT)
    assert "Packet #142" in out
    assert "client→server" in out
    assert "(28 bytes)" in out
    assert "GET / HTTP/1.1" in out


def test_transcript_binary_packet_uses_hexdump_body() -> None:
    p = _packet(b"\x17\x03\x03\x00\x1b\x00", incoming=False)
    out = format_content([p], ContentFormat.TRANSCRIPT)
    assert "server→client" in out
    assert "binary" in out
    assert "00000000:" in out  # hexdump body present
    assert "17 03 03" in out


def test_transcript_direction_label() -> None:
    p_in = _packet(b"REQ", incoming=True)
    p_out = _packet(b"RES", incoming=False)
    out = format_content([p_in, p_out], ContentFormat.TRANSCRIPT)
    assert "client→server" in out
    assert "server→client" in out


def test_transcript_flags_shown_when_set() -> None:
    p = _packet(b"HTTP/1.1 200 OK")
    p.tls_decrypted = True
    p.has_http_body = True
    out = format_content([p], ContentFormat.TRANSCRIPT)
    assert "[tls_decrypted, http_body]" in out


def test_transcript_no_flag_section_when_all_false() -> None:
    p = _packet(b"hello")
    out = format_content([p], ContentFormat.TRANSCRIPT)
    assert "[" not in out.split("\n")[0]  # header has no bracketed flag section


def test_transcript_timestamp_in_header() -> None:
    # 1_700_000_000_123 ms -> UTC 2023-11-14 22:13:20.123
    p = _packet(b"x", ts=1_700_000_000_123)
    out = format_content([p], ContentFormat.TRANSCRIPT)
    assert "22:13:20.123" in out
```

- [ ] **Step 9.2: Verify failure**

```bash
uv run pytest tests/test_formatting.py::test_transcript_text_packet_uses_text_body -v
```

Expected: `NotImplementedError`.

- [ ] **Step 9.3: Implement transcript helpers**

In `src/packmate_mcp/formatting.py`, add after `_python_bytes_literal`:

```python
import datetime as _dt

_PRINTABLE_THRESHOLD = 0.9
_TEXT_BYTES = set(b"\t\r\n") | set(range(0x20, 0x7F))


def _is_mostly_text(data: bytes) -> bool:
    if not data:
        return True
    hits = sum(1 for b in data if b in _TEXT_BYTES)
    return hits / len(data) >= _PRINTABLE_THRESHOLD


def _format_timestamp_ms(ts_ms: int) -> str:
    dt = _dt.datetime.fromtimestamp(ts_ms / 1000, tz=_dt.timezone.utc)
    return dt.strftime("%H:%M:%S.") + f"{ts_ms % 1000:03d}"


def _packet_flags(p: Packet) -> str:
    flags = []
    if p.tls_decrypted:
        flags.append("tls_decrypted")
    if p.web_socket_parsed:
        flags.append("web_socket_parsed")
    if p.ungzipped:
        flags.append("ungzipped")
    if p.has_http_body:
        flags.append("http_body")
    return f" [{', '.join(flags)}]" if flags else ""


def _transcript_header(p: Packet, *, body_kind: str) -> str:
    direction = "client→server" if p.incoming else "server→client"
    ts = _format_timestamp_ms(p.timestamp)
    size = len(p.content)
    kind_suffix = f", {body_kind}" if body_kind != "text" else ""
    flags = _packet_flags(p)
    return f"─── Packet #{p.id} @ {ts}  {direction}  ({size} bytes{kind_suffix}){flags} ───"


def _format_one_transcript(p: Packet) -> str:
    if _is_mostly_text(p.content):
        header = _transcript_header(p, body_kind="text")
        body = p.content.decode("utf-8", errors="backslashreplace")
    else:
        header = _transcript_header(p, body_kind="binary")
        body = _hexdump(p.content)
    return f"{header}\n{body}"
```

Extend `format_content`:

```python
    if mode is ContentFormat.TRANSCRIPT:
        return "\n\n".join(_format_one_transcript(p) for p in packets)
```

- [ ] **Step 9.4: Run tests**

```bash
uv run pytest tests/test_formatting.py -v
```

Expected: 17 passed.

- [ ] **Step 9.5: Commit**

```bash
git add src/packmate_mcp/formatting.py tests/test_formatting.py
git commit -m "feat(formatting): add transcript mode with auto text/hex body"
```

---

## Task 10: Formatting — trimming (per-packet, total, count)

**Files:**
- Modify: `src/packmate_mcp/formatting.py`
- Modify: `tests/test_formatting.py`

- [ ] **Step 10.1: Write failing tests**

Append to `tests/test_formatting.py`:

```python
def test_max_bytes_per_packet_truncates_marker() -> None:
    p = _packet(b"A" * 100)
    out = format_content([p], ContentFormat.TEXT, max_bytes_per_packet=10)
    assert out.startswith("AAAAAAAAAA")
    assert "[truncated: 90 more bytes]" in out


def test_max_bytes_per_packet_no_marker_when_fits() -> None:
    p = _packet(b"AAA")
    out = format_content([p], ContentFormat.TEXT, max_bytes_per_packet=10)
    assert "truncated" not in out


def test_max_packets_caps_count() -> None:
    packets = [_packet(b"x")] * 5
    for i, p in enumerate(packets):
        p.id = i
    out = format_content(packets, ContentFormat.TRANSCRIPT, max_packets=2)
    assert "Packet #0" in out
    assert "Packet #1" in out
    assert "Packet #2 (skipped: max_packets reached)" in out
    assert "Packet #3" not in out.split("Packet #2")[1].split("Packet #")[0]


def test_total_max_bytes_exhausts_budget() -> None:
    big = _packet(b"X" * 1000)
    big.id = 1
    small = _packet(b"y")
    small.id = 2
    out = format_content(
        [big, small],
        ContentFormat.TEXT,
        max_bytes_per_packet=1000,
        total_max_bytes=500,
    )
    # big gets truncated mid-way, small gets skipped
    assert "Packet #2 (skipped: total budget exhausted)" in out


def test_truncation_marker_visible_when_binary() -> None:
    p = _packet(b"\xff" * 50)
    out = format_content([p], ContentFormat.TRANSCRIPT, max_bytes_per_packet=4)
    # transcript renders as hexdump for binary, truncation marker still appears
    assert "[truncated: 46 more bytes]" in out
```

- [ ] **Step 10.2: Verify failure**

```bash
uv run pytest tests/test_formatting.py::test_max_bytes_per_packet_truncates_marker -v
```

Expected: assertion error — current implementation ignores limits.

- [ ] **Step 10.3: Implement trimming**

Replace the body of `format_content` entirely with a routing function that applies trimming uniformly:

```python
def _truncate(data: bytes, limit: int) -> tuple[bytes, int]:
    """Truncate to `limit` bytes; return (data, dropped_count)."""
    if len(data) <= limit:
        return data, 0
    return data[:limit], len(data) - limit


def _render_single(p: Packet, mode: ContentFormat, max_bytes: int) -> str:
    data, dropped = _truncate(p.content, max_bytes)
    truncated_p = p.model_copy(update={"content": data})
    if mode is ContentFormat.TRANSCRIPT:
        body = _format_one_transcript(truncated_p)
    elif mode is ContentFormat.TEXT:
        body = data.decode("utf-8", errors="backslashreplace")
    elif mode is ContentFormat.HEX:
        body = _hexdump(data)
    elif mode is ContentFormat.PYTHON_BYTES:
        body = _python_bytes_literal(data)
    elif mode is ContentFormat.BASE64:
        body = _base64.b64encode(data).decode("ascii")
    else:
        raise ValueError(f"unknown mode: {mode}")
    if dropped:
        body = f"{body}\n[truncated: {dropped} more bytes]"
    return body


_BLOCK_SEPARATOR = {
    ContentFormat.TRANSCRIPT: "\n\n",
    ContentFormat.TEXT: "\n\n",
    ContentFormat.HEX: "\n\n",
    ContentFormat.PYTHON_BYTES: "\n",
    ContentFormat.BASE64: "\n",
}


def format_content(
    packets: Sequence[Packet],
    mode: ContentFormat = ContentFormat.TRANSCRIPT,
    max_bytes_per_packet: int = 4096,
    total_max_bytes: int = 64_000,
    max_packets: int = 200,
) -> str:
    parts: list[str] = []
    used = 0
    for i, p in enumerate(packets):
        if i >= max_packets:
            parts.append(f"─── Packet #{p.id} (skipped: max_packets reached) ───")
            break
        rendered = _render_single(p, mode, max_bytes_per_packet)
        if used + len(rendered) > total_max_bytes and parts:
            parts.append(f"─── Packet #{p.id} (skipped: total budget exhausted) ───")
            continue
        parts.append(rendered)
        used += len(rendered)
    return _BLOCK_SEPARATOR[mode].join(parts)
```

Notes for the implementer:
- `model_copy(update={"content": data})` creates a shallow copy with the truncated bytes, so `_format_one_transcript` sees the right size in the header.
- The `parts` separator depends on mode (transcript needs blank lines, base64/python_bytes do not).
- The "skipped" marker uses the same `─── … ───` style as headers, so it parses visually.
- The `and parts` guard makes sure we always emit at least one rendered packet even if it exceeds the budget — otherwise an LLM-side `total_max_bytes=0` would produce nothing.

- [ ] **Step 10.4: Run all formatting tests**

```bash
uv run pytest tests/test_formatting.py -v
```

Expected: 22 passed.

- [ ] **Step 10.5: Commit**

```bash
git add src/packmate_mcp/formatting.py tests/test_formatting.py
git commit -m "feat(formatting): add three-layer trimming (per-packet, total, count)"
```

---

## Task 11: Client exceptions

**Files:**
- Create: `src/packmate_mcp/client.py`
- Create: `tests/test_client.py`

- [ ] **Step 11.1: Write failing test**

Create `tests/test_client.py`:

```python
"""Tests for PackmateClient HTTP layer."""

from __future__ import annotations

import pytest

from packmate_mcp.client import (
    PackmateAuthError,
    PackmateConnectionError,
    PackmateError,
    PackmateNotFoundError,
    PackmateServerError,
    PackmateValidationError,
)


def test_exception_hierarchy() -> None:
    assert issubclass(PackmateAuthError, PackmateError)
    assert issubclass(PackmateConnectionError, PackmateError)
    assert issubclass(PackmateNotFoundError, PackmateError)
    assert issubclass(PackmateValidationError, PackmateError)
    assert issubclass(PackmateServerError, PackmateError)


def test_exceptions_carry_messages() -> None:
    e = PackmateNotFoundError("Stream 42 not found.")
    assert str(e) == "Stream 42 not found."
```

- [ ] **Step 11.2: Verify failure**

```bash
uv run pytest tests/test_client.py -v
```

Expected: `ModuleNotFoundError: No module named 'packmate_mcp.client'`

- [ ] **Step 11.3: Create `client.py` with exception hierarchy**

Create `src/packmate_mcp/client.py`:

```python
"""Async HTTP client for Packmate's REST API."""

from __future__ import annotations


class PackmateError(Exception):
    """Base for all errors raised by PackmateClient."""


class PackmateConnectionError(PackmateError):
    """Network failure: cannot reach Packmate, or request timed out."""


class PackmateAuthError(PackmateError):
    """HTTP 401/403 — bad credentials."""


class PackmateNotFoundError(PackmateError):
    """HTTP 404 — resource does not exist."""


class PackmateValidationError(PackmateError):
    """HTTP 4xx (other than 401/403/404) — Packmate rejected the request."""


class PackmateServerError(PackmateError):
    """HTTP 5xx — Packmate internal error."""
```

- [ ] **Step 11.4: Run tests**

```bash
uv run pytest tests/test_client.py -v
```

Expected: 2 passed.

- [ ] **Step 11.5: Commit**

```bash
git add src/packmate_mcp/client.py tests/test_client.py
git commit -m "feat(client): add typed PackmateError hierarchy"
```

---

## Task 12: Client `_request()` with error mapping

**Files:**
- Modify: `src/packmate_mcp/client.py`
- Modify: `tests/test_client.py`

- [ ] **Step 12.1: Write failing tests**

Append to `tests/test_client.py`:

```python
import httpx
import respx

from packmate_mcp.client import PackmateClient
from packmate_mcp.config import PackmateSettings


def _settings() -> PackmateSettings:
    return PackmateSettings(login="u", password="p")


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
```

- [ ] **Step 12.2: Verify failure**

```bash
uv run pytest tests/test_client.py -v
```

Expected: import error on `PackmateClient`.

- [ ] **Step 12.3: Implement `PackmateClient` with `_request()`**

Replace the contents of `src/packmate_mcp/client.py` with:

```python
"""Async HTTP client for Packmate's REST API."""

from __future__ import annotations

import logging
from types import TracebackType
from typing import Any, Optional

import httpx

from packmate_mcp.config import PackmateSettings

log = logging.getLogger(__name__)


class PackmateError(Exception):
    """Base for all errors raised by PackmateClient."""


class PackmateConnectionError(PackmateError):
    """Network failure: cannot reach Packmate, or request timed out."""


class PackmateAuthError(PackmateError):
    """HTTP 401/403 — bad credentials."""


class PackmateNotFoundError(PackmateError):
    """HTTP 404 — resource does not exist."""


class PackmateValidationError(PackmateError):
    """HTTP 4xx (other than 401/403/404) — Packmate rejected the request."""


class PackmateServerError(PackmateError):
    """HTTP 5xx — Packmate internal error."""


class PackmateClient:
    """Thin async client over Packmate's REST API.

    Use as an async context manager:
        async with PackmateClient(settings) as client:
            services = await client.list_services()
    """

    def __init__(self, settings: PackmateSettings) -> None:
        self._settings = settings
        self._http: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "PackmateClient":
        self._http = httpx.AsyncClient(
            base_url=str(self._settings.base_url).rstrip("/"),
            auth=(self._settings.login, self._settings.password),
            timeout=self._settings.timeout_seconds,
        )
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Optional[dict[str, Any]] = None,
    ) -> httpx.Response:
        assert self._http is not None, "PackmateClient must be used as async context manager"
        try:
            response = await self._http.request(method, path, json=json, params=params)
        except httpx.TimeoutException as e:
            raise PackmateConnectionError(
                f"Request to {method} {path} timed out after {self._settings.timeout_seconds}s."
            ) from e
        except httpx.ConnectError as e:
            raise PackmateConnectionError(
                f"Cannot reach Packmate at {self._settings.base_url}. Is the server running?"
            ) from e
        except httpx.HTTPError as e:
            raise PackmateConnectionError(f"HTTP error: {e}") from e

        if response.status_code in (401, 403):
            raise PackmateAuthError(
                "Authentication failed. Check PACKMATE_MCP_LOGIN and PACKMATE_MCP_PASSWORD env vars."
            )
        if response.status_code == 404:
            raise PackmateNotFoundError(f"Resource not found: {method} {path}")
        if 400 <= response.status_code < 500:
            raise PackmateValidationError(
                f"Packmate rejected request ({response.status_code}): {response.text}"
            )
        if response.status_code >= 500:
            raise PackmateServerError(
                f"Packmate server error ({response.status_code}). "
                f"Check Packmate logs. Body: {response.text}"
            )
        return response
```

- [ ] **Step 12.4: Run tests**

```bash
uv run pytest tests/test_client.py -v
```

Expected: 9 passed (2 from Task 11 + 7 from this task).

- [ ] **Step 12.5: Commit**

```bash
git add src/packmate_mcp/client.py tests/test_client.py
git commit -m "feat(client): implement _request with httpx error mapping"
```

---

## Task 13: Client — services methods

**Files:**
- Modify: `src/packmate_mcp/client.py`
- Modify: `tests/test_client.py`

- [ ] **Step 13.1: Write failing tests**

Append to `tests/test_client.py`:

```python
from packmate_mcp.models import Service, ServiceCreate, ServiceUpdate


@pytest.mark.asyncio
async def test_list_services_returns_models() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            mock.get("/api/service/").mock(
                return_value=httpx.Response(
                    200,
                    json=[
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
                    ],
                )
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
                return_value=httpx.Response(
                    200,
                    json={
                        "id": 1,
                        "name": "vuln",
                        "port": 8080,
                        "mergeAdjacentPackets": True,
                        "urldecodeHttpRequests": False,
                        "decryptTls": False,
                        "parseWebSockets": False,
                        "http": False,
                    },
                )
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
                return_value=httpx.Response(
                    200,
                    json={
                        "id": 1,
                        "name": "vuln",
                        "port": 8080,
                        "mergeAdjacentPackets": False,
                        "urldecodeHttpRequests": True,
                        "decryptTls": False,
                        "parseWebSockets": False,
                        "http": False,
                    },
                )
            )
            su = ServiceUpdate(urldecode_http_requests=True)
            await client.update_service(8080, su)
            assert route.called
            body = route.calls[0].request.read().decode()
            assert body == '{"urldecodeHttpRequests":true}'  # exclude_unset


@pytest.mark.asyncio
async def test_delete_service() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.delete("/api/service/8080").mock(return_value=httpx.Response(200))
            await client.delete_service(8080)
            assert route.called
```

- [ ] **Step 13.2: Verify failure**

```bash
uv run pytest tests/test_client.py::test_list_services_returns_models -v
```

Expected: `AttributeError: 'PackmateClient' object has no attribute 'list_services'`.

- [ ] **Step 13.3: Implement service methods**

Append to `src/packmate_mcp/client.py` (inside the `PackmateClient` class):

```python
    # ---------- services ----------

    async def list_services(self) -> list["Service"]:
        from packmate_mcp.models import Service

        r = await self._request("GET", "/api/service/")
        return [Service.model_validate(item) for item in r.json()]

    async def create_service(self, payload: "ServiceCreate") -> "Service":
        from packmate_mcp.models import Service

        r = await self._request(
            "POST",
            "/api/service/",
            json=payload.model_dump(by_alias=True),
        )
        return Service.model_validate(r.json())

    async def update_service(self, port: int, payload: "ServiceUpdate") -> "Service":
        from packmate_mcp.models import Service

        r = await self._request(
            "POST",
            f"/api/service/{port}",
            json=payload.model_dump(by_alias=True, exclude_unset=True),
        )
        return Service.model_validate(r.json())

    async def delete_service(self, port: int) -> None:
        await self._request("DELETE", f"/api/service/{port}")
```

Also add forward-reference imports at the top of the file just below the existing imports (replace the existing `from packmate_mcp.config import PackmateSettings` line with):

```python
from packmate_mcp.config import PackmateSettings

# Re-exported for type-checkers and import sites that mock the client.
from packmate_mcp.models import (  # noqa: F401
    FoundPattern,
    Packet,
    PacketPagination,
    Pattern,
    PatternCreate,
    PatternUpdate,
    Service,
    ServiceCreate,
    ServiceUpdate,
    Stream,
    StreamPagination,
)
```

(The local `from packmate_mcp.models import Service` lines inside methods are kept to keep the example methods self-contained; subsequent tasks can drop them once the module-level imports are in place.)

- [ ] **Step 13.4: Run tests**

```bash
uv run pytest tests/test_client.py -v
```

Expected: 13 passed.

- [ ] **Step 13.5: Commit**

```bash
git add src/packmate_mcp/client.py tests/test_client.py
git commit -m "feat(client): add service CRUD methods"
```

---

## Task 14: Client — patterns methods

**Files:**
- Modify: `src/packmate_mcp/client.py`
- Modify: `tests/test_client.py`

- [ ] **Step 14.1: Write failing tests**

Append to `tests/test_client.py`:

```python
from packmate_mcp.models import (
    Pattern,
    PatternActionType,
    PatternCreate,
    PatternDirectionType,
    PatternSearchType,
    PatternUpdate,
)


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
            mock.get("/api/pattern/").mock(return_value=httpx.Response(200, json=[_pattern_json()]))
            patterns = await client.list_patterns()
            assert len(patterns) == 1
            assert isinstance(patterns[0], Pattern)


@pytest.mark.asyncio
async def test_create_pattern() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/pattern/").mock(return_value=httpx.Response(200, json=_pattern_json()))
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
            route = mock.post("/api/pattern/7").mock(return_value=httpx.Response(200, json=_pattern_json(7)))
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
            route = mock.post("/api/pattern/7/enable", params={"enabled": "true"}).mock(
                return_value=httpx.Response(200)
            )
            await client.set_pattern_enabled(7, enabled=True)
            assert route.called


@pytest.mark.asyncio
async def test_pattern_lookback() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/pattern/7/lookback").mock(return_value=httpx.Response(200))
            await client.pattern_lookback(7, minutes=5)
            assert route.called
            assert route.calls[0].request.read().decode() == "5"
```

- [ ] **Step 14.2: Verify failure**

```bash
uv run pytest tests/test_client.py::test_list_patterns -v
```

Expected: `AttributeError`.

- [ ] **Step 14.3: Implement pattern methods**

Append to `PackmateClient` in `src/packmate_mcp/client.py`:

```python
    # ---------- patterns ----------

    async def list_patterns(self) -> list[Pattern]:
        r = await self._request("GET", "/api/pattern/")
        return [Pattern.model_validate(item) for item in r.json()]

    async def create_pattern(self, payload: PatternCreate) -> Pattern:
        r = await self._request(
            "POST",
            "/api/pattern/",
            json=payload.model_dump(by_alias=True, exclude_none=True),
        )
        return Pattern.model_validate(r.json())

    async def update_pattern(self, pattern_id: int, payload: PatternUpdate) -> Pattern:
        r = await self._request(
            "POST",
            f"/api/pattern/{pattern_id}",
            json=payload.model_dump(by_alias=True, exclude_unset=True),
        )
        return Pattern.model_validate(r.json())

    async def delete_pattern(self, pattern_id: int) -> None:
        await self._request("DELETE", f"/api/pattern/{pattern_id}")

    async def set_pattern_enabled(self, pattern_id: int, enabled: bool) -> None:
        await self._request(
            "POST",
            f"/api/pattern/{pattern_id}/enable",
            params={"enabled": "true" if enabled else "false"},
        )

    async def pattern_lookback(self, pattern_id: int, minutes: int) -> None:
        # Packmate's controller deserializes the body as `int` directly (not JSON object).
        # httpx's `json=N` encodes the number correctly: just the digits.
        await self._request(
            "POST",
            f"/api/pattern/{pattern_id}/lookback",
            json=minutes,
        )
```

- [ ] **Step 14.4: Run tests**

```bash
uv run pytest tests/test_client.py -v
```

Expected: 19 passed.

- [ ] **Step 14.5: Commit**

```bash
git add src/packmate_mcp/client.py tests/test_client.py
git commit -m "feat(client): add pattern CRUD + enable + lookback methods"
```

---

## Task 15: Client — streams & packets methods

**Files:**
- Modify: `src/packmate_mcp/client.py`
- Modify: `tests/test_client.py`

- [ ] **Step 15.1: Write failing tests**

Append to `tests/test_client.py`:

```python
from packmate_mcp.models import PacketPagination, Protocol, Stream, StreamPagination


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
    import base64

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
            route = mock.post("/api/stream/42/favorite").mock(return_value=httpx.Response(200))
            await client.set_stream_favorite(42, favorite=True)
            assert route.called


@pytest.mark.asyncio
async def test_unfavorite_stream() -> None:
    async with PackmateClient(_settings()) as client:
        with respx.mock(base_url="http://localhost:65000") as mock:
            route = mock.post("/api/stream/42/unfavorite").mock(return_value=httpx.Response(200))
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
```

- [ ] **Step 15.2: Verify failure**

```bash
uv run pytest tests/test_client.py::test_list_streams_all -v
```

Expected: `AttributeError`.

- [ ] **Step 15.3: Implement stream + packet methods**

Append to `PackmateClient`:

```python
    # ---------- streams ----------

    async def list_streams(
        self,
        pagination: StreamPagination,
        *,
        port: Optional[int] = None,
    ) -> list[Stream]:
        path = "/api/stream/all" if port is None else f"/api/stream/{port}"
        r = await self._request(
            "POST",
            path,
            json=pagination.model_dump(by_alias=True),
        )
        return [Stream.model_validate(item) for item in r.json()]

    async def set_stream_favorite(self, stream_id: int, favorite: bool) -> None:
        suffix = "favorite" if favorite else "unfavorite"
        await self._request("POST", f"/api/stream/{stream_id}/{suffix}")

    # ---------- packets ----------

    async def get_packets(self, stream_id: int, pagination: PacketPagination) -> list[Packet]:
        r = await self._request(
            "POST",
            f"/api/packet/{stream_id}",
            json=pagination.model_dump(by_alias=True),
        )
        return [Packet.model_validate(item) for item in r.json()]
```

- [ ] **Step 15.4: Run tests**

```bash
uv run pytest tests/test_client.py -v
```

Expected: 24 passed.

- [ ] **Step 15.5: Commit**

```bash
git add src/packmate_mcp/client.py tests/test_client.py
git commit -m "feat(client): add stream listing/favorite + packet pagination"
```

---

## Task 16: Client — pcap methods

**Files:**
- Modify: `src/packmate_mcp/client.py`
- Modify: `tests/test_client.py`

- [ ] **Step 16.1: Write failing tests**

Append to `tests/test_client.py`:

```python
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
```

- [ ] **Step 16.2: Verify failure**

```bash
uv run pytest tests/test_client.py::test_pcap_status_true -v
```

Expected: `AttributeError`.

- [ ] **Step 16.3: Implement pcap methods**

Append to `PackmateClient`:

```python
    # ---------- pcap ----------

    async def pcap_status(self) -> bool:
        r = await self._request("GET", "/api/pcap/started")
        return bool(r.json())

    async def pcap_start(self) -> None:
        await self._request("POST", "/api/pcap/start")
```

- [ ] **Step 16.4: Run tests**

```bash
uv run pytest tests/test_client.py -v
```

Expected: 27 passed.

- [ ] **Step 16.5: Commit**

```bash
git add src/packmate_mcp/client.py tests/test_client.py
git commit -m "feat(client): add pcap status/start methods"
```

---

## Task 17: Tools — services

**Files:**
- Create: `src/packmate_mcp/tools/__init__.py`
- Create: `src/packmate_mcp/tools/services.py`
- Create: `tests/test_tools.py`

- [ ] **Step 17.1: Write failing tests**

Create `tests/test_tools.py`:

```python
"""Integration tests for MCP tools.

We don't go through FastMCP's protocol — we instead import the registered
callables directly and call them as async functions with mocked HTTP.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from mcp.server.fastmcp import FastMCP

from packmate_mcp.client import PackmateClient
from packmate_mcp.config import PackmateSettings


@pytest.fixture
async def client():
    settings = PackmateSettings(login="u", password="p")
    async with PackmateClient(settings) as c:
        yield c


def _mcp() -> FastMCP:
    return FastMCP("packmate-test")


@pytest.mark.asyncio
async def test_list_services_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.services import register

    mcp = _mcp()
    register(mcp, client)
    # FastMCP exposes registered tools via _tool_manager
    fn = mcp._tool_manager._tools["list_services"].fn

    with respx.mock(base_url="http://localhost:65000") as mock:
        mock.get("/api/service/").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "id": 1,
                        "name": "vuln",
                        "port": 8080,
                        "mergeAdjacentPackets": False,
                        "urldecodeHttpRequests": False,
                        "decryptTls": False,
                        "parseWebSockets": False,
                        "http": False,
                    }
                ],
            )
        )
        result = await fn()
        assert len(result) == 1
        assert result[0].port == 8080


@pytest.mark.asyncio
async def test_create_service_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.services import register

    mcp = _mcp()
    register(mcp, client)
    fn = mcp._tool_manager._tools["create_service"].fn

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post("/api/service/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": 1,
                    "name": "vuln",
                    "port": 8080,
                    "mergeAdjacentPackets": True,
                    "urldecodeHttpRequests": False,
                    "decryptTls": False,
                    "parseWebSockets": False,
                    "http": False,
                },
            )
        )
        await fn(name="vuln", port=8080, merge_adjacent_packets=True)
        assert route.called


@pytest.mark.asyncio
async def test_delete_service_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.services import register

    mcp = _mcp()
    register(mcp, client)
    fn = mcp._tool_manager._tools["delete_service"].fn

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.delete("/api/service/8080").mock(return_value=httpx.Response(200))
        await fn(port=8080)
        assert route.called
```

- [ ] **Step 17.2: Verify failure**

```bash
uv run pytest tests/test_tools.py -v
```

Expected: `ModuleNotFoundError: No module named 'packmate_mcp.tools'`.

- [ ] **Step 17.3: Implement service tools**

Create `src/packmate_mcp/tools/__init__.py`:

```python
"""Tool registration for MCP server.

Each submodule exposes a `register(mcp, client)` function that attaches its tools
to the FastMCP instance using the shared PackmateClient. `register_all` (added in
Task 22, once all submodules exist) glues them together.
"""
```

(Intentionally just a docstring. We add `register_all` in Task 22 to avoid importing tool submodules that do not exist yet.)

Create `src/packmate_mcp/tools/services.py`:

```python
"""MCP tools for Packmate service management."""

from __future__ import annotations

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
        name: str | None = None,
        merge_adjacent_packets: bool | None = None,
        urldecode_http_requests: bool | None = None,
        decrypt_tls: bool | None = None,
        parse_web_sockets: bool | None = None,
        http: bool | None = None,
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
```

- [ ] **Step 17.4: Run tests**

```bash
uv run pytest tests/test_tools.py -v
```

Expected: 3 passed.

- [ ] **Step 17.5: Commit**

```bash
git add src/packmate_mcp/tools/ tests/test_tools.py
git commit -m "feat(tools): add service CRUD tools"
```

---

## Task 18: Tools — patterns

**Files:**
- Create: `src/packmate_mcp/tools/patterns.py`
- Modify: `tests/test_tools.py`

- [ ] **Step 18.1: Write failing tests**

Append to `tests/test_tools.py`:

```python
@pytest.mark.asyncio
async def test_create_pattern_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.patterns import register

    mcp = _mcp()
    register(mcp, client)
    fn = mcp._tool_manager._tools["create_pattern"].fn

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post("/api/pattern/").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": 1,
                    "name": "flag",
                    "value": "CTF{",
                    "color": None,
                    "actionType": "FIND",
                    "searchType": "SUBSTRING",
                    "directionType": "BOTH",
                    "service": None,
                    "enabled": True,
                },
            )
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
    fn = mcp._tool_manager._tools["pattern_lookback"].fn

    with pytest.raises(Exception):  # pydantic ValidationError
        await fn(pattern_id=7, minutes=0)


@pytest.mark.asyncio
async def test_set_pattern_enabled_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.patterns import register

    mcp = _mcp()
    register(mcp, client)
    fn = mcp._tool_manager._tools["set_pattern_enabled"].fn

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post("/api/pattern/7/enable", params={"enabled": "false"}).mock(
            return_value=httpx.Response(200)
        )
        await fn(pattern_id=7, enabled=False)
        assert route.called
```

- [ ] **Step 18.2: Verify failure**

```bash
uv run pytest tests/test_tools.py::test_create_pattern_tool -v
```

Expected: `ModuleNotFoundError: No module named 'packmate_mcp.tools.patterns'`.

- [ ] **Step 18.3: Implement pattern tools**

Create `src/packmate_mcp/tools/patterns.py`:

```python
"""MCP tools for Packmate pattern management."""

from __future__ import annotations

from typing import Optional

from mcp.server.fastmcp import FastMCP
from pydantic import Field
from typing_extensions import Annotated

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
        color: Optional[str] = None,
        service_port: Optional[int] = None,
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
        name: Optional[str] = None,
        value: Optional[str] = None,
        color: Optional[str] = None,
        action_type: Optional[PatternActionType] = None,
        search_type: Optional[PatternSearchType] = None,
        direction_type: Optional[PatternDirectionType] = None,
        service_port: Optional[int] = None,
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
        """Apply a pattern to streams captured in the last N minutes (N ≥ 1).

        Useful after creating a new pattern to retroactively scan recent traffic.
        """
        await client.pattern_lookback(pattern_id, minutes)
```

- [ ] **Step 18.4: Run tests**

```bash
uv run pytest tests/test_tools.py -v
```

Expected: 6 passed.

- [ ] **Step 18.5: Commit**

```bash
git add src/packmate_mcp/tools/patterns.py tests/test_tools.py
git commit -m "feat(tools): add pattern CRUD + enable + lookback tools"
```

---

## Task 19: Tools — streams (`list_streams`, `get_stream`, `set_stream_favorite`)

**Files:**
- Create: `src/packmate_mcp/tools/streams.py`
- Modify: `tests/test_tools.py`

- [ ] **Step 19.1: Write failing tests**

Append to `tests/test_tools.py`:

```python
import base64


def _stream_dict(sid: int) -> dict:
    return {
        "id": sid,
        "service": 8080,
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


@pytest.mark.asyncio
async def test_list_streams_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.streams import register

    mcp = _mcp()
    register(mcp, client)
    fn = mcp._tool_manager._tools["list_streams"].fn

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
    fn = mcp._tool_manager._tools["list_streams"].fn

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
    fn = mcp._tool_manager._tools["set_stream_favorite"].fn

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post("/api/stream/42/favorite").mock(return_value=httpx.Response(200))
        await fn(stream_id=42, favorite=True)
        assert route.called


@pytest.mark.asyncio
async def test_set_stream_favorite_false(client: PackmateClient) -> None:
    from packmate_mcp.tools.streams import register

    mcp = _mcp()
    register(mcp, client)
    fn = mcp._tool_manager._tools["set_stream_favorite"].fn

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post("/api/stream/42/unfavorite").mock(return_value=httpx.Response(200))
        await fn(stream_id=42, favorite=False)
        assert route.called


@pytest.mark.asyncio
async def test_get_stream_combines_metadata_and_content(client: PackmateClient) -> None:
    from packmate_mcp.tools.streams import register

    mcp = _mcp()
    register(mcp, client)
    fn = mcp._tool_manager._tools["get_stream"].fn

    with respx.mock(base_url="http://localhost:65000") as mock:
        # metadata fetch: list with starting_from=43, page_size=1 → returns stream 42
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
        # request must use starting_from=43, page_size=1
        body = list_route.calls[0].request.read().decode()
        assert '"startingFrom":43' in body
        assert '"pageSize":1' in body


@pytest.mark.asyncio
async def test_get_stream_not_found_when_id_mismatch(client: PackmateClient) -> None:
    from packmate_mcp.client import PackmateNotFoundError
    from packmate_mcp.tools.streams import register

    mcp = _mcp()
    register(mcp, client)
    fn = mcp._tool_manager._tools["get_stream"].fn

    with respx.mock(base_url="http://localhost:65000") as mock:
        # stream 42 was deleted; the list returns stream 41 instead
        mock.post("/api/stream/all").mock(
            return_value=httpx.Response(200, json=[_stream_dict(41)])
        )
        with pytest.raises(PackmateNotFoundError) as exc:
            await fn(stream_id=42)
        assert "42" in str(exc.value)


@pytest.mark.asyncio
async def test_get_stream_not_found_when_empty(client: PackmateClient) -> None:
    from packmate_mcp.client import PackmateNotFoundError
    from packmate_mcp.tools.streams import register

    mcp = _mcp()
    register(mcp, client)
    fn = mcp._tool_manager._tools["get_stream"].fn

    with respx.mock(base_url="http://localhost:65000") as mock:
        mock.post("/api/stream/all").mock(return_value=httpx.Response(200, json=[]))
        with pytest.raises(PackmateNotFoundError):
            await fn(stream_id=42)
```

- [ ] **Step 19.2: Verify failure**

```bash
uv run pytest tests/test_tools.py::test_list_streams_tool -v
```

Expected: `ModuleNotFoundError`.

- [ ] **Step 19.3: Implement stream tools**

Create `src/packmate_mcp/tools/streams.py`:

```python
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
        # Construct pagination. The `pattern` field in StreamPagination wants a full
        # Pattern object — fetch the matching one if pattern_id is set.
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
        # Metadata via the list endpoint: startingFrom=id+1, pageSize=1 returns
        # streams with id < id+1 in DESC order, so the first row is `id` itself (if it still exists).
        metadata = await client.list_streams(
            StreamPagination(starting_from=stream_id + 1, page_size=1),
        )
        if not metadata or metadata[0].id != stream_id:
            raise PackmateNotFoundError(f"Stream {stream_id} not found.")
        stream = metadata[0]

        # Packets (paged, but we fetch up to max_packets in one call).
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
```

- [ ] **Step 19.4: Run tests**

```bash
uv run pytest tests/test_tools.py -v
```

Expected: 13 passed.

- [ ] **Step 19.5: Commit**

```bash
git add src/packmate_mcp/tools/streams.py tests/test_tools.py
git commit -m "feat(tools): add list_streams + get_stream + set_stream_favorite"
```

---

## Task 20: Tools — packets

**Files:**
- Create: `src/packmate_mcp/tools/packets.py`
- Modify: `tests/test_tools.py`

- [ ] **Step 20.1: Write failing test**

Append to `tests/test_tools.py`:

```python
@pytest.mark.asyncio
async def test_get_packets_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.packets import register

    mcp = _mcp()
    register(mcp, client)
    fn = mcp._tool_manager._tools["get_packets"].fn

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
    fn = mcp._tool_manager._tools["get_packets"].fn

    with respx.mock(base_url="http://localhost:65000") as mock:
        route = mock.post("/api/packet/42").mock(
            return_value=httpx.Response(200, json=[])
        )
        await fn(stream_id=42, starting_from=100, page_size=20)
        body = route.calls[0].request.read().decode()
        assert '"startingFrom":100' in body
        assert '"pageSize":20' in body
```

- [ ] **Step 20.2: Verify failure**

```bash
uv run pytest tests/test_tools.py::test_get_packets_tool -v
```

Expected: `ModuleNotFoundError`.

- [ ] **Step 20.3: Implement packet tool**

Create `src/packmate_mcp/tools/packets.py`:

```python
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
```

- [ ] **Step 20.4: Run tests**

```bash
uv run pytest tests/test_tools.py -v
```

Expected: 15 passed.

- [ ] **Step 20.5: Commit**

```bash
git add src/packmate_mcp/tools/packets.py tests/test_tools.py
git commit -m "feat(tools): add get_packets paginated tool"
```

---

## Task 21: Tools — pcap

**Files:**
- Create: `src/packmate_mcp/tools/pcap.py`
- Modify: `tests/test_tools.py`

- [ ] **Step 21.1: Write failing tests**

Append to `tests/test_tools.py`:

```python
@pytest.mark.asyncio
async def test_pcap_status_tool(client: PackmateClient) -> None:
    from packmate_mcp.tools.pcap import register

    mcp = _mcp()
    register(mcp, client)
    fn = mcp._tool_manager._tools["pcap_status"].fn

    with respx.mock(base_url="http://localhost:65000") as mock:
        mock.get("/api/pcap/started").mock(return_value=httpx.Response(200, json=True))
        result = await fn()
        assert result == {"started": True}


@pytest.mark.asyncio
async def test_pcap_start_tool_when_starts(client: PackmateClient) -> None:
    from packmate_mcp.tools.pcap import register

    mcp = _mcp()
    register(mcp, client)
    fn = mcp._tool_manager._tools["pcap_start"].fn

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
    fn = mcp._tool_manager._tools["pcap_start"].fn

    with respx.mock(base_url="http://localhost:65000") as mock:
        mock.post("/api/pcap/start").mock(return_value=httpx.Response(200))
        mock.get("/api/pcap/started").mock(return_value=httpx.Response(200, json=False))
        result = await fn()
        assert result["started"] is False
        assert "FILE mode" in result["note"]
```

- [ ] **Step 21.2: Verify failure**

```bash
uv run pytest tests/test_tools.py::test_pcap_status_tool -v
```

Expected: `ModuleNotFoundError`.

- [ ] **Step 21.3: Implement pcap tool**

Create `src/packmate_mcp/tools/pcap.py`:

```python
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
```

- [ ] **Step 21.4: Run tests**

```bash
uv run pytest tests/test_tools.py -v
```

Expected: 18 passed.

- [ ] **Step 21.5: Commit**

```bash
git add src/packmate_mcp/tools/pcap.py tests/test_tools.py
git commit -m "feat(tools): add pcap_status + pcap_start with FILE-mode note"
```

---

## Task 22: Server wiring + entrypoint

**Files:**
- Modify: `src/packmate_mcp/tools/__init__.py` (add `register_all`)
- Create: `src/packmate_mcp/server.py`
- Create: `src/packmate_mcp/__main__.py`

- [ ] **Step 22.1: Add `register_all` to `tools/__init__.py`**

Replace the contents of `src/packmate_mcp/tools/__init__.py` with:

```python
"""Tool registration for MCP server.

Each submodule exposes a `register(mcp, client)` function that attaches its tools
to the FastMCP instance using the shared PackmateClient.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from packmate_mcp.client import PackmateClient
from packmate_mcp.tools import patterns, packets, pcap, services, streams


def register_all(mcp: FastMCP, client: PackmateClient) -> None:
    services.register(mcp, client)
    patterns.register(mcp, client)
    streams.register(mcp, client)
    packets.register(mcp, client)
    pcap.register(mcp, client)
```

- [ ] **Step 22.2: Implement `server.py`**

Create `src/packmate_mcp/server.py`:

```python
"""FastMCP server wiring.

Builds the FastMCP instance, the PackmateClient, registers all tools, and runs
over stdio.
"""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager
from typing import AsyncIterator

from mcp.server.fastmcp import FastMCP

from packmate_mcp.client import PackmateClient
from packmate_mcp.config import PackmateSettings
from packmate_mcp.tools import register_all

log = logging.getLogger(__name__)


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        stream=sys.stderr,
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def build_server() -> FastMCP:
    """Construct a FastMCP server with all tools registered.

    Settings are loaded from env at call time. The PackmateClient is opened in a
    lifespan context manager so it shares the FastMCP lifecycle.
    """
    settings = PackmateSettings()
    _configure_logging(settings.log_level)
    log.info("Connecting to Packmate at %s", settings.base_url)

    @asynccontextmanager
    async def lifespan(_server: FastMCP) -> AsyncIterator[None]:
        async with PackmateClient(settings) as client:
            register_all(mcp, client)
            yield

    mcp = FastMCP("packmate", lifespan=lifespan)
    return mcp


def run() -> None:
    """Entrypoint: build the server and run it over stdio."""
    server = build_server()
    server.run(transport="stdio")
```

- [ ] **Step 22.3: Implement `__main__.py`**

Create `src/packmate_mcp/__main__.py`:

```python
"""CLI entrypoint: `packmate-mcp` and `python -m packmate_mcp`."""

from __future__ import annotations

import sys

from packmate_mcp.server import run


def main() -> None:
    try:
        run()
    except Exception as e:  # noqa: BLE001 — top-level fence
        print(f"packmate-mcp failed to start: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
```

- [ ] **Step 22.4: Manually verify the entrypoint at least imports**

```bash
PACKMATE_MCP_LOGIN=u PACKMATE_MCP_PASSWORD=p uv run python -c "from packmate_mcp.server import build_server; print(build_server())"
```

Expected: prints `FastMCP("packmate", ...)` representation without crashing.

- [ ] **Step 22.5: Verify the installed entrypoint resolves**

```bash
PACKMATE_MCP_LOGIN=u PACKMATE_MCP_PASSWORD=p uv run packmate-mcp --help 2>&1 | head -20 || true
```

Expected: starts the server and waits for stdio input. Send `Ctrl-C` after a second to stop. (`--help` is not a FastMCP arg; the goal here is to confirm the entrypoint exists.)

- [ ] **Step 22.6: Run the full test suite**

```bash
uv run pytest -v
```

Expected: all tests pass (≈45+).

- [ ] **Step 22.7: Commit**

```bash
git add src/packmate_mcp/server.py src/packmate_mcp/__main__.py src/packmate_mcp/tools/__init__.py
git commit -m "feat(server): wire FastMCP with lifespan-managed PackmateClient"
```

---

## Task 23: README, .env.example, CHANGELOG

**Files:**
- Rewrite: `README.md`
- Create: `.env.example`
- Create: `CHANGELOG.md`

- [ ] **Step 23.1: Rewrite `README.md`**

Replace contents with:

````markdown
# packmate-mcp

MCP server that exposes [Packmate](https://gitlab.com/packmate/Packmate) — a CTF network traffic analyzer — to LLM tooling like Claude Desktop or Claude Code.

## Features

- 16 tools across services, patterns, streams, packets, and pcap-file lifecycle.
- Packet content formatting tuned for LLM consumption: `transcript` (auto text/hex with `client→server` markers), `text`, `hex`, `python_bytes`, `base64`.
- Three-layer trimming (per-packet, total budget, packet count) to keep responses inside the LLM context window.
- Pure async `httpx` client over Packmate's HTTP API + Basic Auth.
- stdio transport — drop into Claude Desktop or Claude Code as a subprocess.

## Install

```bash
uvx packmate-mcp        # ephemeral, recommended
# or
pip install packmate-mcp
```

## Configure

All settings are env vars with the `PACKMATE_MCP_` prefix:

| Env var | Default | Description |
|---|---|---|
| `PACKMATE_MCP_BASE_URL` | `http://localhost:65000` | Packmate base URL |
| `PACKMATE_MCP_LOGIN` | (required) | Basic auth login |
| `PACKMATE_MCP_PASSWORD` | (required) | Basic auth password |
| `PACKMATE_MCP_TIMEOUT_SECONDS` | `30` | HTTP request timeout |
| `PACKMATE_MCP_LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` |

See [`.env.example`](.env.example) for a starter template.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%AppData%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "packmate": {
      "command": "uvx",
      "args": ["packmate-mcp"],
      "env": {
        "PACKMATE_MCP_BASE_URL": "http://localhost:65000",
        "PACKMATE_MCP_LOGIN": "BinaryBears",
        "PACKMATE_MCP_PASSWORD": "..."
      }
    }
  }
}
```

Restart Claude Desktop fully (`Cmd+Q` / tray → Quit), then look for the connector under the `+` menu.

### Claude Code

```bash
claude mcp add packmate uvx packmate-mcp \
  --env PACKMATE_MCP_LOGIN=BinaryBears \
  --env PACKMATE_MCP_PASSWORD=...
```

## Tools

See [the design spec](docs/superpowers/specs/2026-05-13-packmate-mcp-design.md) for the full list. Highlights:

- **`get_stream(stream_id, content_format='transcript')`** — fetch a stream with packets pre-rendered. Most common entrypoint.
- **`create_pattern + pattern_lookback + list_streams(pattern_id=…)`** — the native Packmate workflow for content search.
- **`set_stream_favorite(stream_id, favorite=True/False)`** — pin interesting streams.
- **`pcap_status` / `pcap_start`** — kick off pcap-file processing in FILE mode.

## Development

```bash
git clone https://github.com/umbra2728/packmate-mcp
cd packmate-mcp
uv sync --dev
uv run pytest
uv run ruff check src tests
uv run mypy src
```

Manual smoke test against a real Packmate instance:

```bash
# in the Packmate repo
docker compose up -d
# back here
PACKMATE_MCP_LOGIN=BinaryBears PACKMATE_MCP_PASSWORD=123456 \
  uv run mcp dev src/packmate_mcp/server.py
```

This opens the MCP Inspector and lets you exercise each tool.

## Releasing

This package ships to PyPI via Trusted Publishing. The workflow runs on any `v*.*.*` tag.

1. Bump `version` in `pyproject.toml`.
2. Add a `## [X.Y.Z] - YYYY-MM-DD` section to `CHANGELOG.md`.
3. Commit, tag, push:

```bash
git commit -am "Release vX.Y.Z"
git tag vX.Y.Z
git push --tags
```

One-time setup (not in repo state):

- On PyPI → Account settings → Add a pending publisher with repo `umbra2728/packmate-mcp`, workflow `release.yml`, environment `pypi`.
- On GitHub → repo → Settings → Environments → create `pypi`.

## License

MIT.
````

- [ ] **Step 23.2: Create `.env.example`**

```bash
cat > .env.example <<'EOF'
# Copy to .env and fill in real values. Never commit .env.
PACKMATE_MCP_BASE_URL=http://localhost:65000
PACKMATE_MCP_LOGIN=BinaryBears
PACKMATE_MCP_PASSWORD=change-me
PACKMATE_MCP_TIMEOUT_SECONDS=30
PACKMATE_MCP_LOG_LEVEL=INFO
EOF
```

- [ ] **Step 23.3: Create `CHANGELOG.md`**

```bash
cat > CHANGELOG.md <<'EOF'
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release: 16 MCP tools wrapping Packmate's REST API.
- Packet content formatting: transcript / text / hex / python_bytes / base64 with three-layer trimming.
- PyPI Trusted Publishing release workflow.
EOF
```

- [ ] **Step 23.4: Commit**

```bash
git add README.md .env.example CHANGELOG.md
git commit -m "docs: add README, .env.example, CHANGELOG"
```

---

## Task 24: CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 24.1: Create CI workflow**

Run:

```bash
mkdir -p .github/workflows
```

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.10", "3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v3
        with:
          enable-cache: true

      - name: Set up Python
        run: uv python install ${{ matrix.python-version }}

      - name: Install deps
        run: uv sync --dev

      - name: Lint
        run: uv run ruff check src tests

      - name: Type-check
        run: uv run mypy src

      - name: Test
        run: uv run pytest --cov=src/packmate_mcp --cov-report=term-missing
```

- [ ] **Step 24.2: Verify the workflow file parses locally**

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"
```

Expected: no output (valid YAML).

- [ ] **Step 24.3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add lint + type-check + test matrix"
```

---

## Task 25: Release workflow (PyPI Trusted Publishing)

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 25.1: Create release workflow**

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags: ["v*.*.*"]

jobs:
  release:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write
      contents: write
    steps:
      - uses: actions/checkout@v4

      - name: Install uv
        uses: astral-sh/setup-uv@v3
        with:
          enable-cache: true

      - name: Set up Python
        run: uv python install 3.12

      - name: Install deps
        run: uv sync --dev

      - name: Test
        run: uv run pytest

      - name: Build
        run: uv build

      - name: Publish to PyPI (Trusted Publishing)
        uses: pypa/gh-action-pypi-publish@release/v1

      - name: GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          files: dist/*
```

- [ ] **Step 25.2: Verify the workflow file parses**

```bash
python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"
```

Expected: no output.

- [ ] **Step 25.3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add Trusted Publishing release workflow"
```

- [ ] **Step 25.4: Final verification — full test suite + lint**

```bash
uv run pytest -v
uv run ruff check src tests
uv run mypy src
```

Expected: pytest all green, ruff clean, mypy clean. If mypy complains about `mcp.server.fastmcp` internals (`_tool_manager` is private), add a per-line `# type: ignore[attr-defined]` in the test file as needed — but don't broaden mypy ignores.

---

## Done

By end of Task 25 the repo contains:

- A working MCP server (`uvx packmate-mcp`) covering all 16 tools.
- ~45+ unit tests against mocked httpx with respx.
- CI matrix across Python 3.10–3.13.
- Release pipeline on `v*.*.*` tags.

To cut `v0.1.0`, follow the **Releasing** section in the README.
