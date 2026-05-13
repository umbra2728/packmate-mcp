"""Pure functions for rendering packet content for an LLM.

All formatting is deterministic, side-effect free, and operates on
already-fetched Packet objects.
"""

from __future__ import annotations

import base64 as _base64
import datetime as _dt
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

    Layout: 8-digit offset, 16 hex pairs, ASCII gutter with '.' for non-printable bytes.
    """
    rows: list[str] = []
    for offset in range(0, len(data), _HEXDUMP_BYTES_PER_ROW):
        chunk = data[offset : offset + _HEXDUMP_BYTES_PER_ROW]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(_HEXDUMP_BYTES_PER_ROW * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        rows.append(f"{offset:08x}: {hex_part}  {ascii_part}")
    return "\n".join(rows)


def _python_bytes_literal(data: bytes) -> str:
    """Render bytes as a Python bytes literal using \\xNN escapes for every byte."""
    return "b'" + "".join(f"\\x{b:02x}" for b in data) + "'"


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
    flags: list[str] = []
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
    """Render a sequence of packets as a single string in the requested mode."""
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
