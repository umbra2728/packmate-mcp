"""Tests for packet content formatting."""

from __future__ import annotations

import base64

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
            "content": base64.b64encode(content).decode(),
        }
    )


# ---------- hex ----------


def test_hex_canonical_layout() -> None:
    p = _packet(b"Hello, world!\n\x00\xff")
    out = format_content([p], ContentFormat.HEX)
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
    assert "...A" in out


# ---------- python_bytes ----------


def test_python_bytes_basic() -> None:
    p = _packet(b"GET")
    out = format_content([p], ContentFormat.PYTHON_BYTES)
    assert out == "b'\\x47\\x45\\x54'"


def test_python_bytes_special_chars() -> None:
    p = _packet(b"\x00\n\\'\"a")
    out = format_content([p], ContentFormat.PYTHON_BYTES)
    assert out == "b'\\x00\\x0a\\x5c\\x27\\x22\\x61'"


def test_python_bytes_multiple_packets_separated() -> None:
    out = format_content([_packet(b"A"), _packet(b"B")], ContentFormat.PYTHON_BYTES)
    assert out == "b'\\x41'\nb'\\x42'"


# ---------- base64 ----------


def test_base64_round_trip() -> None:
    p = _packet(b"\x01\x02\x03\xff")
    out = format_content([p], ContentFormat.BASE64)
    assert base64.b64decode(out) == b"\x01\x02\x03\xff"


def test_base64_multiple_packets_newline_separated() -> None:
    p1 = _packet(b"A")
    p2 = _packet(b"B")
    out = format_content([p1, p2], ContentFormat.BASE64)
    lines = out.split("\n")
    assert len(lines) == 2
    assert base64.b64decode(lines[0]) == b"A"
    assert base64.b64decode(lines[1]) == b"B"


# ---------- text ----------


def test_text_utf8() -> None:
    p = _packet("héllo".encode("utf-8"))
    out = format_content([p], ContentFormat.TEXT)
    assert out == "héllo"


def test_text_invalid_utf8_backslashreplace() -> None:
    p = _packet(b"\xff\xfe\x00A")
    out = format_content([p], ContentFormat.TEXT)
    assert "\\xff" in out
    assert "A" in out


def test_text_multiple_packets_joined_with_double_newline() -> None:
    out = format_content([_packet(b"hello"), _packet(b"world")], ContentFormat.TEXT)
    assert out == "hello\n\nworld"


# ---------- transcript ----------


def test_transcript_text_packet_uses_text_body() -> None:
    p = _packet(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", incoming=True)
    p.id = 142
    out = format_content([p], ContentFormat.TRANSCRIPT)
    assert "Packet #142" in out
    assert "client→server" in out
    assert "(27 bytes)" in out
    assert "GET / HTTP/1.1" in out


def test_transcript_binary_packet_uses_hexdump_body() -> None:
    p = _packet(b"\x17\x03\x03\x00\x1b\x00", incoming=False)
    out = format_content([p], ContentFormat.TRANSCRIPT)
    assert "server→client" in out
    assert "binary" in out
    assert "00000000:" in out
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
    assert "[" not in out.split("\n")[0]


def test_transcript_timestamp_in_header() -> None:
    p = _packet(b"x", ts=1_700_000_000_123)
    out = format_content([p], ContentFormat.TRANSCRIPT)
    assert "22:13:20.123" in out


# ---------- trimming ----------


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
    packets = [_packet(b"x") for _ in range(5)]
    for i, p in enumerate(packets):
        p.id = i
    out = format_content(packets, ContentFormat.TRANSCRIPT, max_packets=2)
    assert "Packet #0" in out
    assert "Packet #1" in out
    assert "Packet #2 (skipped: max_packets reached)" in out
    assert "Packet #3" not in out


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
    assert "Packet #2 (skipped: total budget exhausted)" in out


def test_truncation_marker_visible_when_binary() -> None:
    p = _packet(b"\xff" * 50)
    out = format_content([p], ContentFormat.TRANSCRIPT, max_bytes_per_packet=4)
    assert "[truncated: 46 more bytes]" in out
