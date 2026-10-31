"""Inspect WebSocket frames of a mitmproxy stream file.

Reads the WhatsApp envelope without touching the encrypted contents:

    [ "WA" magic? ] [ 3-byte big-endian length ] [ payload ]

For the very first client frame the payload is a protobuf HandshakeMessage,
which this tool decodes into a field tree. Everything after the handshake is
Noise ciphertext and cannot be decoded without session keys.

Usage:
    /usr/bin/python3 tools/capture/frames.py ~/captures/wa-flows.mitm
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

MAGIC = b"WA"


def read_varint(data: bytes, position: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if position >= len(data):
            raise ValueError("truncated varint")
        byte = data[position]
        position += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, position
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def decode_message(data: bytes) -> list[tuple[int, str, object]]:
    """Best-effort protobuf field decoding for display purposes."""
    fields: list[tuple[int, str, object]] = []
    position = 0
    while position < len(data):
        tag, position = read_varint(data, position)
        number, wire = tag >> 3, tag & 0x07
        if wire == 0:
            value, position = read_varint(data, position)
            fields.append((number, "varint", value))
        elif wire == 2:
            length, position = read_varint(data, position)
            blob = data[position : position + length]
            position += length
            try:
                nested = decode_message(blob)
            except ValueError:
                nested = []
            if nested and _looks_like_message(blob):
                fields.append((number, "message", nested))
            else:
                fields.append((number, "bytes", blob))
        elif wire == 5:
            fields.append((number, "fixed32", int.from_bytes(data[position : position + 4], "big")))
            position += 4
        elif wire == 1:
            fields.append((number, "fixed64", int.from_bytes(data[position : position + 8], "big")))
            position += 8
        else:
            raise ValueError(f"unsupported wire type {wire}")
    return fields


def _looks_like_message(blob: bytes) -> bool:
    try:
        decode_message(blob)
    except ValueError:
        return False
    return True


def render(fields: list[tuple[int, str, object]], indent: int = 0) -> list[str]:
    lines: list[str] = []
    pad = "  " * indent
    for number, kind, value in fields:
        if kind == "message":
            lines.append(f"{pad}field {number} (message):")
            lines.extend(render(value, indent + 1))  # type: ignore[arg-type]
        elif kind == "bytes":
            raw = value  # type: ignore[assignment]
            preview = raw[:16].hex()
            ellipsis = "..." if len(raw) > 16 else ""
            lines.append(f"{pad}field {number} (bytes, {len(raw)}B): {preview}{ellipsis}")
        else:
            lines.append(f"{pad}field {number} ({kind}): {value}")
    return lines


def split_envelope(payload: bytes) -> tuple[bool, int, int, bytes]:
    """Return (has_magic, declared_length, header_size, body)."""
    offset = 0
    has_magic = payload.startswith(MAGIC)
    if has_magic:
        offset = 2
        offset = 4  # magic plus two protocol bytes
    declared = int.from_bytes(payload[offset : offset + 3], "big")
    body = payload[offset + 3 :]
    return has_magic, declared, offset + 3, body


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args()

    try:
        from mitmproxy import io
    except ImportError:
        print("error: run this with the interpreter that has mitmproxy installed", file=sys.stderr)
        return 1

    with args.path.open("rb") as handle:
        flows = [
            flow for flow in io.FlowReader(handle).stream() if getattr(flow, "websocket", None)
        ]

    for flow in flows:
        print(f"\n=== {flow.request.pretty_url} (frames={len(flow.websocket.messages)})")
        for index, message in enumerate(flow.websocket.messages):
            payload = message.content
            direction = "C->S" if message.from_client else "S->C"
            has_magic, declared, header, body = split_envelope(payload)
            consistent = len(body) == declared
            print(
                f"  [{index}] {direction} {len(payload):5d}B "
                f"magic={'WA' if has_magic else '-':2s} "
                f"len={declared:5d} body={len(body):5d} "
                f"{'OK' if consistent else 'MISMATCH'}"
            )
            if has_magic:
                print(f"       header bytes: {payload[:header].hex()}")
                try:
                    for line in render(decode_message(body)):
                        print(f"       {line}")
                except ValueError as exc:
                    print(f"       protobuf decode failed: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
