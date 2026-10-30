from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from wapy.protocol.wabinary.decode import DecodeError, decode_node
from wapy.protocol.wabinary.encode import encode_node
from wapy.protocol.wabinary.node import Node

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "wabinary" / "nodes.json"


def load_node(payload: dict[str, Any]) -> Node:
    content = payload.get("content")
    if isinstance(content, list):
        decoded: Any = [load_node(item) for item in content]
    elif isinstance(content, dict) and "$binary" in content:
        decoded = base64.b64decode(content["$binary"])
    else:
        decoded = content
    return Node(tag=payload["tag"], attrs=dict(payload.get("attrs", {})), content=decoded)


def fixtures() -> list[dict[str, Any]]:
    loaded: list[dict[str, Any]] = json.loads(FIXTURES.read_text(encoding="utf-8"))
    return loaded


@pytest.mark.parametrize("case", fixtures(), ids=lambda case: case["name"])
def test_decode_reference_frames(case: dict[str, Any]) -> None:
    """Наш декодер обязан воспроизводить результат эталонного декодера."""
    decoded = decode_node(bytes.fromhex(case["hex"]))
    assert decoded == load_node(case["decoded"])


def test_decode_compressed_frame_roundtrips() -> None:
    node = Node(tag="iq", attrs={"id": "42", "type": "get"})
    assert decode_node(encode_node(node, compress=True)) == node


def test_decode_strips_single_flag_byte() -> None:
    assert decode_node(bytes.fromhex("00f8011f")) == Node(tag="presence")


def test_decoded_binary_is_bytes() -> None:
    decoded = decode_node(bytes.fromhex("00f8061311faff06491234567890030438fc0568656c6c6f"))
    assert decoded.content == b"hello"


def test_decode_rejects_empty_input() -> None:
    with pytest.raises(DecodeError):
        decode_node(b"")


def test_decode_rejects_truncated_frame() -> None:
    with pytest.raises(DecodeError):
        decode_node(bytes.fromhex("00f80819085504291103f801f801"))


def test_decode_rejects_invalid_string_tag() -> None:
    with pytest.raises(DecodeError):
        decode_node(bytes.fromhex("00f803f004"))


def test_decode_rejects_unknown_dictionary() -> None:
    with pytest.raises(DecodeError):
        decode_node(bytes.fromhex("00f803ec01"))


def test_decode_rejects_broken_zlib() -> None:
    with pytest.raises(DecodeError):
        decode_node(b"\x02not-zlib-data")
