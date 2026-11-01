from __future__ import annotations

import base64
import json
import zlib
from pathlib import Path
from typing import Any

import pytest

from aiowapy.protocol.wabinary.encode import EncodeError, encode_node
from aiowapy.protocol.wabinary.node import Node

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
def test_encode_matches_reference_bytes(case: dict[str, Any]) -> None:
    encoded = encode_node(load_node(case["node"]))
    assert encoded.hex() == case["hex"]


def test_encode_empty_attrs_and_no_content() -> None:
    assert encode_node(Node(tag="presence")).hex() == "00f8011f"


def test_encode_empty_string_attribute() -> None:
    assert encode_node(Node(tag="iq", attrs={"id": ""})).hex() == "00f8031908fc00"


def test_encode_rejects_empty_tag() -> None:
    with pytest.raises(EncodeError):
        encode_node(Node(tag=""))


def test_encode_rejects_unknown_content_type() -> None:
    with pytest.raises(EncodeError):
        encode_node(Node(tag="iq", attrs={}, content=123))  # type: ignore[arg-type]


def test_encode_compressed_frame_is_decodable_by_zlib() -> None:
    encoded = encode_node(Node(tag="presence", attrs={"type": "available"}), compress=True)
    assert encoded[0] == 0x02
    assert zlib.decompress(encoded[1:]) == bytes.fromhex("f8031f0488")
