from __future__ import annotations

import pytest

from wapy.creds import DeviceCredentials, generate_credentials
from wapy.protocol.prekeys import (
    PreKeyError,
    build_count_query,
    build_upload_node,
    pack_key_pair,
    parse_count,
    prekey_node,
    prekeys_to_upload,
    signed_prekey_node,
    unpack_public,
)
from wapy.protocol.stream import child
from wapy.protocol.wabinary import Node, decode_node, encode_node


@pytest.fixture
def credentials() -> DeviceCredentials:
    return generate_credentials()


def content_of(node: Node, tag: str) -> bytes:
    found = child(node, tag)
    assert found is not None and isinstance(found.content, bytes)
    return found.content


def test_prekey_node_uses_three_byte_id(credentials: DeviceCredentials) -> None:
    node = prekey_node(7, b"\x01" * 32)
    assert node.tag == "key"
    assert content_of(node, "id") == b"\x00\x00\x07"
    assert content_of(node, "value") == b"\x01" * 32


def test_prekey_node_rejects_wrong_key_length() -> None:
    with pytest.raises(PreKeyError):
        prekey_node(1, b"\x01" * 31)


def test_signed_prekey_node_structure(credentials: DeviceCredentials) -> None:
    node = signed_prekey_node(credentials.signed_pre_key)
    assert node.tag == "skey"
    assert content_of(node, "id") == b"\x00\x00\x01"
    assert content_of(node, "value") == credentials.signed_pre_key.key_pair.public
    assert content_of(node, "signature") == credentials.signed_pre_key.signature


def test_upload_node_matches_wire_layout(credentials: DeviceCredentials) -> None:
    prekeys = [(1, b"\x02" * 32), (2, b"\x03" * 32)]
    node = build_upload_node(credentials, prekeys, "abc123")

    assert node.tag == "iq"
    assert node.attrs["xmlns"] == "encrypt"
    assert node.attrs["type"] == "set"
    assert node.attrs["to"] == "s.whatsapp.net"
    assert node.attrs["id"] == "abc123"

    assert content_of(node, "registration") == credentials.registration_id.to_bytes(4, "big")
    assert content_of(node, "type") == b"\x05"
    assert content_of(node, "identity") == credentials.identity_public

    keys = child(node, "list")
    assert keys is not None and isinstance(keys.content, list)
    assert [item.tag for item in keys.content] == ["key", "key"]
    assert content_of(keys.content[1], "id") == b"\x00\x00\x02"

    assert child(node, "skey") is not None


def test_upload_node_requires_prekeys(credentials: DeviceCredentials) -> None:
    with pytest.raises(PreKeyError):
        build_upload_node(credentials, [], "id")


def test_upload_node_survives_encoding_roundtrip(credentials: DeviceCredentials) -> None:
    node = build_upload_node(credentials, [(5, b"\x04" * 32)], "xyz")
    assert decode_node(encode_node(node)) == node


def test_count_query_and_parsing() -> None:
    query = build_count_query("q1")
    assert query.tag == "iq"
    assert query.attrs["type"] == "get"
    assert isinstance(query.content, list) and query.content[0].tag == "count"

    response = Node(
        tag="iq", attrs={"id": "q1"}, content=[Node(tag="count", attrs={}, content=b"812")]
    )
    assert parse_count(response) == 812


def test_parse_count_rejects_junk() -> None:
    with pytest.raises(PreKeyError):
        parse_count(Node(tag="iq", content=[Node(tag="count", attrs={}, content=b"many")]))
    with pytest.raises(PreKeyError):
        parse_count(Node(tag="iq"))


def test_key_pair_packing() -> None:
    packed = pack_key_pair(b"\x01" * 32, b"\x02" * 32)
    assert len(packed) == 64
    assert unpack_public(packed) == b"\x02" * 32
    with pytest.raises(PreKeyError):
        unpack_public(b"\x00" * 63)


def test_prekeys_to_upload_respects_limit() -> None:
    pending = [(index, bytes([index]) * 32) for index in range(10)]
    assert len(prekeys_to_upload(pending, limit=4)) == 4
