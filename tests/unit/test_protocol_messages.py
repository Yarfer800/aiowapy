from __future__ import annotations

import pytest

from wapy.pb import parse_fields
from wapy.protocol.messages import (
    EncryptedDevice,
    MessageError,
    build_message_node,
    decode_from_transport,
    decode_text,
    enc_node,
    encode_for_transport,
    encode_text,
    parse_incoming,
)
from wapy.protocol.wabinary import Node, decode_node, encode_node


def test_short_text_uses_conversation_field() -> None:
    payload = encode_text("hello")
    fields = parse_fields(payload)
    assert 1 in fields
    assert decode_text(payload) == "hello"


def test_long_text_uses_extended_text() -> None:
    text = "x" * 400
    payload = encode_text(text)
    assert decode_text(payload) == text


def test_unicode_text_roundtrip() -> None:
    assert decode_text(encode_text("привет 🌍")) == "привет 🌍"


def test_empty_text_is_rejected() -> None:
    with pytest.raises(MessageError):
        encode_text("")


def test_decode_text_of_non_text_payload() -> None:
    other = bytes.fromhex("120610041a020102")  # some other field, no text
    assert decode_text(other) is None


def test_enc_node_marks_prekey_messages() -> None:
    device = EncryptedDevice(device_jid="1:2@s.whatsapp.net", ciphertext=b"cipher")
    node = enc_node(device)
    assert node.attrs == {"v": "2", "type": "msg", "jid": "1:2@s.whatsapp.net"}
    assert node.content == b"cipher"
    assert enc_node(EncryptedDevice("x", b"c", prekey=True)).attrs["type"] == "pkmsg"


def test_build_message_node_structure() -> None:
    devices = [
        EncryptedDevice("1:2@s.whatsapp.net", b"a"),
        EncryptedDevice("1:3@s.whatsapp.net", b"b", prekey=True),
    ]
    node = build_message_node("1@s.whatsapp.net", "MSGID", devices)
    assert node.attrs == {"id": "MSGID", "to": "1@s.whatsapp.net", "type": "text"}
    assert isinstance(node.content, list) and len(node.content) == 2
    assert [item.attrs["type"] for item in node.content] == ["msg", "pkmsg"]


def test_build_message_node_requires_devices() -> None:
    with pytest.raises(MessageError):
        build_message_node("1@s.whatsapp.net", "id", [])


def test_message_node_survives_encoding() -> None:
    node = build_message_node(
        "1@s.whatsapp.net", "id", [EncryptedDevice("1:2@s.whatsapp.net", b"x")]
    )
    assert decode_node(encode_node(node)) == node


def test_parse_incoming_message() -> None:
    node = build_message_node(
        "1@s.whatsapp.net",
        "id",
        [
            EncryptedDevice("1:2@s.whatsapp.net", b"x"),
            EncryptedDevice("1:3@s.whatsapp.net", b"y", prekey=True),
        ],
    )
    node.attrs["from"] = "1@s.whatsapp.net"
    incoming = parse_incoming(node)
    assert incoming.message_id == "id"
    assert incoming.from_jid == "1@s.whatsapp.net"
    assert [device.prekey for device in incoming.devices] == [False, True]


def test_parse_incoming_requires_ids() -> None:
    with pytest.raises(MessageError):
        parse_incoming(Node(tag="message", attrs={}))


def test_transport_base64_helpers() -> None:
    payload = b"\x00\x01\x02"
    assert decode_from_transport(encode_for_transport(payload)) == payload
    with pytest.raises(MessageError):
        decode_from_transport("not base64!!")
