from __future__ import annotations

import pytest

from aiowapy.pb import parse_fields
from aiowapy.protocol.messages import (
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
from aiowapy.protocol.wabinary import Node, decode_node, encode_node


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
    assert isinstance(node.content, list) and len(node.content) == 1
    participants = node.content[0]
    assert participants.tag == "participants"
    assert [item.attrs["type"] for item in participants.content] == ["msg", "pkmsg"]  # type: ignore[union-attr]


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


def test_message_node_carries_device_identity_only_when_asked() -> None:
    devices = [EncryptedDevice("1:2@s.whatsapp.net", b"x", prekey=True)]
    node = build_message_node("1@s.whatsapp.net", "id", devices, device_identity=b"identity")
    assert [item.tag for item in node.content] == ["participants", "device-identity"]  # type: ignore[union-attr]

    plain = build_message_node("1@s.whatsapp.net", "id", devices)
    assert [item.tag for item in plain.content] == ["participants"]  # type: ignore[union-attr]


def test_media_type_lands_on_the_enc_nodes() -> None:
    devices = [EncryptedDevice("1:2@s.whatsapp.net", b"x")]
    node = build_message_node("1@s.whatsapp.net", "id", devices, media_type="image")
    participants = node.content[0]  # type: ignore[index]
    assert participants.content[0].attrs["mediatype"] == "image"


def test_incoming_reads_enc_both_inline_and_in_participants() -> None:
    from aiowapy.protocol.messages import parse_incoming

    inline = Node(
        tag="message",
        attrs={"id": "1", "from": "2@s.whatsapp.net"},
        content=[Node(tag="enc", attrs={"type": "msg", "jid": "2:1@s.whatsapp.net"}, content=b"x")],
    )
    nested = Node(
        tag="message",
        attrs={"id": "2", "from": "2@s.whatsapp.net"},
        content=[
            Node(
                tag="participants",
                content=[
                    Node(
                        tag="enc",
                        attrs={"type": "msg", "jid": "2:1@s.whatsapp.net"},
                        content=b"y",
                    )
                ],
            )
        ],
    )
    assert parse_incoming(inline).devices[0].ciphertext == b"x"
    assert parse_incoming(nested).devices[0].ciphertext == b"y"


def test_device_sent_message_wraps_the_payload() -> None:
    from aiowapy.pb import parse_fields
    from aiowapy.protocol.messages import encode_device_sent

    wrapped = encode_device_sent("1@s.whatsapp.net", b"\x0a\x02hi")
    outer = parse_fields(wrapped)
    assert 31 in outer
    inner = parse_fields(outer[31][0])  # type: ignore[index]
    assert inner[1][0] == b"1@s.whatsapp.net"
    assert inner[2][0] == b"\x0a\x02hi"
