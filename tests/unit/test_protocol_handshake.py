from __future__ import annotations

import pytest

from wapy.pb import ProtobufError, parse_fields
from wapy.protocol.handshake import (
    ClientFinish,
    ClientHello,
    HandshakeError,
    HandshakeMessage,
    ServerHello,
    decode,
    encode,
)


def test_client_hello_encoding_matches_captured_bytes() -> None:
    ephemeral = bytes.fromhex("9c9dbd2a029df316e92c1ecaa43f9fc600000000000000000000000000000000")
    encoded = encode(HandshakeMessage(client_hello=ClientHello(ephemeral=ephemeral)))
    assert encoded.hex() == "12220a20" + ephemeral.hex()
    assert len(encoded) == 36


def test_client_hello_roundtrip() -> None:
    message = HandshakeMessage(client_hello=ClientHello(ephemeral=b"\x01" * 32))
    decoded = decode(encode(message))
    assert decoded.client_hello is not None
    assert decoded.client_hello.ephemeral == b"\x01" * 32
    assert decoded.client_hello.static == b""
    assert decoded.client_hello.payload == b""


def test_server_hello_roundtrip_keeps_all_fields() -> None:
    message = HandshakeMessage(
        server_hello=ServerHello(ephemeral=b"\x02" * 32, static=b"\x03" * 48, payload=b"\x04" * 257)
    )
    decoded = decode(encode(message))
    assert decoded.server_hello is not None
    assert decoded.server_hello.ephemeral == b"\x02" * 32
    assert decoded.server_hello.static == b"\x03" * 48
    assert decoded.server_hello.payload == b"\x04" * 257


def test_client_finish_roundtrip() -> None:
    message = HandshakeMessage(
        client_finish=ClientFinish(static=b"\x05" * 48, payload=b"\x06" * 305)
    )
    decoded = decode(encode(message))
    assert decoded.client_finish is not None
    assert decoded.client_finish.static == b"\x05" * 48
    assert decoded.client_finish.payload == b"\x06" * 305


def test_decode_rejects_unknown_message() -> None:
    with pytest.raises(HandshakeError):
        decode(b"\x0a\x00")


def test_encode_requires_a_field() -> None:
    with pytest.raises(HandshakeError):
        encode(HandshakeMessage())


def test_unknown_fields_are_ignored() -> None:
    encoded = encode(HandshakeMessage(client_hello=ClientHello(ephemeral=b"\x07" * 32)))
    extended = encoded + b"\x50\x2a"  # field 10, varint
    decoded = decode(extended)
    assert decoded.client_hello is not None
    assert decoded.client_hello.ephemeral == b"\x07" * 32


def test_truncated_message_is_rejected() -> None:
    with pytest.raises(ProtobufError):
        parse_fields(b"\x12\x40\x00")
