"""The protobuf messages exchanged during the Noise handshake.

Field numbers are fixed by the protocol:
HandshakeMessage  - 2 clientHello, 3 serverHello, 4 clientFinish
ClientHello       - 1 ephemeral, 2 static, 3 payload
ServerHello       - 1 ephemeral, 2 static, 3 payload
ClientFinish      - 1 static, 2 payload
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aiowapy.errors import WapyError
from aiowapy.pb import bytes_field, first_bytes, message_field, parse_fields


class HandshakeError(WapyError):
    """A handshake message is malformed or missing required fields."""


@dataclass(slots=True)
class ClientHello:
    ephemeral: bytes = b""
    static: bytes = b""
    payload: bytes = b""


@dataclass(slots=True)
class ServerHello:
    ephemeral: bytes = b""
    static: bytes = b""
    payload: bytes = b""


@dataclass(slots=True)
class ClientFinish:
    static: bytes = b""
    payload: bytes = b""


@dataclass(slots=True)
class HandshakeMessage:
    client_hello: ClientHello | None = None
    server_hello: ServerHello | None = None
    client_finish: ClientFinish | None = field(default=None)


def _encode_client_hello(message: ClientHello) -> bytes:
    body = b"".join(
        (
            bytes_field(1, message.ephemeral),
            bytes_field(2, message.static),
            bytes_field(3, message.payload),
        )
    )
    return message_field(2, body)


def _encode_server_hello(message: ServerHello) -> bytes:
    body = b"".join(
        (
            bytes_field(1, message.ephemeral),
            bytes_field(2, message.static),
            bytes_field(3, message.payload),
        )
    )
    return message_field(3, body)


def _encode_client_finish(message: ClientFinish) -> bytes:
    body = b"".join(
        (
            bytes_field(1, message.static),
            bytes_field(2, message.payload),
        )
    )
    return message_field(4, body)


def encode(message: HandshakeMessage) -> bytes:
    if message.client_hello is not None:
        return _encode_client_hello(message.client_hello)
    if message.server_hello is not None:
        return _encode_server_hello(message.server_hello)
    if message.client_finish is not None:
        return _encode_client_finish(message.client_finish)
    raise HandshakeError("handshake message carries no known field")


def decode(data: bytes) -> HandshakeMessage:
    fields = parse_fields(data)
    if 2 in fields:
        inner = parse_fields(first_bytes(fields, 2))
        return HandshakeMessage(
            client_hello=ClientHello(
                ephemeral=first_bytes(inner, 1),
                static=first_bytes(inner, 2),
                payload=first_bytes(inner, 3),
            )
        )
    if 3 in fields:
        inner = parse_fields(first_bytes(fields, 3))
        return HandshakeMessage(
            server_hello=ServerHello(
                ephemeral=first_bytes(inner, 1),
                static=first_bytes(inner, 2),
                payload=first_bytes(inner, 3),
            )
        )
    if 4 in fields:
        inner = parse_fields(first_bytes(fields, 4))
        return HandshakeMessage(
            client_finish=ClientFinish(
                static=first_bytes(inner, 1),
                payload=first_bytes(inner, 2),
            )
        )
    raise HandshakeError("unknown handshake message")
