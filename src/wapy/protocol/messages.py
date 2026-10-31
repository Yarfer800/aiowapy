"""Message encoding and the `message` node.

A text message travels as a Signal ciphertext per recipient device, wrapped in
`<enc>` children of one `<message>` node. The plaintext itself is a `Message`
protobuf; this module owns that small subset and the node shape, while the
encryption itself lives in `wapy.crypto.session`.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from wapy.errors import WapyError
from wapy.pb import bytes_field, first_bytes, parse_fields
from wapy.protocol.stream import children
from wapy.protocol.wabinary import Node


class MessageError(WapyError):
    """Message payload or node is malformed."""


def encode_text(text: str) -> bytes:
    """Plain text as a `Message` protobuf: `conversation`, or extended text for length."""
    if not text:
        raise MessageError("text must not be empty")
    if len(text) <= 256:
        return bytes_field(1, text.encode("utf-8"))
    return bytes_field(6, bytes_field(1, text.encode("utf-8")))


def decode_text(payload: bytes) -> str | None:
    """Extract text from a `Message` protobuf; None for non-text payloads."""
    fields = parse_fields(payload)
    conversation = first_bytes(fields, 1)
    if conversation:
        return conversation.decode("utf-8", errors="replace")
    extended = fields.get(6)
    if extended:
        inner = parse_fields(first_bytes(fields, 6))
        text = first_bytes(inner, 1)
        if text:
            return text.decode("utf-8", errors="replace")
    return None


@dataclass(frozen=True, slots=True)
class EncryptedDevice:
    device_jid: str
    ciphertext: bytes
    prekey: bool = False

    @property
    def enc_type(self) -> str:
        return "pkmsg" if self.prekey else "msg"


def enc_node(device: EncryptedDevice) -> Node:
    return Node(
        tag="enc",
        attrs={"v": "2", "type": device.enc_type, "jid": device.device_jid},
        content=device.ciphertext,
    )


def build_message_node(
    to_jid: str,
    message_id: str,
    devices: list[EncryptedDevice],
    *,
    message_type: str = "text",
) -> Node:
    if not devices:
        raise MessageError("a message needs at least one encrypted payload")
    return Node(
        tag="message",
        attrs={"id": message_id, "to": to_jid, "type": message_type},
        content=[enc_node(device) for device in devices],
    )


@dataclass(frozen=True, slots=True)
class IncomingMessage:
    from_jid: str
    message_id: str
    message_type: str
    devices: list[EncryptedDevice]


def parse_incoming(node: Node) -> IncomingMessage:
    if node.tag != "message":
        raise MessageError(f"expected a message node, got {node.tag!r}")
    from_jid = node.attrs.get("from", "")
    message_id = node.attrs.get("id", "")
    if not from_jid or not message_id:
        raise MessageError("message node is missing from or id")
    devices: list[EncryptedDevice] = []
    for enc in children(node, "enc"):
        payload = enc.content
        if not isinstance(payload, bytes):
            raise MessageError("enc content must be bytes")
        devices.append(
            EncryptedDevice(
                device_jid=enc.attrs.get("jid", from_jid),
                ciphertext=payload,
                prekey=enc.attrs.get("type") == "pkmsg",
            )
        )
    return IncomingMessage(
        from_jid=from_jid,
        message_id=message_id,
        message_type=node.attrs.get("type", ""),
        devices=devices,
    )


def encode_for_transport(payload: bytes) -> str:
    """WhatsApp's own base64 form used inside some nodes."""
    return base64.b64encode(payload).decode("ascii")


def decode_from_transport(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise MessageError("payload is not valid base64") from exc
