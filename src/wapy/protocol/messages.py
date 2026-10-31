from __future__ import annotations

import base64
from dataclasses import dataclass

from wapy.errors import WapyError
from wapy.pb import (
    ProtobufError,
    bytes_field,
    first_bytes,
    first_int,
    message_field,
    parse_fields,
    varint_field,
)
from wapy.protocol.media import (
    MEDIA_AUDIO,
    MEDIA_DOCUMENT,
    MEDIA_IMAGE,
    MEDIA_PTT,
    MEDIA_STICKER,
    MEDIA_VIDEO,
    MESSAGE_FIELDS,
    MediaInfo,
)
from wapy.protocol.stream import children
from wapy.protocol.wabinary import Node

FIELD_CONVERSATION = 1
FIELD_SKDM = 2
FIELD_EXTENDED_TEXT = 6
FIELD_PROTOCOL = 12
PROTOCOL_FIELD_TYPE = 2
PROTOCOL_FIELD_KEY_SHARE = 7
PROTOCOL_APP_STATE_KEY_SHARE = 6


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
    return parse_message(payload).text


def _text_field(field: int, value: str | None) -> bytes:
    return bytes_field(field, value.encode("utf-8")) if value else b""


def encode_media(info: MediaInfo) -> bytes:
    """Wrap a media description into the matching `Message` field."""
    field = MESSAGE_FIELDS.get(info.media_type)
    if field is None:
        raise MessageError(f"unsupported media type: {info.media_type!r}")
    body = _encode_media_body(info)
    return bytes_field(field, body)


def _encode_media_body(info: MediaInfo) -> bytes:
    if info.media_type == MEDIA_IMAGE:
        return b"".join(
            (
                _text_field(1, info.url),
                _text_field(2, info.mime_type),
                bytes_field(3, info.caption.encode("utf-8")) if info.caption else b"",
                bytes_field(4, info.file_sha256),
                varint_field(5, info.file_length),
                varint_field(6, info.height or 0),
                varint_field(7, info.width or 0),
                bytes_field(8, info.media_key),
                bytes_field(9, info.file_enc_sha256),
                _text_field(11, info.direct_path),
                varint_field(12, info.media_key_timestamp or 0),
            )
        )
    if info.media_type == MEDIA_VIDEO:
        return b"".join(
            (
                _text_field(1, info.url),
                _text_field(2, info.mime_type),
                bytes_field(3, info.file_sha256),
                varint_field(4, info.file_length),
                varint_field(5, info.seconds or 0),
                bytes_field(6, info.media_key),
                _text_field(7, info.caption),
                varint_field(9, info.height or 0),
                varint_field(10, info.width or 0),
                bytes_field(11, info.file_enc_sha256),
                _text_field(13, info.direct_path),
                varint_field(14, info.media_key_timestamp or 0),
            )
        )
    if info.media_type in (MEDIA_AUDIO, MEDIA_PTT):
        return b"".join(
            (
                _text_field(1, info.url),
                _text_field(2, info.mime_type),
                bytes_field(3, info.file_sha256),
                varint_field(4, info.file_length),
                varint_field(5, info.seconds or 0),
                varint_field(6, 1 if info.is_ptt else 0),
                bytes_field(7, info.media_key),
                bytes_field(8, info.file_enc_sha256),
                _text_field(9, info.direct_path),
                varint_field(10, info.media_key_timestamp or 0),
            )
        )
    if info.media_type == MEDIA_DOCUMENT:
        return b"".join(
            (
                _text_field(1, info.url),
                _text_field(2, info.mime_type),
                _text_field(3, info.file_name),
                bytes_field(4, info.file_sha256),
                varint_field(5, info.file_length),
                bytes_field(7, info.media_key),
                _text_field(8, info.file_name),
                bytes_field(9, info.file_enc_sha256),
                _text_field(10, info.direct_path),
                varint_field(11, info.media_key_timestamp or 0),
                _text_field(20, info.caption),
            )
        )
    # sticker
    return b"".join(
        (
            _text_field(1, info.url),
            bytes_field(2, info.file_sha256),
            bytes_field(3, info.file_enc_sha256),
            bytes_field(4, info.media_key),
            _text_field(5, info.mime_type),
            varint_field(6, info.height or 0),
            varint_field(7, info.width or 0),
            _text_field(8, info.direct_path),
            varint_field(9, info.file_length),
            varint_field(10, info.media_key_timestamp or 0),
        )
    )


def encode_device_sent(destination_jid: str, message: bytes) -> bytes:
    """The copy our own devices read: `DeviceSentMessage{destination, message}`."""
    return bytes_field(
        31,
        bytes_field(1, destination_jid.encode("utf-8")) + message_field(2, message),
    )


def encode_sender_key_distribution(group_id: str, axolotl: bytes) -> bytes:
    return bytes_field(2, _text_field(1, group_id) + bytes_field(2, axolotl))


@dataclass(frozen=True, slots=True)
class ParsedMessage:
    text: str | None = None
    media: MediaInfo | None = None
    sender_key_distribution: bytes | None = None
    sender_key_group: str | None = None
    app_state_keys: tuple[tuple[bytes, bytes], ...] = ()


_MEDIA_FIELDS = {
    MESSAGE_FIELDS[MEDIA_IMAGE]: MEDIA_IMAGE,
    MESSAGE_FIELDS[MEDIA_VIDEO]: MEDIA_VIDEO,
    MESSAGE_FIELDS[MEDIA_AUDIO]: MEDIA_AUDIO,
    MESSAGE_FIELDS[MEDIA_DOCUMENT]: MEDIA_DOCUMENT,
    MESSAGE_FIELDS[MEDIA_STICKER]: MEDIA_STICKER,
}


def parse_message(payload: bytes) -> ParsedMessage:
    fields = parse_fields(payload)
    conversation = first_bytes(fields, FIELD_CONVERSATION)
    if conversation:
        return ParsedMessage(text=conversation.decode("utf-8", errors="replace"))
    extended = fields.get(FIELD_EXTENDED_TEXT)
    if extended:
        text = first_bytes(parse_fields(first_bytes(fields, FIELD_EXTENDED_TEXT)), 1)
        if text:
            return ParsedMessage(text=text.decode("utf-8", errors="replace"))

    protocol = _maybe_bytes(fields, FIELD_PROTOCOL)
    if protocol:
        try:
            keys = _app_state_keys(protocol)
        except ProtobufError:
            keys = ()
        if keys:
            return ParsedMessage(app_state_keys=keys)

    raw_skdm = _maybe_bytes(fields, FIELD_SKDM)
    if raw_skdm:
        inner = parse_fields(raw_skdm)
        axolotl = _maybe_bytes(inner, 2)
        if axolotl:
            group = (_maybe_bytes(inner, 1) or b"").decode("utf-8", errors="replace")
            return ParsedMessage(sender_key_distribution=axolotl, sender_key_group=group)

    for number, media_type in _MEDIA_FIELDS.items():
        raw = fields.get(number)
        if raw:
            return ParsedMessage(media=_parse_media_body(first_bytes(fields, number), media_type))
    return ParsedMessage()


def _parse_media_body(body: bytes, media_type: str) -> MediaInfo:
    fields = parse_fields(body)
    if media_type == MEDIA_IMAGE:
        return MediaInfo(
            media_type=MEDIA_IMAGE,
            mime_type=_opt_text(fields, 2) or "",
            url=_opt_text(fields, 1) or "",
            direct_path=_opt_text(fields, 11) or "",
            media_key=first_bytes(fields, 8),
            file_sha256=first_bytes(fields, 4),
            file_enc_sha256=first_bytes(fields, 9),
            file_length=first_int(fields, 5),
            caption=_opt_text(fields, 3),
            width=first_int(fields, 7) or None,
            height=first_int(fields, 6) or None,
            media_key_timestamp=first_int(fields, 12) or None,
        )
    if media_type == MEDIA_VIDEO:
        return MediaInfo(
            media_type=MEDIA_VIDEO,
            mime_type=_opt_text(fields, 2) or "",
            url=_opt_text(fields, 1) or "",
            direct_path=_opt_text(fields, 13) or "",
            media_key=first_bytes(fields, 6),
            file_sha256=first_bytes(fields, 3),
            file_enc_sha256=first_bytes(fields, 11),
            file_length=first_int(fields, 4),
            caption=_opt_text(fields, 7),
            seconds=first_int(fields, 5) or None,
            width=first_int(fields, 10) or None,
            height=first_int(fields, 9) or None,
            media_key_timestamp=first_int(fields, 14) or None,
        )
    if media_type == MEDIA_DOCUMENT:
        return MediaInfo(
            media_type=MEDIA_DOCUMENT,
            mime_type=_opt_text(fields, 2) or "",
            url=_opt_text(fields, 1) or "",
            direct_path=_opt_text(fields, 10) or "",
            media_key=first_bytes(fields, 7),
            file_sha256=first_bytes(fields, 4),
            file_enc_sha256=first_bytes(fields, 9),
            file_length=first_int(fields, 5),
            caption=_opt_text(fields, 20),
            file_name=_opt_text(fields, 8) or _opt_text(fields, 3),
            media_key_timestamp=first_int(fields, 11) or None,
        )
    if media_type in (MEDIA_AUDIO, MEDIA_PTT):
        is_ptt = bool(first_int(fields, 6))
        return MediaInfo(
            media_type=MEDIA_PTT if is_ptt else MEDIA_AUDIO,
            mime_type=_opt_text(fields, 2) or "",
            url=_opt_text(fields, 1) or "",
            direct_path=_opt_text(fields, 9) or "",
            media_key=first_bytes(fields, 7),
            file_sha256=first_bytes(fields, 3),
            file_enc_sha256=first_bytes(fields, 8),
            file_length=first_int(fields, 4),
            seconds=first_int(fields, 5) or None,
            is_ptt=is_ptt,
            media_key_timestamp=first_int(fields, 10) or None,
        )
    return MediaInfo(
        media_type=MEDIA_STICKER,
        mime_type=_opt_text(fields, 5) or "",
        url=_opt_text(fields, 1) or "",
        direct_path=_opt_text(fields, 8) or "",
        media_key=first_bytes(fields, 4),
        file_sha256=first_bytes(fields, 2),
        file_enc_sha256=first_bytes(fields, 3),
        file_length=first_int(fields, 9),
        width=first_int(fields, 7) or None,
        height=first_int(fields, 6) or None,
        media_key_timestamp=first_int(fields, 10) or None,
    )


def _app_state_keys(protocol: bytes) -> tuple[tuple[bytes, bytes], ...]:
    """App state sync keys the phone shares through a protocol message."""
    inner = parse_fields(protocol)
    if first_int(inner, PROTOCOL_FIELD_TYPE) != PROTOCOL_APP_STATE_KEY_SHARE:
        return ()
    share = _maybe_bytes(inner, PROTOCOL_FIELD_KEY_SHARE)
    if not share:
        return ()
    result: list[tuple[bytes, bytes]] = []
    for raw_key in _all_bytes(parse_fields(share), 1):
        key = parse_fields(raw_key)
        key_id = _maybe_bytes(parse_fields(_maybe_bytes(key, 1) or b""), 1)
        key_value = _maybe_bytes(parse_fields(_maybe_bytes(key, 2) or b""), 1)
        if key_id and key_value:
            result.append((key_id, key_value))
    return tuple(result)


def _all_bytes(fields: dict[int, list[object]], number: int) -> list[bytes]:
    return [item for item in fields.get(number, []) if isinstance(item, bytes)]


def _maybe_bytes(fields: dict[int, list[object]], number: int) -> bytes | None:
    values = fields.get(number)
    if not values:
        return None
    value = values[-1]
    return value if isinstance(value, bytes) else None


def _opt_text(fields: dict[int, list[object]], number: int) -> str | None:
    value = first_bytes(fields, number)
    return value.decode("utf-8", errors="replace") if value else None


@dataclass(frozen=True, slots=True)
class EncryptedDevice:
    device_jid: str
    ciphertext: bytes
    prekey: bool = False

    @property
    def enc_type(self) -> str:
        return "pkmsg" if self.prekey else "msg"


def enc_node(device: EncryptedDevice, *, media_type: str | None = None) -> Node:
    attrs = {"v": "2", "type": device.enc_type, "jid": device.device_jid}
    if media_type:
        attrs["mediatype"] = media_type
    return Node(tag="enc", attrs=attrs, content=device.ciphertext)


def group_enc_node(ciphertext: bytes, *, media_type: str | None = None) -> Node:
    """Sender key ciphertext: one blob for every member, no `jid`."""
    attrs = {"v": "2", "type": "skmsg"}
    if media_type:
        attrs["mediatype"] = media_type
    return Node(tag="enc", attrs=attrs, content=ciphertext)


def build_message_node(
    to_jid: str,
    message_id: str,
    devices: list[EncryptedDevice],
    *,
    message_type: str = "text",
    media_type: str | None = None,
    device_identity: bytes | None = None,
    extra: list[Node] | None = None,
) -> Node:
    """One `<message>`: per-device payloads inside `<participants>`.

    The participants wrapper is not cosmetic: both reference clients put every
    `<enc>` there, and a stanza with bare `<enc>` children is not a message the
    server knows how to route. A sender key payload (`skmsg`) stays at the root.
    """
    if not devices:
        raise MessageError("a message needs at least one encrypted payload")
    content = [
        Node(
            tag="participants",
            attrs={},
            content=[enc_node(device, media_type=media_type) for device in devices],
        )
    ]
    if device_identity:
        content.append(Node(tag="device-identity", attrs={}, content=device_identity))
    if extra:
        content.extend(extra)
    return Node(
        tag="message",
        attrs={"id": message_id, "to": to_jid, "type": message_type},
        content=content,
    )


@dataclass(frozen=True, slots=True)
class IncomingMessage:
    from_jid: str
    message_id: str
    message_type: str
    timestamp: int | None
    devices: list[EncryptedDevice]
    sender_key: bytes | None = None
    participant: str | None = None
    push_name: str | None = None


def parse_incoming(node: Node) -> IncomingMessage:
    if node.tag != "message":
        raise MessageError(f"expected a message node, got {node.tag!r}")
    from_jid = node.attrs.get("from", "")
    message_id = node.attrs.get("id", "")
    if not from_jid or not message_id:
        raise MessageError("message node is missing from or id")
    devices: list[EncryptedDevice] = []
    sender_key: bytes | None = None
    for enc in _enc_nodes(node):
        payload = enc.content
        if not isinstance(payload, bytes):
            raise MessageError("enc content must be bytes")
        enc_type = enc.attrs.get("type")
        if enc_type == "skmsg":
            sender_key = payload
            continue
        devices.append(
            EncryptedDevice(
                device_jid=enc.attrs.get("jid", from_jid),
                ciphertext=payload,
                prekey=enc_type == "pkmsg",
            )
        )
    timestamp: int | None = None
    raw_timestamp = node.attrs.get("t")
    if raw_timestamp:
        try:
            timestamp = int(raw_timestamp)
        except ValueError:
            timestamp = None
    return IncomingMessage(
        from_jid=from_jid,
        message_id=message_id,
        message_type=node.attrs.get("type", ""),
        timestamp=timestamp,
        devices=devices,
        sender_key=sender_key,
        participant=node.attrs.get("participant"),
        push_name=node.attrs.get("notify"),
    )


def _enc_nodes(node: Node) -> list[Node]:
    """`<enc>` entries: ours come in `<participants>`, old captures had them inline."""
    found = children(node, "enc")
    for participants in children(node, "participants"):
        found.extend(children(participants, "enc"))
    return found


def encode_for_transport(payload: bytes) -> str:
    """WhatsApp's own base64 form used inside some nodes."""
    return base64.b64encode(payload).decode("ascii")


def decode_from_transport(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise MessageError("payload is not valid base64") from exc
