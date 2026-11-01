from __future__ import annotations

import gzip
from dataclasses import dataclass, field

from aiowapy.errors import WapyError
from aiowapy.models import MediaInfo
from aiowapy.pb import (
    ProtobufError,
    bytes_field,
    first_bytes,
    first_int,
    message_field,
    parse_fields,
)
from aiowapy.protocol.messages import parse_message

HISTORY_MEDIA_TYPE = "md-msg-hist"
HISTORY_INFO = "Message History"

SYNC_INITIAL_BOOTSTRAP = 0
SYNC_INITIAL_STATUS = 1
SYNC_FULL = 2
SYNC_RECENT = 3
SYNC_PUSH_NAME = 4
SYNC_NON_BLOCKING = 5
SYNC_ON_DEMAND = 6

_FIELD_KEY = 1
_FIELD_MESSAGE = 2
_FIELD_TIMESTAMP = 3
_FIELD_PARTICIPANT = 5
_FIELD_PUSH_NAME = 19

_HS_SYNC_TYPE = 1
_HS_CONVERSATIONS = 2
_HS_CHUNK_ORDER = 5
_HS_PROGRESS = 6
_HS_PUSH_NAMES = 7
_HS_LID_MAPPINGS = 15

_CONV_ID = 1
_CONV_MESSAGES = 2
_CONV_NAME = 13
_CONV_PN_JID = 39

_NOTIF_FILE_SHA256 = 1
_NOTIF_FILE_LENGTH = 2
_NOTIF_MEDIA_KEY = 3
_NOTIF_FILE_ENC_SHA256 = 4
_NOTIF_DIRECT_PATH = 5
_NOTIF_SYNC_TYPE = 6
_NOTIF_CHUNK_ORDER = 7
_NOTIF_PROGRESS = 9
_NOTIF_OLDEST_TS = 10
_NOTIF_INLINE = 11
_NOTIF_ENC_HANDLE = 14


class HistoryError(WapyError):
    """A history sync payload cannot be understood."""


@dataclass(frozen=True, slots=True)
class HistorySyncNotification:
    direct_path: str
    media_key: bytes = b""
    file_sha256: bytes = b""
    file_enc_sha256: bytes = b""
    file_length: int = 0
    sync_type: int = SYNC_INITIAL_BOOTSTRAP
    chunk_order: int = 0
    progress: int = 0
    oldest_timestamp: int = 0
    enc_handle: str = ""
    inline_payload: bytes = b""

    @property
    def media(self) -> MediaInfo:
        return MediaInfo(
            media_type=HISTORY_MEDIA_TYPE,
            mime_type="application/octet-stream",
            url="",
            direct_path=self.direct_path,
            media_key=self.media_key,
            file_sha256=self.file_sha256,
            file_enc_sha256=self.file_enc_sha256 or self.file_sha256,
            file_length=self.file_length,
        )


@dataclass(frozen=True, slots=True)
class HistoryMessage:
    chat_jid: str
    message_id: str
    sender_jid: str | None = None
    timestamp: int | None = None
    text: str | None = None
    media: MediaInfo | None = None
    outgoing: bool = False


@dataclass(frozen=True, slots=True)
class HistoryChat:
    jid: str
    name: str | None = None
    messages: list[HistoryMessage] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class HistorySync:
    sync_type: int
    conversations: list[HistoryChat] = field(default_factory=list)
    push_names: dict[str, str] = field(default_factory=dict)
    lid_mappings: dict[str, str] = field(default_factory=dict)
    chunk_order: int = 0
    progress: int = 0

    @property
    def message_count(self) -> int:
        return sum(len(chat.messages) for chat in self.conversations)


def parse_notification(raw: bytes) -> HistorySyncNotification:
    fields = parse_fields(raw)
    direct_path = _text(fields, _NOTIF_DIRECT_PATH) or ""
    inline = first_bytes(fields, _NOTIF_INLINE)
    if not direct_path and not inline:
        raise HistoryError("history sync notification has no payload source")
    return HistorySyncNotification(
        direct_path=direct_path,
        media_key=first_bytes(fields, _NOTIF_MEDIA_KEY),
        file_sha256=first_bytes(fields, _NOTIF_FILE_SHA256),
        file_enc_sha256=first_bytes(fields, _NOTIF_FILE_ENC_SHA256),
        file_length=first_int(fields, _NOTIF_FILE_LENGTH),
        sync_type=first_int(fields, _NOTIF_SYNC_TYPE),
        chunk_order=first_int(fields, _NOTIF_CHUNK_ORDER),
        progress=first_int(fields, _NOTIF_PROGRESS),
        oldest_timestamp=first_int(fields, _NOTIF_OLDEST_TS),
        enc_handle=_text(fields, _NOTIF_ENC_HANDLE) or "",
        inline_payload=inline,
    )


def decompress(blob: bytes) -> bytes:
    """History blobs are gzipped; inline bootstrap payloads are already plain."""
    try:
        return gzip.decompress(blob)
    except (OSError, EOFError):
        return blob


def parse_history_sync(blob: bytes) -> HistorySync:
    try:
        fields = parse_fields(decompress(blob))
    except ProtobufError as exc:
        raise HistoryError("history blob is not a valid protobuf") from exc

    conversations: list[HistoryChat] = []
    for raw in _all_bytes(fields, _HS_CONVERSATIONS):
        conversations.append(_parse_conversation(raw))

    push_names: dict[str, str] = {}
    for raw in _all_bytes(fields, _HS_PUSH_NAMES):
        push = parse_fields(raw)
        jid = _text(push, 1)
        name = _text(push, 2)
        if jid and name:
            push_names[jid] = name

    mappings: dict[str, str] = {}
    for raw in _all_bytes(fields, _HS_LID_MAPPINGS):
        item = parse_fields(raw)
        pn = _text(item, 1)
        lid = _text(item, 2)
        if pn and lid:
            mappings[pn] = lid

    return HistorySync(
        sync_type=first_int(fields, _HS_SYNC_TYPE),
        conversations=conversations,
        push_names=push_names,
        lid_mappings=mappings,
        chunk_order=first_int(fields, _HS_CHUNK_ORDER),
        progress=first_int(fields, _HS_PROGRESS),
    )


def _parse_conversation(raw: bytes) -> HistoryChat:
    fields = parse_fields(raw)
    chat_jid = _text(fields, _CONV_ID) or ""
    if not chat_jid:
        raise HistoryError("conversation has no id")
    messages: list[HistoryMessage] = []
    for raw_message in _all_bytes(fields, _CONV_MESSAGES):
        parsed = _parse_history_message(raw_message, chat_jid)
        if parsed is not None:
            messages.append(parsed)
    messages.sort(key=lambda item: item.timestamp or 0)
    return HistoryChat(
        jid=chat_jid,
        name=_text(fields, _CONV_NAME) or _text(fields, _CONV_PN_JID),
        messages=messages,
    )


def _parse_history_message(raw: bytes, chat_jid: str) -> HistoryMessage | None:
    wrapper = parse_fields(raw)
    info = parse_fields(_maybe_bytes(wrapper, 1) or b"")
    if not info:
        return None
    key = parse_fields(_maybe_bytes(info, _FIELD_KEY) or b"")
    message_id = _text(key, 3) or ""
    if not message_id:
        return None
    body = _maybe_bytes(info, _FIELD_MESSAGE)
    parsed = parse_message(body) if body else None
    sender = _text(info, _FIELD_PARTICIPANT) or _text(key, 4)
    return HistoryMessage(
        chat_jid=chat_jid,
        message_id=message_id,
        sender_jid=sender,
        timestamp=first_int(info, _FIELD_TIMESTAMP) or None,
        text=parsed.text if parsed else None,
        media=parsed.media if parsed else None,
        outgoing=bool(first_int(key, 2)),
    )


def _all_bytes(fields: dict[int, list[object]], number: int) -> list[bytes]:
    return [item for item in fields.get(number, []) if isinstance(item, bytes)]


def _maybe_bytes(fields: dict[int, list[object]], number: int) -> bytes | None:
    value = fields.get(number)
    if not value:
        return None
    last = value[-1]
    return last if isinstance(last, bytes) else None


def _text(fields: dict[int, list[object]], number: int) -> str | None:
    value = _maybe_bytes(fields, number)
    return value.decode("utf-8", errors="replace") if value else None


def encode_conversation(chat_jid: str, messages: list[bytes], *, name: str | None = None) -> bytes:
    """Test/import helper: one Conversation with already encoded HistorySyncMsg entries."""
    body = bytes_field(_CONV_ID, chat_jid.encode("utf-8"))
    body += b"".join(bytes_field(_CONV_MESSAGES, item) for item in messages)
    if name:
        body += bytes_field(_CONV_NAME, name.encode("utf-8"))
    return body


def encode_history_message(
    chat_jid: str,
    message_id: str,
    payload: bytes,
    *,
    timestamp: int = 0,
    participant: str | None = None,
    from_me: bool = False,
) -> bytes:
    key = bytes_field(1, chat_jid.encode("utf-8"))
    if from_me:
        key += b"\x10\x01"
    key += bytes_field(3, message_id.encode("utf-8"))
    if participant:
        key += bytes_field(4, participant.encode("utf-8"))
    info = message_field(_FIELD_KEY, key) + message_field(_FIELD_MESSAGE, payload)
    if timestamp:
        info += _varint(_FIELD_TIMESTAMP, timestamp)
    if participant:
        info += bytes_field(_FIELD_PARTICIPANT, participant.encode("utf-8"))
    return message_field(1, info)


def _varint(number: int, value: int) -> bytes:
    from aiowapy.pb import varint_field

    return varint_field(number, value)
