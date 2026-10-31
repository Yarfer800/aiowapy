from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

KIND_USER = "user"
KIND_GROUP = "group"

MEDIA_IMAGE = "image"
MEDIA_VIDEO = "video"
MEDIA_AUDIO = "audio"
MEDIA_PTT = "ptt"
MEDIA_DOCUMENT = "document"
MEDIA_STICKER = "sticker"


@dataclass(frozen=True, slots=True)
class MediaInfo:
    media_type: str
    mime_type: str
    url: str
    direct_path: str
    media_key: bytes
    file_sha256: bytes
    file_enc_sha256: bytes
    file_length: int
    caption: str | None = None
    file_name: str | None = None
    seconds: int | None = None
    width: int | None = None
    height: int | None = None
    is_ptt: bool = False
    media_key_timestamp: int | None = None


@dataclass(frozen=True, slots=True)
class MediaConnection:
    auth: str
    hosts: tuple[str, ...]
    ttl: int

    @property
    def upload_host(self) -> str:
        if not self.hosts:
            raise ValueError("the server returned no media hosts")
        return self.hosts[0]


@dataclass(frozen=True, slots=True)
class Peer:
    """A user or a group we have seen, stored in the session file."""

    jid: str
    kind: str
    phone: str | None = None
    push_name: str | None = None
    contact_name: str | None = None
    subject: str | None = None
    last_update_on: int = 0
    last_message_at: int | None = None
    total_messages: int | None = None

    @property
    def name(self) -> str:
        return self.contact_name or self.push_name or self.subject or self.jid

    @property
    def is_group(self) -> bool:
        return self.kind == KIND_GROUP


@dataclass(frozen=True, slots=True)
class StoredMessage:
    """A message as kept in the session file."""

    chat_jid: str
    message_id: str
    sender_jid: str | None = None
    timestamp: int | None = None
    text: str | None = None
    media: MediaInfo | None = None
    outgoing: bool = False


def media_to_dict(media: MediaInfo) -> dict[str, Any]:
    return {
        "media_type": media.media_type,
        "mime_type": media.mime_type,
        "url": media.url,
        "direct_path": media.direct_path,
        "media_key": _b64(media.media_key),
        "file_sha256": _b64(media.file_sha256),
        "file_enc_sha256": _b64(media.file_enc_sha256),
        "file_length": media.file_length,
        "caption": media.caption,
        "file_name": media.file_name,
        "seconds": media.seconds,
        "width": media.width,
        "height": media.height,
        "is_ptt": media.is_ptt,
        "media_key_timestamp": media.media_key_timestamp,
    }


def media_from_dict(data: dict[str, Any]) -> MediaInfo:
    return MediaInfo(
        media_type=str(data["media_type"]),
        mime_type=str(data.get("mime_type", "")),
        url=str(data.get("url", "")),
        direct_path=str(data.get("direct_path", "")),
        media_key=_unb64(data.get("media_key")),
        file_sha256=_unb64(data.get("file_sha256")),
        file_enc_sha256=_unb64(data.get("file_enc_sha256")),
        file_length=int(data.get("file_length", 0)),
        caption=_opt_str(data.get("caption")),
        file_name=_opt_str(data.get("file_name")),
        seconds=_opt_int(data.get("seconds")),
        width=_opt_int(data.get("width")),
        height=_opt_int(data.get("height")),
        is_ptt=bool(data.get("is_ptt", False)),
        media_key_timestamp=_opt_int(data.get("media_key_timestamp")),
    )


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        return b""
    return base64.b64decode(value)


def _opt_str(value: object) -> str | None:
    return None if value is None else str(value)


def _opt_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float, str, bytes, bytearray)):
        return int(value)
    raise TypeError(f"not an integer: {value!r}")
