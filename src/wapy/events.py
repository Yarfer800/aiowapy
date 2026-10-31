from __future__ import annotations

from dataclasses import dataclass, field

from wapy.protocol.media import MediaInfo
from wapy.protocol.wabinary import Node


@dataclass(frozen=True, slots=True)
class MessageEvent:
    """A decrypted incoming message: text, an attachment, or both."""

    chat_jid: str
    sender_jid: str
    message_id: str
    text: str | None = None
    media: MediaInfo | None = None
    timestamp: int | None = None
    from_me: bool = False
    sender_key: bool = False
    raw: Node | None = None


@dataclass(frozen=True, slots=True)
class ReceiptEvent:
    """Delivery or read confirmation, for one message or a batch of them."""

    chat_jid: str
    sender_jid: str
    message_ids: tuple[str, ...]
    receipt_type: str
    timestamp: int | None = None
    raw: Node | None = None


@dataclass(frozen=True, slots=True)
class PresenceEvent:
    jid: str
    available: bool
    last_seen: int | None = None
    raw: Node | None = None


@dataclass(frozen=True, slots=True)
class ChatStateEvent:
    """Typing indicator: `composing` (optionally recording `audio`) or `paused`."""

    jid: str
    state: str
    media: str | None = None
    raw: Node | None = None


@dataclass(frozen=True, slots=True)
class ConnectedEvent:
    jid: str
    lid: str | None = None


@dataclass(frozen=True, slots=True)
class DisconnectedEvent:
    reason: str


@dataclass(frozen=True, slots=True)
class NotificationEvent:
    """Server-side notification we do not model yet (device changes, sync, ...)."""

    kind: str
    attrs: dict[str, str] = field(default_factory=dict)
    raw: Node | None = None


AnyEvent = (
    MessageEvent
    | ReceiptEvent
    | PresenceEvent
    | ChatStateEvent
    | ConnectedEvent
    | DisconnectedEvent
    | NotificationEvent
)
