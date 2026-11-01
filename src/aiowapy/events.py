from __future__ import annotations

from dataclasses import dataclass, field

from aiowapy.protocol.media import MediaInfo
from aiowapy.protocol.wabinary import Node


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
class ReactionEvent:
    """An emoji reaction; `text` is empty when the reaction was retracted."""

    chat_jid: str
    sender_jid: str
    message_id: str
    text: str
    from_me: bool = False
    timestamp: int | None = None
    raw: Node | None = None


@dataclass(frozen=True, slots=True)
class EditEvent:
    chat_jid: str
    sender_jid: str
    message_id: str
    text: str | None
    timestamp: int | None = None
    raw: Node | None = None


@dataclass(frozen=True, slots=True)
class RevokeEvent:
    chat_jid: str
    sender_jid: str
    message_id: str
    raw: Node | None = None


@dataclass(frozen=True, slots=True)
class HistorySyncEvent:
    """One history chunk was stored: messages the bot never saw live."""

    sync_type: int
    chats: int
    messages: int
    chunk_order: int = 0
    has_more: bool = False


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
    | ReactionEvent
    | HistorySyncEvent
    | EditEvent
    | RevokeEvent
    | ReceiptEvent
    | PresenceEvent
    | ChatStateEvent
    | ConnectedEvent
    | DisconnectedEvent
    | NotificationEvent
)
