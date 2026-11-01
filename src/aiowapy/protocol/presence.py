from __future__ import annotations

from dataclasses import dataclass

from aiowapy.errors import WapyError
from aiowapy.protocol.stream import child, children
from aiowapy.protocol.wabinary import Node

PRESENCE_AVAILABLE = "available"
PRESENCE_UNAVAILABLE = "unavailable"
CHAT_COMPOSING = "composing"
CHAT_PAUSED = "paused"
MEDIA_AUDIO = "audio"


class PresenceError(WapyError):
    """A presence node is malformed."""


def build_presence(state: str, *, push_name: str | None = None) -> Node:
    if state not in (PRESENCE_AVAILABLE, PRESENCE_UNAVAILABLE):
        raise PresenceError(f"unknown presence state: {state!r}")
    attrs = {"type": state}
    if push_name:
        attrs["name"] = push_name
    return Node(tag="presence", attrs=attrs)


def build_subscribe(jid: str, *, tctoken: bytes | None = None) -> Node:
    """Ask the server to forward this user's presence; some accounts need a token."""
    node = Node(tag="presence", attrs={"type": "subscribe", "to": jid})
    if tctoken:
        node.content = [Node(tag="tctoken", attrs={}, content=tctoken)]
    return node


def build_chat_state(jid: str, state: str, *, media: str | None = None) -> Node:
    if state not in (CHAT_COMPOSING, CHAT_PAUSED):
        raise PresenceError(f"unknown chat state: {state!r}")
    inner = Node(tag=state, attrs={})
    if state == CHAT_COMPOSING and media:
        inner.attrs["media"] = media
    return Node(tag="chatstate", attrs={"to": jid}, content=[inner])


@dataclass(frozen=True, slots=True)
class PresenceUpdate:
    jid: str
    available: bool
    last_seen: int | None
    """Unix seconds, or None when the user hides it or it was not sent."""


@dataclass(frozen=True, slots=True)
class ChatStateUpdate:
    jid: str
    state: str
    media: str | None = None


def parse_presence(node: Node) -> PresenceUpdate | None:
    if node.tag != "presence":
        return None
    jid = node.attrs.get("from")
    presence_type = node.attrs.get("type", "")
    if not jid or not presence_type:
        return None
    last_seen: int | None = None
    raw_last = node.attrs.get("last", "")
    if raw_last and raw_last != "deny":
        try:
            last_seen = int(raw_last)
        except ValueError:
            last_seen = None
    return PresenceUpdate(
        jid=jid,
        available=presence_type != PRESENCE_UNAVAILABLE,
        last_seen=last_seen,
    )


def parse_chat_state(node: Node) -> ChatStateUpdate | None:
    if node.tag != "chatstate":
        return None
    jid = node.attrs.get("from")
    parts = children(node, "composing") + children(node, "paused")
    if not jid or len(parts) != 1:
        return None
    inner = parts[0]
    return ChatStateUpdate(jid=jid, state=inner.tag, media=inner.attrs.get("media"))


def presence_child(node: Node) -> Node | None:
    """`<presence>` inside an `<ib>` or notification wrapper."""
    return child(node, "presence") or child(node, "chatstate")
