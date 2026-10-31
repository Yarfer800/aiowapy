from __future__ import annotations

import pytest

from wapy.errors import WapyError
from wapy.protocol.presence import (
    CHAT_COMPOSING,
    CHAT_PAUSED,
    PRESENCE_AVAILABLE,
    PRESENCE_UNAVAILABLE,
    PresenceError,
    build_chat_state,
    build_presence,
    build_subscribe,
    parse_chat_state,
    parse_presence,
)
from wapy.protocol.wabinary import Node, decode_node, encode_node


def test_available_presence_carries_the_push_name() -> None:
    node = build_presence(PRESENCE_AVAILABLE, push_name="bot")
    assert node.tag == "presence"
    assert node.attrs == {"type": "available", "name": "bot"}


def test_unavailable_presence_has_no_name() -> None:
    node = build_presence(PRESENCE_UNAVAILABLE)
    assert node.attrs == {"type": "unavailable"}


def test_unknown_presence_state_is_rejected() -> None:
    with pytest.raises(PresenceError):
        build_presence("sleeping")


def test_subscribe_without_token() -> None:
    node = build_subscribe("1@s.whatsapp.net")
    assert node.attrs == {"type": "subscribe", "to": "1@s.whatsapp.net"}
    assert node.content is None


def test_subscribe_with_token() -> None:
    node = build_subscribe("1@s.whatsapp.net", tctoken=b"\x01\x02")
    assert isinstance(node.content, list)
    assert node.content[0].tag == "tctoken"


def test_composing_with_media() -> None:
    node = build_chat_state("1@s.whatsapp.net", CHAT_COMPOSING, media="audio")
    assert node.tag == "chatstate"
    inner = node.content[0]  # type: ignore[index]
    assert inner.tag == "composing"
    assert inner.attrs == {"media": "audio"}


def test_paused_has_no_media_attribute() -> None:
    node = build_chat_state("1@s.whatsapp.net", CHAT_PAUSED)
    inner = node.content[0]  # type: ignore[index]
    assert inner.tag == "paused"
    assert inner.attrs == {}


def test_bad_chat_state_is_rejected() -> None:
    with pytest.raises(PresenceError):
        build_chat_state("1@s.whatsapp.net", "typing")


def test_parse_presence_with_last_seen() -> None:
    node = Node(tag="presence", attrs={"from": "1@s", "type": "available", "last": "1700000000"})
    update = parse_presence(node)
    assert update is not None
    assert update.available is True
    assert update.last_seen == 1_700_000_000


def test_parse_presence_unavailable_hides_last_seen() -> None:
    node = Node(tag="presence", attrs={"from": "1@s", "type": "unavailable", "last": "deny"})
    update = parse_presence(node)
    assert update is not None
    assert update.available is False
    assert update.last_seen is None


def test_parse_presence_ignores_other_nodes() -> None:
    assert parse_presence(Node(tag="chatstate", attrs={"from": "1@s", "type": "available"})) is None


def test_parse_chat_state() -> None:
    node = Node(
        tag="chatstate",
        attrs={"from": "1@s"},
        content=[Node(tag="composing", attrs={"media": "audio"})],
    )
    update = parse_chat_state(node)
    assert update is not None
    assert (update.jid, update.state, update.media) == ("1@s", "composing", "audio")


def test_parse_chat_state_needs_exactly_one_child() -> None:
    node = Node(tag="chatstate", attrs={"from": "1@s"}, content=[Node(tag="paused")])
    assert parse_chat_state(node) is not None
    empty = Node(tag="chatstate", attrs={"from": "1@s"}, content=[])
    assert parse_chat_state(empty) is None


@pytest.mark.parametrize(
    "node",
    [
        build_presence(PRESENCE_AVAILABLE, push_name="bot"),
        build_subscribe("1@s", tctoken=b"token"),
        build_chat_state("1@s", CHAT_COMPOSING, media="audio"),
    ],
)
def test_presence_nodes_roundtrip(node: Node) -> None:
    assert decode_node(encode_node(node)) == node


def test_errors_are_wapy_errors() -> None:
    assert issubclass(PresenceError, WapyError)
