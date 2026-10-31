from __future__ import annotations

import gzip

import pytest

from wapy.messaging.history import HistorySyncService
from wapy.models import MEDIA_IMAGE, MediaInfo
from wapy.pb import bytes_field, message_field, varint_field
from wapy.protocol.history import (
    HistoryError,
    encode_conversation,
    encode_history_message,
    parse_history_sync,
    parse_notification,
)
from wapy.protocol.messages import encode_media, encode_text, parse_message
from wapy.store import SessionStore

CHAT = "491234567890@s.whatsapp.net"
GROUP = "120363000000000001@g.us"


def history_blob() -> bytes:
    direct = encode_history_message(
        CHAT, "H1", encode_text("first"), timestamp=100, participant=CHAT
    )
    reply = encode_history_message(
        CHAT, "H2", encode_text("second"), timestamp=200, participant=CHAT, from_me=True
    )
    group_message = encode_history_message(
        GROUP, "G1", encode_text("in group"), timestamp=150, participant=CHAT
    )
    body = varint_field(1, 0)  # INITIAL_BOOTSTRAP
    body += bytes_field(2, encode_conversation(CHAT, [direct, reply], name="Alice"))
    body += bytes_field(2, encode_conversation(GROUP, [group_message], name="Team"))
    body += message_field(7, bytes_field(1, CHAT.encode()) + bytes_field(2, b"Alice"))
    body += message_field(15, bytes_field(1, CHAT.encode()) + bytes_field(2, b"11111@lid"))
    body += varint_field(5, 2)
    body += varint_field(6, 100)
    return gzip.compress(body)


def test_parse_history_sync() -> None:
    history = parse_history_sync(history_blob())
    assert history.sync_type == 0
    assert history.chunk_order == 2
    assert history.progress == 100
    assert history.message_count == 3
    assert history.push_names == {CHAT: "Alice"}
    assert history.lid_mappings == {CHAT: "11111@lid"}

    direct = history.conversations[0]
    assert direct.jid == CHAT
    assert direct.name == "Alice"
    assert [message.message_id for message in direct.messages] == ["H1", "H2"]
    assert [message.text for message in direct.messages] == ["first", "second"]
    assert direct.messages[0].outgoing is False
    assert direct.messages[1].outgoing is True
    assert direct.messages[0].timestamp == 100


def test_history_media_message_is_parsed() -> None:
    info = MediaInfo(
        media_type=MEDIA_IMAGE,
        mime_type="image/jpeg",
        url="https://mmg.example/x",
        direct_path="/v/t62/x",
        media_key=b"k" * 32,
        file_sha256=b"a" * 32,
        file_enc_sha256=b"b" * 32,
        file_length=10,
    )
    raw = encode_history_message(CHAT, "H3", encode_media(info), timestamp=1)
    history = parse_history_sync(gzip.compress(bytes_field(2, encode_conversation(CHAT, [raw]))))
    media = history.conversations[0].messages[0].media
    assert media is not None
    assert media.media_type == "image"
    assert media.media_key == info.media_key


def test_uncompressed_history_is_accepted() -> None:
    raw = encode_history_message(CHAT, "H1", encode_text("plain"), timestamp=1)
    history = parse_history_sync(bytes_field(2, encode_conversation(CHAT, [raw])))
    assert history.message_count == 1


def test_broken_blob_is_rejected() -> None:
    with pytest.raises(HistoryError):
        parse_history_sync(b"\xff\xff\xff")


def test_notification_parsing() -> None:
    raw = (
        bytes_field(1, b"h" * 32)
        + varint_field(2, 1024)
        + bytes_field(3, b"k" * 32)
        + bytes_field(4, b"e" * 32)
        + bytes_field(5, b"/v/t62/history")
        + varint_field(6, 0)
        + varint_field(7, 3)
        + varint_field(9, 42)
        + bytes_field(14, b"handle")
    )
    notification = parse_notification(raw)
    assert notification.direct_path == "/v/t62/history"
    assert notification.media_key == b"k" * 32
    assert notification.chunk_order == 3
    assert notification.progress == 42
    assert notification.enc_handle == "handle"
    assert notification.media.media_type == "md-msg-hist"


def test_notification_without_source_is_rejected() -> None:
    with pytest.raises(HistoryError):
        parse_notification(varint_field(6, 0))


def test_protocol_message_carries_the_notification() -> None:
    notification = bytes_field(11, history_blob())
    protocol = varint_field(2, 5) + bytes_field(6, notification)
    parsed = parse_message(bytes_field(12, protocol))
    assert parsed.protocol is not None
    assert parsed.protocol.kind == "history_sync"
    assert parsed.protocol.raw == notification


async def test_service_stores_messages_and_peers(tmp_path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:

        class NoMedia:
            async def download(self, info: object) -> bytes:  # pragma: no cover
                raise AssertionError("inline payloads must not be downloaded")

        service = HistorySyncService(NoMedia(), store)  # type: ignore[arg-type]
        notification = parse_notification(bytes_field(11, history_blob()))
        result = await service.handle(notification)

        assert result.chats == 2
        assert result.messages == 3
        assert result.has_more is False

        alice = await store.get_peer(CHAT)
        assert alice is not None and alice["push_name"] == "Alice"
        team = await store.get_peer(GROUP)
        assert team is not None and team["subject"] == "Team" and team["kind"] == "group"

        messages = await store.get_messages(CHAT)
        assert [row["message_id"] for row in messages] == ["H2", "H1"]
        assert messages[1]["text"] == "first"
        assert messages[0]["outgoing"] == 1
    finally:
        await store.close()


async def test_service_skips_duplicate_chunks(tmp_path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:

        class NoMedia:
            async def download(self, info: object) -> bytes:  # pragma: no cover
                raise AssertionError

        service = HistorySyncService(NoMedia(), store)  # type: ignore[arg-type]
        notification = parse_notification(bytes_field(11, history_blob()))
        await service.handle(notification)
        await service.handle(notification)
        assert len(await store.get_messages(CHAT)) == 2
    finally:
        await store.close()
