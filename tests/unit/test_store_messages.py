from __future__ import annotations

from pathlib import Path

import pytest

from wapy.store import SessionStore

CHAT = "491234567890@s.whatsapp.net"
GROUP = "120363000000000001@g.us"


@pytest.fixture
async def store(tmp_path: Path):
    instance = SessionStore(tmp_path / "bot.session")
    await instance.open()
    try:
        yield instance
    finally:
        await instance.close()


async def test_peer_is_created_and_refined(store: SessionStore) -> None:
    await store.upsert_peer(CHAT, "user")
    await store.upsert_peer(CHAT, "user", push_name="Alice")
    row = await store.get_peer(CHAT)
    assert row is not None
    assert row["push_name"] == "Alice"
    assert row["kind"] == "user"


async def test_peer_values_are_not_wiped_by_none(store: SessionStore) -> None:
    await store.upsert_peer(CHAT, "user", push_name="Alice", phone="491234567890")
    await store.upsert_peer(CHAT, "user")
    row = await store.get_peer(CHAT)
    assert row is not None
    assert row["push_name"] == "Alice"
    assert row["phone"] == "491234567890"


async def test_contact_name_wins_over_push_name(store: SessionStore) -> None:
    await store.upsert_peer(CHAT, "user", push_name="Alice")
    await store.upsert_peer(CHAT, "user", contact_name="Mom")
    row = await store.get_peer(CHAT)
    assert row is not None
    assert row["push_name"] == "Alice"
    assert row["contact_name"] == "Mom"


async def test_list_peers_filters_by_kind(store: SessionStore) -> None:
    await store.upsert_peer(CHAT, "user")
    await store.upsert_peer(GROUP, "group", subject="Team")
    users = await store.list_peers("user")
    groups = await store.list_peers("group")
    assert [row["jid"] for row in users] == [CHAT]
    assert [row["jid"] for row in groups] == [GROUP]
    assert len(await store.list_peers()) == 2


async def test_messages_are_stored_newest_first(store: SessionStore) -> None:
    for index in range(5):
        await store.save_message(
            CHAT,
            f"M{index}",
            sender_jid=CHAT,
            timestamp=1000 + index,
            text=f"text {index}",
        )
    rows = await store.get_messages(CHAT)
    assert [row["message_id"] for row in rows] == ["M4", "M3", "M2", "M1", "M0"]


async def test_messages_support_paging_and_limit(store: SessionStore) -> None:
    for index in range(5):
        await store.save_message(CHAT, f"M{index}", timestamp=1000 + index, text=str(index))
    page = await store.get_messages(CHAT, limit=2, before_timestamp=1003)
    assert [row["message_id"] for row in page] == ["M2", "M1"]


async def test_message_saved_twice_is_updated(store: SessionStore) -> None:
    await store.save_message(CHAT, "M1", timestamp=1, text="first", outgoing=False)
    await store.save_message(CHAT, "M1", timestamp=1, text="edited", outgoing=True)
    row = await store.get_message(CHAT, "M1")
    assert row is not None
    assert row["text"] == "edited"
    assert row["outgoing"] == 1


async def test_media_roundtrip_through_json(store: SessionStore) -> None:
    import json

    from wapy.models import MEDIA_IMAGE, MediaInfo, media_from_dict, media_to_dict

    info = MediaInfo(
        media_type=MEDIA_IMAGE,
        mime_type="image/jpeg",
        url="https://mmg.example/x",
        direct_path="/v/t62/x",
        media_key=b"k" * 32,
        file_sha256=b"a" * 32,
        file_enc_sha256=b"b" * 32,
        file_length=10,
        caption="hi",
    )
    await store.save_message(CHAT, "M1", timestamp=1, media_json=json.dumps(media_to_dict(info)))
    row = await store.get_message(CHAT, "M1")
    assert row is not None
    restored = media_from_dict(json.loads(row["media_json"]))
    assert restored == info


async def test_list_chats_orders_by_last_message(store: SessionStore) -> None:
    await store.upsert_peer(CHAT, "user")
    await store.upsert_peer(GROUP, "group")
    await store.save_message(CHAT, "M1", timestamp=100)
    await store.save_message(GROUP, "M2", timestamp=200)
    await store.save_message(GROUP, "M3", timestamp=300)
    chats = await store.list_chats()
    assert [row["jid"] for row in chats] == [GROUP, CHAT]
    assert chats[0]["last_message_at"] == 300
    assert chats[0]["total"] == 2


async def test_delete_messages_keeps_the_peer(store: SessionStore) -> None:
    await store.upsert_peer(CHAT, "user")
    await store.save_message(CHAT, "M1", timestamp=1)
    await store.delete_messages(CHAT)
    assert await store.get_messages(CHAT) == []
    assert await store.get_peer(CHAT) is not None


async def test_peer_survives_reopening(tmp_path: Path) -> None:
    path = tmp_path / "bot.session"
    first = SessionStore(path)
    await first.open()
    await first.upsert_peer(CHAT, "user", contact_name="Mom")
    await first.save_message(CHAT, "M1", timestamp=5, text="hi")
    await first.close()

    second = SessionStore(path)
    await second.open()
    try:
        peer = await second.get_peer(CHAT)
        assert peer is not None and peer["contact_name"] == "Mom"
        messages = await second.get_messages(CHAT)
        assert messages[0]["text"] == "hi"
    finally:
        await second.close()


async def test_lid_mappings(store: SessionStore) -> None:
    await store.put_lid_mapping(CHAT, "11111@lid")
    assert await store.get_lid(CHAT) == "11111@lid"
    assert await store.get_pn("11111@lid") == CHAT
    assert await store.list_lid_mappings() == {CHAT: "11111@lid"}

    await store.put_lid_mapping(CHAT, "22222@lid")
    assert await store.get_lid(CHAT) == "22222@lid"
    assert await store.get_pn("11111@lid") is None
    assert await store.get_lid("99999@s.whatsapp.net") is None
