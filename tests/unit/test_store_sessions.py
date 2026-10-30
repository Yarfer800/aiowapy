from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from wapy.store import SessionStore

ALICE = "491111111111.0:0@s.whatsapp.net"
BOB = "492222222222@s.whatsapp.net"


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[SessionStore]:
    instance = SessionStore(tmp_path / "bot.session")
    await instance.open()
    yield instance
    await instance.close()


async def test_session_roundtrip(store: SessionStore) -> None:
    assert await store.get_session(ALICE) is None
    await store.put_session(ALICE, b"ratchet-1")
    assert await store.get_session(ALICE) == b"ratchet-1"
    await store.put_session(ALICE, b"ratchet-2")
    assert await store.get_session(ALICE) == b"ratchet-2"


async def test_delete_session(store: SessionStore) -> None:
    await store.put_session(ALICE, b"ratchet")
    await store.delete_session(ALICE)
    assert await store.get_session(ALICE) is None


async def test_sessions_are_isolated_per_device(store: SessionStore) -> None:
    alice_device_1 = "491111111111.0:0@s.whatsapp.net"
    alice_device_2 = "491111111111.0:1@s.whatsapp.net"
    await store.put_session(alice_device_1, b"one")
    await store.put_session(alice_device_2, b"two")
    assert await store.get_session(alice_device_1) == b"one"
    assert await store.get_session(alice_device_2) == b"two"


async def test_identity_roundtrip_and_default_trust(store: SessionStore) -> None:
    assert await store.get_identity(BOB) is None
    await store.put_identity(BOB, b"pubkey")
    assert await store.get_identity(BOB) == b"pubkey"
    async with store._tx(write=False) as conn:
        cursor = await conn.execute("SELECT trust FROM identity_keys WHERE jid = ?", (BOB,))
        row = await cursor.fetchone()
        await cursor.close()
    assert row["trust"] == "trusted"


async def test_identity_trust_can_be_marked_untrusted(store: SessionStore) -> None:
    await store.put_identity(BOB, b"pubkey", trust="untrusted")
    async with store._tx(write=False) as conn:
        cursor = await conn.execute("SELECT trust FROM identity_keys WHERE jid = ?", (BOB,))
        row = await cursor.fetchone()
        await cursor.close()
    assert row["trust"] == "untrusted"


async def test_app_state_key_roundtrip(store: SessionStore) -> None:
    key_id = b"\x01\x02"
    assert await store.get_app_state_key(key_id) is None
    await store.put_app_state_key(key_id, b"keydata")
    assert await store.get_app_state_key(key_id) == b"keydata"


async def test_app_state_version_roundtrip(store: SessionStore) -> None:
    assert await store.get_app_state_version("regular") is None
    await store.set_app_state_version("regular", 12, b"hash")
    assert await store.get_app_state_version("regular") == (12, b"hash")
    await store.set_app_state_version("regular", 13, b"hash2")
    assert await store.get_app_state_version("regular") == (13, b"hash2")
