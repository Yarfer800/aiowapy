from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from wapy.store import SessionStore


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[SessionStore]:
    instance = SessionStore(tmp_path / "bot.session")
    await instance.open()
    yield instance
    await instance.close()


async def test_new_prekeys_are_pending(store: SessionStore) -> None:
    await store.add_prekeys([(1, b"a"), (2, b"b")])
    assert await store.pending_prekeys() == [(1, b"a"), (2, b"b")]


async def test_mark_uploaded_removes_from_pending(store: SessionStore) -> None:
    await store.add_prekeys([(1, b"a"), (2, b"b"), (3, b"c")])
    await store.mark_prekeys_uploaded([1, 3])
    assert await store.pending_prekeys() == [(2, b"b")]
    assert await store.count_available_prekeys() == 2


async def test_consume_prekey_removes_it(store: SessionStore) -> None:
    await store.add_prekeys([(1, b"a")])
    await store.mark_prekeys_uploaded([1])
    assert await store.consume_prekey(1) == b"a"
    assert await store.consume_prekey(1) is None
    assert await store.get_prekey(1) is None


async def test_consume_unknown_prekey_returns_none(store: SessionStore) -> None:
    assert await store.consume_prekey(999) is None


async def test_max_prekey_id(store: SessionStore) -> None:
    assert await store.max_prekey_id() is None
    await store.add_prekeys([(5, b"a"), (9, b"b")])
    assert await store.max_prekey_id() == 9


async def test_adding_existing_prekey_id_raises(store: SessionStore) -> None:
    await store.add_prekeys([(1, b"a")])
    with pytest.raises(sqlite3.IntegrityError):
        await store.add_prekeys([(1, b"b")])
    assert await store.get_prekey(1) == b"a"
