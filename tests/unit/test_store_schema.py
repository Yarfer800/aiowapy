from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from wapy.errors import StoreNotOpenError
from wapy.store import SCHEMA_VERSION, SessionStore


async def test_open_creates_file_with_private_permissions(tmp_path: Path) -> None:
    path = tmp_path / "bot.session"
    store = SessionStore(path)
    await store.open()
    try:
        assert path.exists()
        assert path.stat().st_mode & 0o777 == 0o600
    finally:
        await store.close()


async def test_open_applies_initial_migration(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        assert await store.get_meta("schema_version") == str(SCHEMA_VERSION)
        async with store._tx(write=False) as conn:
            cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            tables = {row["name"] for row in await cursor.fetchall()}
    finally:
        await store.close()
    assert {"meta", "creds", "prekeys", "sessions", "identity_keys"} <= tables
    assert {"app_state_keys", "app_state_ver"} <= tables


async def test_reopen_keeps_data_and_does_not_reapply_migrations(tmp_path: Path) -> None:
    path = tmp_path / "bot.session"
    first = SessionStore(path)
    await first.open()
    await first.set_meta("probe", "42")
    await first.close()

    second = SessionStore(path)
    await second.open()
    try:
        assert await second.get_meta("probe") == "42"
        assert await second.get_meta("schema_version") == str(SCHEMA_VERSION)
    finally:
        await second.close()


async def test_reopen_recovers_missing_schema_version(tmp_path: Path) -> None:
    path = tmp_path / "bot.session"
    store = SessionStore(path)
    await store.open()
    await store.set_meta("probe", "42")
    async with store._tx(write=True) as conn:
        await conn.execute("DELETE FROM meta WHERE key = 'schema_version'")
    await store.close()

    reopened = SessionStore(path)
    await reopened.open()
    try:
        assert await reopened.get_meta("schema_version") == str(SCHEMA_VERSION)
        assert await reopened.get_meta("probe") == "42"
    finally:
        await reopened.close()


async def test_operations_require_open_store(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    with pytest.raises(StoreNotOpenError):
        await store.get_meta("schema_version")


async def test_file_is_valid_sqlite(tmp_path: Path) -> None:
    path = tmp_path / "bot.session"
    store = SessionStore(path)
    await store.open()
    await store.close()
    with sqlite3.connect(path) as raw:
        assert raw.execute("SELECT count(*) FROM meta").fetchone()[0] >= 1
