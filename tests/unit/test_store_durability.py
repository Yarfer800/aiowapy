"""Guarantees from spec section 5: commit before return, atomicity, single writer."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest

from wapy.store import SessionStore

ALICE = "491111111111.0:0@s.whatsapp.net"


async def test_put_session_is_committed_before_return(tmp_path: Path) -> None:
    """Write-ahead rule: once the call returns, another connection sees the write."""
    path = tmp_path / "bot.session"
    store = SessionStore(path)
    await store.open()
    try:
        await store.put_session(ALICE, b"ratchet-state")
        with sqlite3.connect(path) as raw:
            row = raw.execute("SELECT record FROM sessions WHERE jid = ?", (ALICE,)).fetchone()
        assert row is not None
        assert bytes(row[0]) == b"ratchet-state"
    finally:
        await store.close()


async def test_failed_transaction_rolls_back_all_statements(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        with pytest.raises(sqlite3.IntegrityError):
            async with store._tx(write=True) as conn:
                await conn.execute("INSERT INTO meta (key, value) VALUES ('probe', '1')")
                await conn.execute("INSERT INTO meta (key, value) VALUES ('probe', '2')")
        assert await store.get_meta("probe") is None
    finally:
        await store.close()


async def test_concurrent_writes_do_not_fail_or_lose_data(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        await asyncio.gather(
            *(
                store.put_session(f"49111111{i:04d}@s.whatsapp.net", f"rec-{i}".encode())
                for i in range(50)
            )
        )
        for i in range(50):
            jid = f"49111111{i:04d}@s.whatsapp.net"
            assert await store.get_session(jid) == f"rec-{i}".encode()
    finally:
        await store.close()


async def test_consume_prekey_is_atomic_under_concurrency(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        await store.add_prekeys([(1, b"only-one")])
        results = await asyncio.gather(*(store.consume_prekey(1) for _ in range(10)))
        assert [r for r in results if r is not None] == [b"only-one"]
    finally:
        await store.close()


async def test_second_client_can_open_same_file(tmp_path: Path) -> None:
    """WAL lets another connection open the same file and read the data."""
    path = tmp_path / "bot.session"
    first = SessionStore(path)
    await first.open()
    try:
        await first.put_session(ALICE, b"state")
        second = SessionStore(path)
        await second.open()
        try:
            assert await second.get_session(ALICE) == b"state"
        finally:
            await second.close()
    finally:
        await first.close()


async def test_close_is_idempotent(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    await store.close()
    await store.close()
