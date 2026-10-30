"""SQLite-хранилище сессии: один файл на аккаунт."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sqlite3
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

import aiosqlite

from wapy.errors import StoreError, StoreNotOpenError

SCHEMA_VERSION = 1
MIGRATIONS_DIR = Path(__file__).parent / "migrations"

_PRAGMAS = (
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA busy_timeout=5000",
    "PRAGMA foreign_keys=ON",
)


def migration_files() -> list[tuple[int, Path]]:
    """Нумерованные миграции в порядке применения."""
    result: list[tuple[int, Path]] = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        prefix = path.name.split("_", 1)[0]
        try:
            number = int(prefix)
        except ValueError as exc:  # pragma: no cover - защита от кривого имени файла
            raise StoreError(f"Некорректное имя миграции: {path.name}") from exc
        result.append((number, path))
    return result


def ensure_private_file(path: Path) -> None:
    """Создать файл с правами 0600 или ужесточить права существующего."""
    if path.exists():
        path.chmod(0o600)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(fd)
    path.chmod(0o600)


class SessionStore:
    """Хранилище состояния одной сессии WhatsApp.

    Все операции сериализуются одним asyncio.Lock: SQLite имеет одного писателя,
    а общий lock заодно исключает чтение недокоммиченного состояния тем же соединением.
    """

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def _require_conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise StoreNotOpenError("SessionStore не открыт: вызовите await open()")
        return self._conn

    @contextlib.asynccontextmanager
    async def _tx(self, *, write: bool) -> AsyncIterator[aiosqlite.Connection]:
        """Транзакция под общим lock: коммит при выходе, откат при исключении."""
        conn = self._require_conn()
        async with self._lock:
            try:
                yield conn
            except BaseException:
                if write:
                    await conn.rollback()
                raise
            else:
                if write:
                    await conn.commit()

    async def open(self) -> None:
        if self._conn is not None:
            return
        ensure_private_file(self._path)
        conn = await aiosqlite.connect(self._path)
        conn.row_factory = sqlite3.Row
        for pragma in _PRAGMAS:
            await conn.execute(pragma)
        await conn.commit()
        self._conn = conn
        try:
            await self._migrate()
        except BaseException:
            await conn.close()
            self._conn = None
            raise

    async def close(self) -> None:
        if self._conn is None:
            return
        conn = self._conn
        self._conn = None
        await conn.close()

    async def __aenter__(self) -> SessionStore:
        await self.open()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    async def _migrate(self) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
        current_raw = await self.get_meta("schema_version")
        current = int(current_raw) if current_raw is not None else 0
        for number, path in migration_files():
            if number <= current:
                continue
            sql = path.read_text(encoding="utf-8")
            conn = self._require_conn()
            await conn.executescript(sql)
            await self.set_meta("schema_version", str(number))

    async def get_meta(self, key: str) -> str | None:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute("SELECT value FROM meta WHERE key = ?", (key,))
            row = await cursor.fetchone()
            await cursor.close()
        return None if row is None else str(row["value"])

    async def set_meta(self, key: str, value: str) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    async def load_creds(self) -> dict[str, Any] | None:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute("SELECT data FROM creds WHERE id = 1")
            row = await cursor.fetchone()
            await cursor.close()
        if row is None:
            return None
        decoded: dict[str, Any] = json.loads(bytes(row["data"]).decode("utf-8"))
        return decoded

    async def save_creds(self, creds: Mapping[str, Any]) -> None:
        payload = json.dumps(dict(creds), ensure_ascii=False).encode("utf-8")
        async with self._tx(write=True) as conn:
            await conn.execute(
                "INSERT INTO creds (id, data) VALUES (1, ?) "
                "ON CONFLICT(id) DO UPDATE SET data = excluded.data",
                (payload,),
            )

    async def clear_creds(self) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute("DELETE FROM creds WHERE id = 1")

    async def add_prekeys(self, prekeys: Iterable[tuple[int, bytes]]) -> None:
        rows = [(prekey_id, key_pair, 0) for prekey_id, key_pair in prekeys]
        if not rows:
            return
        async with self._tx(write=True) as conn:
            await conn.executemany(
                "INSERT INTO prekeys (id, key_pair, uploaded) VALUES (?, ?, ?)", rows
            )

    async def get_prekey(self, prekey_id: int) -> bytes | None:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute("SELECT key_pair FROM prekeys WHERE id = ?", (prekey_id,))
            row = await cursor.fetchone()
            await cursor.close()
        return None if row is None else bytes(row["key_pair"])

    async def consume_prekey(self, prekey_id: int) -> bytes | None:
        async with self._tx(write=True) as conn:
            cursor = await conn.execute("SELECT key_pair FROM prekeys WHERE id = ?", (prekey_id,))
            row = await cursor.fetchone()
            await cursor.close()
            if row is None:
                return None
            await conn.execute("DELETE FROM prekeys WHERE id = ?", (prekey_id,))
            return bytes(row["key_pair"])

    async def pending_prekeys(self) -> list[tuple[int, bytes]]:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute(
                "SELECT id, key_pair FROM prekeys WHERE uploaded = 0 ORDER BY id"
            )
            rows = await cursor.fetchall()
            await cursor.close()
        return [(int(row["id"]), bytes(row["key_pair"])) for row in rows]

    async def mark_prekeys_uploaded(self, ids: Sequence[int]) -> None:
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        async with self._tx(write=True) as conn:
            await conn.execute(
                f"UPDATE prekeys SET uploaded = 1 WHERE id IN ({placeholders})", tuple(ids)
            )

    async def count_available_prekeys(self) -> int:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute("SELECT count(*) AS n FROM prekeys WHERE uploaded = 1")
            row = await cursor.fetchone()
            await cursor.close()
        return 0 if row is None else int(row["n"])

    async def max_prekey_id(self) -> int | None:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute("SELECT max(id) AS n FROM prekeys")
            row = await cursor.fetchone()
            await cursor.close()
        if row is None or row["n"] is None:
            return None
        return int(row["n"])
