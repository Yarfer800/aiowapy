"""SQLite session store: one file per account."""

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

SCHEMA_VERSION = 4
MIGRATIONS_DIR = Path(__file__).parent / "migrations"

_PRAGMAS = (
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA busy_timeout=5000",
    "PRAGMA foreign_keys=ON",
)


def migration_files() -> list[tuple[int, Path]]:
    """Numbered migrations in application order."""
    result: list[tuple[int, Path]] = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        prefix = path.name.split("_", 1)[0]
        try:
            number = int(prefix)
        except ValueError as exc:  # pragma: no cover - guards against a malformed file name
            raise StoreError(f"Invalid migration file name: {path.name}") from exc
        result.append((number, path))
    return result


def ensure_private_file(path: Path) -> None:
    """Create the file with 0600 permissions or tighten an existing file."""
    if path.exists():
        path.chmod(0o600)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
    os.close(fd)
    path.chmod(0o600)


class SessionStore:
    """Storage for the state of a single WhatsApp session.

    All operations are serialized by a single asyncio.Lock: SQLite allows one writer,
    and the shared lock also prevents reading uncommitted state over the same connection.
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
            raise StoreNotOpenError("SessionStore is not open: call await open()")
        return self._conn

    @contextlib.asynccontextmanager
    async def _tx(self, *, write: bool) -> AsyncIterator[aiosqlite.Connection]:
        """Transaction under the shared lock: commit on exit, rollback on exception."""
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

    async def get_session(self, jid: str) -> bytes | None:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute("SELECT record FROM sessions WHERE jid = ?", (jid,))
            row = await cursor.fetchone()
            await cursor.close()
        return None if row is None else bytes(row["record"])

    async def put_session(self, jid: str, record: bytes) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute(
                "INSERT INTO sessions (jid, record) VALUES (?, ?) "
                "ON CONFLICT(jid) DO UPDATE SET record = excluded.record",
                (jid, record),
            )

    async def delete_session(self, jid: str) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute("DELETE FROM sessions WHERE jid = ?", (jid,))

    async def delete_sessions_for_user(self, user: str) -> None:
        """Drop every device session of one account, e.g. after a retry request."""
        async with self._tx(write=True) as conn:
            await conn.execute("DELETE FROM sessions WHERE jid LIKE ?", (f"{user}:%",))
            await conn.execute("DELETE FROM sessions WHERE jid = ?", (user,))

    async def get_identity(self, jid: str) -> bytes | None:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute("SELECT key FROM identity_keys WHERE jid = ?", (jid,))
            row = await cursor.fetchone()
            await cursor.close()
        return None if row is None else bytes(row["key"])

    async def put_identity(self, jid: str, key: bytes, trust: str = "trusted") -> None:
        async with self._tx(write=True) as conn:
            await conn.execute(
                "INSERT INTO identity_keys (jid, key, trust) VALUES (?, ?, ?) "
                "ON CONFLICT(jid) DO UPDATE SET key = excluded.key, trust = excluded.trust",
                (jid, key, trust),
            )

    async def get_sender_key(self, group_jid: str, sender: str) -> bytes | None:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute(
                "SELECT record FROM sender_keys WHERE group_jid = ? AND sender = ?",
                (group_jid, sender),
            )
            row = await cursor.fetchone()
            await cursor.close()
        return None if row is None else bytes(row["record"])

    async def put_sender_key(self, group_jid: str, sender: str, record: bytes) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute(
                "INSERT INTO sender_keys (group_jid, sender, record) VALUES (?, ?, ?) "
                "ON CONFLICT(group_jid, sender) DO UPDATE SET record = excluded.record",
                (group_jid, sender, record),
            )

    async def delete_sender_key(self, group_jid: str, sender: str) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute(
                "DELETE FROM sender_keys WHERE group_jid = ? AND sender = ?",
                (group_jid, sender),
            )

    async def delete_sender_keys_for_group(self, group_jid: str) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute("DELETE FROM sender_keys WHERE group_jid = ?", (group_jid,))

    async def get_group(self, jid: str) -> tuple[bytes, float] | None:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute("SELECT record, fetched FROM groups WHERE jid = ?", (jid,))
            row = await cursor.fetchone()
            await cursor.close()
        if row is None:
            return None
        return bytes(row["record"]), float(row["fetched"])

    async def put_group(self, jid: str, record: bytes, fetched: float) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute(
                "INSERT INTO groups (jid, record, fetched) VALUES (?, ?, ?) "
                "ON CONFLICT(jid) DO UPDATE SET record = excluded.record, "
                "fetched = excluded.fetched",
                (jid, record, fetched),
            )

    # -- peers: users and groups we have seen ---------------------------------

    async def upsert_peer(
        self,
        jid: str,
        kind: str,
        *,
        phone: str | None = None,
        push_name: str | None = None,
        contact_name: str | None = None,
        subject: str | None = None,
    ) -> None:
        """Insert or refine a peer; existing values are never wiped by a None."""
        async with self._tx(write=True) as conn:
            await conn.execute(
                "INSERT INTO peers (jid, kind, phone, push_name, contact_name, subject) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(jid) DO UPDATE SET "
                "kind = excluded.kind, "
                "phone = COALESCE(excluded.phone, peers.phone), "
                "push_name = COALESCE(excluded.push_name, peers.push_name), "
                "contact_name = COALESCE(excluded.contact_name, peers.contact_name), "
                "subject = COALESCE(excluded.subject, peers.subject), "
                "last_update_on = CAST(STRFTIME('%s', 'now') AS INTEGER)",
                (jid, kind, phone, push_name, contact_name, subject),
            )

    async def get_peer(self, jid: str) -> dict[str, Any] | None:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute("SELECT * FROM peers WHERE jid = ?", (jid,))
            row = await cursor.fetchone()
            await cursor.close()
        return None if row is None else dict(row)

    async def list_peers(self, kind: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM peers"
        params: tuple[object, ...] = ()
        if kind is not None:
            query += " WHERE kind = ?"
            params = (kind,)
        query += " ORDER BY last_update_on DESC, jid"
        async with self._tx(write=False) as conn:
            cursor = await conn.execute(query, params)
            rows = await cursor.fetchall()
            await cursor.close()
        return [dict(row) for row in rows]

    async def delete_peer(self, jid: str) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute("DELETE FROM peers WHERE jid = ?", (jid,))

    # -- messages ------------------------------------------------------------

    async def save_message(
        self,
        chat_jid: str,
        message_id: str,
        *,
        sender_jid: str | None = None,
        timestamp: int | None = None,
        text: str | None = None,
        media_json: str | None = None,
        outgoing: bool = False,
    ) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute(
                "INSERT INTO messages "
                "(chat_jid, message_id, sender_jid, timestamp, text, media_json, outgoing) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(chat_jid, message_id) DO UPDATE SET "
                "sender_jid = COALESCE(excluded.sender_jid, messages.sender_jid), "
                "timestamp = COALESCE(excluded.timestamp, messages.timestamp), "
                "text = COALESCE(excluded.text, messages.text), "
                "media_json = COALESCE(excluded.media_json, messages.media_json), "
                "outgoing = excluded.outgoing",
                (chat_jid, message_id, sender_jid, timestamp, text, media_json, int(outgoing)),
            )

    async def get_message(self, chat_jid: str, message_id: str) -> dict[str, Any] | None:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute(
                "SELECT * FROM messages WHERE chat_jid = ? AND message_id = ?",
                (chat_jid, message_id),
            )
            row = await cursor.fetchone()
            await cursor.close()
        return None if row is None else dict(row)

    async def get_messages(
        self, chat_jid: str, *, limit: int = 100, before_timestamp: int | None = None
    ) -> list[dict[str, Any]]:
        """Newest first; `before_timestamp` walks towards older messages."""
        query = "SELECT * FROM messages WHERE chat_jid = ?"
        params: list[object] = [chat_jid]
        if before_timestamp is not None:
            query += " AND timestamp < ?"
            params.append(before_timestamp)
        query += " ORDER BY timestamp DESC, message_id DESC LIMIT ?"
        params.append(limit)
        async with self._tx(write=False) as conn:
            cursor = await conn.execute(query, tuple(params))
            rows = await cursor.fetchall()
            await cursor.close()
        return [dict(row) for row in rows]

    async def list_chats(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Peers that have messages, newest conversation first."""
        async with self._tx(write=False) as conn:
            cursor = await conn.execute(
                "SELECT p.*, MAX(m.timestamp) AS last_message_at, COUNT(m.message_id) AS total "
                "FROM peers p LEFT JOIN messages m ON m.chat_jid = p.jid "
                "GROUP BY p.jid ORDER BY last_message_at DESC NULLS LAST, p.jid LIMIT ?",
                (limit,),
            )
            rows = await cursor.fetchall()
            await cursor.close()
        return [dict(row) for row in rows]

    async def delete_messages(self, chat_jid: str) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute("DELETE FROM messages WHERE chat_jid = ?", (chat_jid,))

    async def delete_group(self, jid: str) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute("DELETE FROM groups WHERE jid = ?", (jid,))

    async def get_app_state_key(self, key_id: bytes) -> bytes | None:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute(
                "SELECT key_data FROM app_state_keys WHERE key_id = ?", (key_id,)
            )
            row = await cursor.fetchone()
            await cursor.close()
        return None if row is None else bytes(row["key_data"])

    async def put_app_state_key(self, key_id: bytes, key_data: bytes) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute(
                "INSERT INTO app_state_keys (key_id, key_data) VALUES (?, ?) "
                "ON CONFLICT(key_id) DO UPDATE SET key_data = excluded.key_data",
                (key_id, key_data),
            )

    async def get_app_state_version(self, name: str) -> tuple[int, bytes] | None:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute(
                "SELECT version, hash FROM app_state_ver WHERE name = ?", (name,)
            )
            row = await cursor.fetchone()
            await cursor.close()
        if row is None:
            return None
        return int(row["version"]), bytes(row["hash"])

    async def latest_app_state_key_id(self) -> bytes | None:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute(
                "SELECT key_id FROM app_state_keys ORDER BY rowid DESC LIMIT 1"
            )
            row = await cursor.fetchone()
            await cursor.close()
        return None if row is None else bytes(row["key_id"])

    async def put_app_state(
        self, collection: str, index_json: str, value: bytes, timestamp: int, value_mac: bytes
    ) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute(
                "INSERT INTO app_state_data (collection, index_json, value, timestamp, value_mac) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(collection, index_json) DO UPDATE SET value = excluded.value, "
                "timestamp = excluded.timestamp, value_mac = excluded.value_mac",
                (collection, index_json, value, timestamp, value_mac),
            )

    async def delete_app_state(self, collection: str, index_json: str) -> bytes | None:
        async with self._tx(write=True) as conn:
            cursor = await conn.execute(
                "SELECT value_mac FROM app_state_data WHERE collection = ? AND index_json = ?",
                (collection, index_json),
            )
            row = await cursor.fetchone()
            await cursor.close()
            if row is None:
                return None
            await conn.execute(
                "DELETE FROM app_state_data WHERE collection = ? AND index_json = ?",
                (collection, index_json),
            )
            return bytes(row["value_mac"])

    async def list_app_state(self, collection: str) -> list[tuple[str, bytes, int]]:
        async with self._tx(write=False) as conn:
            cursor = await conn.execute(
                "SELECT index_json, value, timestamp FROM app_state_data "
                "WHERE collection = ? ORDER BY timestamp",
                (collection,),
            )
            rows = await cursor.fetchall()
            await cursor.close()
        return [
            (str(row["index_json"]), bytes(row["value"]), int(row["timestamp"])) for row in rows
        ]

    async def set_app_state_version(self, name: str, version: int, digest: bytes) -> None:
        async with self._tx(write=True) as conn:
            await conn.execute(
                "INSERT INTO app_state_ver (name, version, hash) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET version = excluded.version, "
                "hash = excluded.hash",
                (name, version, digest),
            )
