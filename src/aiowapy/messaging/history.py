from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from aiowapy.errors import WapyError
from aiowapy.messaging.media import MediaStorage
from aiowapy.models import KIND_GROUP, KIND_USER, media_to_dict
from aiowapy.protocol.history import (
    HistoryError,
    HistorySync,
    HistorySyncNotification,
    parse_history_sync,
    parse_notification,
)
from aiowapy.store import SessionStore

logger = logging.getLogger("aiowapy")


class HistorySyncError(WapyError):
    """A history sync chunk cannot be stored."""


@dataclass(frozen=True, slots=True)
class HistorySyncResult:
    sync_type: int
    chats: int
    messages: int
    push_names: int
    chunk_order: int
    has_more: bool


class HistorySyncService:
    """Downloads history chunks and writes them into the session file.

    WhatsApp sends history as encrypted, gzipped protobuf blobs announced by a
    protocol message. This service turns one announcement into rows: peers with
    names, and messages attached to their chat.
    """

    def __init__(
        self,
        media: MediaStorage,
        store: SessionStore,
        *,
        on_chunk: Callable[[HistorySync], None] | None = None,
    ) -> None:
        self._media = media
        self._store = store
        self._on_chunk = on_chunk
        self._seen: set[str] = set()

    async def handle(self, notification: HistorySyncNotification) -> HistorySyncResult:
        if notification.inline_payload:
            blob = notification.inline_payload
        else:
            if not notification.media_key:
                raise HistorySyncError("history notification has no media key")
            blob = await self._media.download(notification.media)
        try:
            history = parse_history_sync(blob)
        except HistoryError as exc:
            raise HistorySyncError(str(exc)) from exc

        await self._store_chats(history)
        for jid, name in history.push_names.items():
            await self._store.upsert_peer(jid, _kind(jid), push_name=name)
        for pn_jid, lid_jid in history.lid_mappings.items():
            await self._store.put_lid_mapping(pn_jid, lid_jid)

        if self._on_chunk is not None:
            self._on_chunk(history)
        logger.info(
            "history sync %s: %d chats, %d messages (chunk %d)",
            history.sync_type,
            len(history.conversations),
            history.message_count,
            history.chunk_order,
        )
        return HistorySyncResult(
            sync_type=history.sync_type,
            chats=len(history.conversations),
            messages=history.message_count,
            push_names=len(history.push_names),
            chunk_order=history.chunk_order,
            has_more=history.progress < 100,
        )

    async def handle_raw(self, raw_notification: bytes) -> HistorySyncResult:
        return await self.handle(parse_notification(raw_notification))

    async def _store_chats(self, history: HistorySync) -> None:
        for chat in history.conversations:
            await self._store.upsert_peer(chat.jid, _kind(chat.jid), subject=chat.name)
            for message in chat.messages:
                key = f"{message.chat_jid}|{message.message_id}"
                if key in self._seen:
                    continue
                self._seen.add(key)
                await self._store.save_message(
                    message.chat_jid,
                    message.message_id,
                    sender_jid=message.sender_jid,
                    timestamp=message.timestamp,
                    text=message.text,
                    media_json=(
                        _json(media_to_dict(message.media)) if message.media is not None else None
                    ),
                    outgoing=message.outgoing,
                )


def _kind(jid: str) -> str:
    return KIND_GROUP if jid.endswith("@g.us") else KIND_USER


def _json(data: dict[str, object]) -> str:
    import json

    return json.dumps(data)
