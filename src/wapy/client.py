from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from wapy.creds import DeviceCredentials, generate_credentials
from wapy.crypto.primitives import generate_keypair
from wapy.errors import WapyError
from wapy.events import (
    AnyEvent,
    ChatStateEvent,
    ConnectedEvent,
    DisconnectedEvent,
    EditEvent,
    HistorySyncEvent,
    MessageEvent,
    NotificationEvent,
    PresenceEvent,
    ReactionEvent,
    ReceiptEvent,
    RevokeEvent,
)
from wapy.messaging.appstate import AppStateSync, SyncedCollection
from wapy.messaging.devices import CachedDeviceResolver
from wapy.messaging.groups import GroupSender, GroupService, StoreSenderKeys
from wapy.messaging.history import HistorySyncService
from wapy.messaging.media import MediaStorage, MediaTransport, UrllibMediaTransport
from wapy.messaging.messenger import Messenger, SendResult
from wapy.messaging.real import (
    StoreSignalSessionsWithDecrypt,
    StreamNodeSender,
    UsyncDeviceFetcher,
)
from wapy.messaging.receiving import (
    DecryptError,
    MessageReceiver,
    ReceivedMessage,
    ReceiveError,
)
from wapy.models import (
    KIND_GROUP,
    KIND_USER,
    Peer,
    StoredMessage,
    media_from_dict,
    media_to_dict,
)
from wapy.protocol.groups import GroupInfo, GroupParticipant
from wapy.protocol.media import (
    MEDIA_AUDIO,
    MEDIA_DOCUMENT,
    MEDIA_IMAGE,
    MEDIA_PTT,
    MEDIA_VIDEO,
    MediaInfo,
)
from wapy.protocol.messages import (
    QuoteRef,
    encode_edit,
    encode_media,
    encode_reaction,
    encode_revoke,
)
from wapy.protocol.prekeys import pack_key_pair
from wapy.protocol.presence import (
    PRESENCE_AVAILABLE,
    PRESENCE_UNAVAILABLE,
    build_chat_state,
    build_presence,
    build_subscribe,
    parse_chat_state,
    parse_presence,
)
from wapy.protocol.receipts import (
    MAX_RETRY_COUNT,
    RECEIPT_DELIVERY,
    RECEIPT_READ,
    RECEIPT_RETRY,
    build_receipt,
    build_retry_receipt,
    parse_receipt,
)
from wapy.protocol.stream import NodeStream, child
from wapy.protocol.transport import WhatsAppTransport
from wapy.protocol.wabinary import Node
from wapy.router import Router
from wapy.session import (
    DEFAULT_VERSION,
    ClientSession,
    LoggedOutError,
    SessionError,
    SessionState,
    Transport,
    new_message_id,
)
from wapy.store import SessionStore

logger = logging.getLogger("wapy")

DEFAULT_ACK_TIMEOUT = 5.0
DEFAULT_PUSH_NAME = "wapy"
KEEPALIVE_INTERVAL = 30.0
KEEPALIVE_TIMEOUT = 35.0
MAX_RECONNECT_DELAY = 30.0
MAX_TRACKED_RETRIES = 512
OUTBOX_LIMIT = 256
LOGGED_OUT_CODES = {401, 403, 409}


class ClientError(WapyError):
    """The client cannot be started or is in the wrong state."""


@dataclass(frozen=True, slots=True)
class ClientInfo:
    jid: str
    lid: str | None
    push_name: str


@dataclass(frozen=True, slots=True)
class OutgoingMessage:
    """What we remember about a sent message so a retry request can resend it."""

    chat_jid: str
    payload: bytes


class WhatsAppClient:
    """A connected WhatsApp session.

    Usage:

        client = WhatsAppClient("bot.session", qr_callback=show_qr)
        await client.connect()
        await client.send_text("4917...@s.whatsapp.net", "hi")
        await client.run()          # serves until closed
    """

    def __init__(
        self,
        path: Path | str,
        *,
        transport_factory: Callable[[], Transport] | None = None,
        qr_callback: Callable[[object], Awaitable[None] | None] | None = None,
        push_name: str = DEFAULT_PUSH_NAME,
        platform: str = "chrome",
        version: tuple[int, int, int] = DEFAULT_VERSION,
        ack_timeout: float = DEFAULT_ACK_TIMEOUT,
        auto_receipts: bool = True,
        media_transport: MediaTransport | None = None,
        node_observer: Callable[[Node], None] | None = None,
        sent_observer: Callable[[Node], None] | None = None,
        reconnect: bool = True,
        reconnect_delay: float = 1.0,
        max_reconnect_delay: float = MAX_RECONNECT_DELAY,
    ) -> None:
        self.router = Router()
        self.push_name = push_name
        self._path = Path(path)
        self._factory = transport_factory or (lambda: WhatsAppTransport())
        self._qr_callback = qr_callback
        self._platform = platform
        self._version = version
        self._ack_timeout = ack_timeout
        self._auto_receipts = auto_receipts
        self._observer = node_observer
        self._sent_observer = sent_observer
        self._reconnect = reconnect
        self._reconnect_delay = reconnect_delay
        self._max_reconnect_delay = max_reconnect_delay

        self._store: SessionStore | None = None
        self._stream: NodeStream | None = None
        self._credentials: DeviceCredentials | None = None
        self._messenger: Messenger | None = None
        self._receiver: MessageReceiver | None = None
        self._groups: GroupService | None = None
        self._group_sender: GroupSender | None = None
        self._sender_keys: StoreSenderKeys | None = None
        self._media: MediaStorage | None = None
        self._app_state: AppStateSync | None = None
        self._history: HistorySyncService | None = None
        self._media_transport: MediaTransport = media_transport or UrllibMediaTransport()
        self._session: ClientSession | None = None

        self._ready = asyncio.Event()
        self._done = asyncio.Event()
        self._closed = False
        self._stop_reconnect = False
        self._last_error: str | None = None
        self._runner: asyncio.Task[None] | None = None
        self._worker: asyncio.Task[None] | None = None
        self._keepalive: asyncio.Task[None] | None = None
        self._queue: asyncio.Queue[Node] = asyncio.Queue()

        self._outbox: OrderedDict[str, OutgoingMessage] = OrderedDict()
        self._incoming_retries: dict[str, int] = {}

        self.info: ClientInfo | None = None

    # ------------------------------------------------------------------ lifecycle

    @property
    def connected(self) -> bool:
        return self._stream is not None and not self._stream.closed

    async def connect(self) -> ClientInfo:
        """Log in (pairing first if the session file is new) and start serving.

        Returns as soon as the server accepts the login payload. Pairing through a QR
        code calls `qr_callback` from the connection task while this method waits.
        """
        if self._runner is not None:
            raise ClientError("the client is already connected")
        self._store = SessionStore(self._path)
        await self._store.open()
        raw = await self._store.load_creds()
        if raw is None:
            await self._store.save_creds(generate_credentials().to_dict())

        self._closed = False
        self._stop_reconnect = False
        self._done.clear()
        self._runner = asyncio.create_task(self._connection_loop(), name="wapy-connect")
        ready = asyncio.create_task(self._ready.wait(), name="wapy-ready")
        done, _pending = await asyncio.wait(
            {ready, self._runner}, return_when=asyncio.FIRST_COMPLETED
        )
        if ready in done:
            ready.cancel()
            info = self.info
            if info is None:  # pragma: no cover - ready implies info
                raise ClientError("connected without client info")
            return info
        ready.cancel()
        error = self._runner.exception() if self._runner.done() else None
        await self._shutdown()
        if isinstance(error, SessionError):
            raise error
        raise ClientError(f"could not connect: {error or 'unknown reason'}")

    async def run(self) -> None:
        """Connect and then serve until `close()` is called."""
        if self._runner is None:
            await self.connect()
        await self._done.wait()

    async def close(self) -> None:
        """Stop serving and release the session file."""
        self._closed = True
        stream = self._stream
        if stream is not None:
            # Close from a separate task: this handler runs inside the dispatch
            # worker, and that worker is cancelled as part of the shutdown.
            asyncio.get_running_loop().create_task(stream.close(), name="wapy-close")
        await self._shutdown()

    async def __aenter__(self) -> WhatsAppClient:
        await self.connect()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    async def _shutdown(self) -> None:
        for task in (self._runner, self._worker, self._keepalive):
            if task is not None and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        self._runner = self._worker = self._keepalive = None
        self._ready.clear()
        store, self._store = self._store, None
        if store is not None:
            await store.close()
        self._stream = None
        self._done.set()

    async def _connection_loop(self) -> None:
        delay = self._reconnect_delay
        while not self._closed:
            reason = "connection closed"
            try:
                self._session = ClientSession(
                    self._path,
                    transport_factory=self._factory,
                    qr_callback=self._qr_callback,
                    node_observer=self._observer,
                    sent_observer=self._sent_observer,
                    platform=self._platform,
                    version=self._version,
                    store=self._store,
                    on_connected=self._serve_connected,
                    reauthenticate=False,
                )
                await self._session.run()
            except LoggedOutError as exc:
                reason = str(exc)
                await self.router.dispatch(DisconnectedEvent(reason=reason))
                break
            except asyncio.CancelledError:
                raise
            except SessionError as exc:
                reason = str(exc)
            except Exception as exc:  # a broken transport must not kill the task
                logger.exception("connection attempt failed")
                reason = f"{type(exc).__name__}: {exc}"
            finally:
                self._ready.clear()
                self._stream = None
                self.info = None
                if self._last_error is not None:
                    reason = self._last_error
                    self._last_error = None
            await self.router.dispatch(DisconnectedEvent(reason=reason))
            if self._closed or self._stop_reconnect or not self._reconnect:
                break
            logger.info("reconnecting in %.0fs: %s", delay, reason)
            await asyncio.sleep(delay)
            delay = min(delay * 2, self._max_reconnect_delay)
        if not self._closed:
            self._done.set()

    async def _serve_connected(self, transport: Transport, state: SessionState) -> None:
        """Runs while the connection is up; `ClientSession` awaits this to completion."""
        stream = NodeStream(transport)
        await stream.start()
        self._stream = stream
        self._credentials = state.credentials
        self._messenger = self._build_messenger(stream, state)
        if self._store is None:  # pragma: no cover - guarded by connect()
            raise ClientError("the session file is not open")
        self._sender_keys = StoreSenderKeys(self._store, state.jid or "")
        self._groups = GroupService(stream, self._store)
        self._media = MediaStorage(stream, self._media_transport)
        self._app_state = AppStateSync(stream, self._store)
        self._history = HistorySyncService(self._media, self._store)
        self._group_sender = GroupSender(
            StreamNodeSender(stream),
            self._build_resolver(stream, state),
            StoreSignalSessionsWithDecrypt(self._store, state.credentials),
            self._sender_keys,
            self._groups,
            device_identity=state.credentials.device_identity,
            ack_timeout=self._ack_timeout,
        )
        self._receiver = MessageReceiver(
            StoreSignalSessionsWithDecrypt(self._store, state.credentials),
            self._sender_keys,
        )
        self.info = ClientInfo(jid=state.jid or "", lid=state.lid, push_name=self.push_name)
        stream.on_node(self._enqueue)
        self._worker = asyncio.create_task(self._process_loop(), name="wapy-dispatch")
        self._keepalive = asyncio.create_task(self._keepalive_loop(stream), name="wapy-keepalive")
        self._ready.set()
        await self.router.dispatch(ConnectedEvent(jid=self.info.jid, lid=state.lid))
        try:
            await self._announce_presence()
            await stream.wait_closed()
        finally:
            await self._stop_tasks(self._worker, self._keepalive)
            self._worker = self._keepalive = None
            self._ready.clear()

    def _build_resolver(self, stream: NodeStream, state: SessionState) -> CachedDeviceResolver:
        fetcher = UsyncDeviceFetcher(stream, state.credentials, own_jid=state.jid)
        return CachedDeviceResolver(fetcher)

    def _build_messenger(self, stream: NodeStream, state: SessionState) -> Messenger:
        assert self._store is not None
        return Messenger(
            StreamNodeSender(stream),
            self._build_resolver(stream, state),
            StoreSignalSessionsWithDecrypt(self._store, state.credentials),
            own_jid=state.jid,
            device_identity=state.credentials.device_identity,
            ack_timeout=self._ack_timeout,
        )

    @staticmethod
    async def _stop_tasks(*tasks: asyncio.Task[None] | None) -> None:
        """Cancel helper tasks, never the caller and never twice."""
        current = asyncio.current_task()
        for task in tasks:
            if task is None or task is current or task.done():
                continue
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    async def _keepalive_loop(self, stream: NodeStream) -> None:
        while not stream.closed:
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            if time.monotonic() - stream.last_activity > KEEPALIVE_TIMEOUT:
                logger.info("no traffic for %.0fs, reconnecting", KEEPALIVE_TIMEOUT)
                await stream.close()
                return
            await stream.send(
                Node(
                    tag="iq",
                    attrs={
                        "id": new_message_id(),
                        "to": "@s.whatsapp.net",
                        "type": "get",
                        "xmlns": "w:p",
                    },
                    content=[Node(tag="ping", attrs={})],
                )
            )

    async def _announce_presence(self) -> None:
        """Mark ourselves available: without it, contacts see no name."""
        await self._require_stream().send(
            build_presence(PRESENCE_AVAILABLE, push_name=self.push_name)
        )

    # ------------------------------------------------------------------- outgoing

    async def send_text(
        self,
        jid: str,
        text: str,
        *,
        quote: str | None = None,
        wait_for_message: bool = True,
    ) -> SendResult:
        """Send text; `quote` is the id of a message to reply to."""
        if not text:
            raise ClientError("text must not be empty")
        payload = _encode_text_payload(text)
        if quote is not None:
            payload = _encode_text_payload(text, await self._quote_ref(jid, quote))
        return await self._deliver(
            jid,
            payload,
            message_type="text",
            wait_for_message=wait_for_message,
        )

    async def _quote_ref(self, chat_jid: str, message_id: str) -> QuoteRef:
        stored = await self.get_message(chat_jid, message_id)
        if stored is None:
            return QuoteRef(chat_jid=chat_jid, message_id=message_id, sender_jid=chat_jid)
        return QuoteRef(
            chat_jid=chat_jid,
            message_id=message_id,
            sender_jid=stored.sender_jid or chat_jid,
            text=stored.text,
        )

    async def send_reaction(
        self,
        chat_jid: str,
        message_id: str,
        text: str,
        *,
        sender_jid: str | None = None,
        wait_for_message: bool = False,
    ) -> SendResult:
        """React with an emoji; pass an empty string to remove your reaction."""
        payload = encode_reaction(
            chat_jid,
            message_id,
            text,
            sender_jid=sender_jid if chat_jid.endswith("@g.us") else None,
            timestamp_ms=int(time.time() * 1000),
        )
        return await self._deliver(
            chat_jid,
            payload,
            message_type="reaction",
            wait_for_message=wait_for_message,
        )

    async def edit_message(
        self, chat_jid: str, message_id: str, text: str, *, wait_for_message: bool = True
    ) -> SendResult:
        if not text:
            raise ClientError("text must not be empty")
        return await self._deliver(
            chat_jid,
            encode_edit(chat_jid, message_id, text),
            message_type="text",
            wait_for_message=wait_for_message,
        )

    async def revoke_message(
        self, chat_jid: str, message_id: str, *, wait_for_message: bool = True
    ) -> SendResult:
        return await self._deliver(
            chat_jid,
            encode_revoke(chat_jid, message_id),
            message_type="text",
            wait_for_message=wait_for_message,
        )

    async def reactions(self, chat_jid: str, message_id: str) -> list[tuple[str, str]]:
        rows = await self._require_store().list_reactions(chat_jid, message_id)
        return [(str(row["sender_jid"]), str(row["text"])) for row in rows]

    async def send_group_text(
        self, group_jid: str, text: str, *, wait_for_message: bool = True
    ) -> SendResult:
        if not text:
            raise ClientError("text must not be empty")
        return await self._deliver(
            group_jid,
            _encode_text_payload(text),
            message_type="text",
            wait_for_message=wait_for_message,
        )

    async def send_media(
        self,
        jid: str,
        data: bytes,
        media_type: str,
        *,
        caption: str | None = None,
        file_name: str | None = None,
        mime_type: str | None = None,
        seconds: int | None = None,
        width: int | None = None,
        height: int | None = None,
        wait_for_message: bool = True,
    ) -> SendResult:
        """Encrypt, upload and send an attachment (image, video, audio or document)."""
        info = await self._require_media().upload(
            data,
            media_type,
            caption=caption,
            file_name=file_name,
            mime_type=mime_type or default_mime_type(media_type),
            seconds=seconds,
            width=width,
            height=height,
        )
        return await self._deliver(
            jid,
            encode_media(info),
            message_type=media_type,
            wait_for_message=wait_for_message,
        )

    async def send_image(
        self,
        jid: str,
        data: bytes,
        *,
        caption: str | None = None,
        mime_type: str | None = None,
        wait_for_message: bool = True,
    ) -> SendResult:
        return await self.send_media(
            jid,
            data,
            MEDIA_IMAGE,
            caption=caption,
            mime_type=mime_type,
            wait_for_message=wait_for_message,
        )

    async def send_video(
        self,
        jid: str,
        data: bytes,
        *,
        caption: str | None = None,
        seconds: int | None = None,
        mime_type: str | None = None,
        wait_for_message: bool = True,
    ) -> SendResult:
        return await self.send_media(
            jid,
            data,
            MEDIA_VIDEO,
            caption=caption,
            seconds=seconds,
            mime_type=mime_type,
            wait_for_message=wait_for_message,
        )

    async def send_audio(
        self,
        jid: str,
        data: bytes,
        *,
        voice_note: bool = False,
        seconds: int | None = None,
        mime_type: str | None = None,
        wait_for_message: bool = True,
    ) -> SendResult:
        media_type = MEDIA_PTT if voice_note else MEDIA_AUDIO
        return await self.send_media(
            jid,
            data,
            media_type,
            seconds=seconds,
            mime_type=mime_type,
            wait_for_message=wait_for_message,
        )

    async def send_document(
        self,
        jid: str,
        data: bytes,
        *,
        file_name: str,
        mime_type: str = "application/octet-stream",
        caption: str | None = None,
        wait_for_message: bool = True,
    ) -> SendResult:
        return await self.send_media(
            jid,
            data,
            MEDIA_DOCUMENT,
            file_name=file_name,
            mime_type=mime_type,
            caption=caption,
            wait_for_message=wait_for_message,
        )

    async def download_media(self, media: MediaInfo) -> bytes:
        """Fetch and decrypt an attachment announced by a `MessageEvent`."""
        return await self._require_media().download(media)

    # ------------------------------------------------------------------- app state

    async def sync_app_state(self) -> list[SyncedCollection]:
        """Pull app state patches (contacts, mutes, pins, ...) for every collection.

        Requires sync keys, which WhatsApp shares from the phone; without them the
        call raises and the local copy stays as it is.
        """
        if self._app_state is None:
            raise ClientError("the client is not connected")
        return await self._app_state.sync_all()

    async def app_state_entries(self, collection: str) -> list[tuple[str, bytes, int]]:
        if self._app_state is None:
            raise ClientError("the client is not connected")
        return await self._app_state.entries(collection)

    async def mute_chat(self, chat_jid: str, muted: bool) -> int:
        return await self._require_app_state().mute(chat_jid, muted)

    async def pin_chat(self, chat_jid: str, pinned: bool) -> int:
        return await self._require_app_state().pin(chat_jid, pinned)

    async def mark_chat_read(self, chat_jid: str, read: bool = True) -> int:
        return await self._require_app_state().mark_chat_read(chat_jid, read)

    async def set_push_name(self, name: str) -> int:
        return await self._require_app_state().set_push_name(name)

    # ------------------------------------------------------------------ storage

    async def save_message(
        self,
        chat_jid: str,
        message_id: str,
        text: str | None = None,
        *,
        sender_jid: str | None = None,
        timestamp: int | None = None,
        media: MediaInfo | None = None,
        outgoing: bool = False,
    ) -> None:
        """Record a message in the session file (useful for history imported from elsewhere)."""
        await self._require_store().save_message(
            chat_jid,
            message_id,
            sender_jid=sender_jid,
            timestamp=timestamp,
            text=text,
            media_json=json.dumps(media_to_dict(media)) if media is not None else None,
            outgoing=outgoing,
        )

    async def get_chat_history(
        self, chat_jid: str, limit: int = 100, *, before_timestamp: int | None = None
    ) -> list[StoredMessage]:
        """Messages of one chat from the session file, newest first."""
        rows = await self._require_store().get_messages(
            chat_jid, limit=limit, before_timestamp=before_timestamp
        )
        return [self._stored_message(row) for row in rows]

    async def get_message(self, chat_jid: str, message_id: str) -> StoredMessage | None:
        row = await self._require_store().get_message(chat_jid, message_id)
        return None if row is None else self._stored_message(row)

    async def get_chats(self, limit: int = 100) -> list[Peer]:
        rows = await self._require_store().list_chats(limit=limit)
        return [self._peer(row) for row in rows]

    async def get_users(self, limit: int = 1000) -> list[Peer]:
        rows = await self._require_store().list_peers(KIND_USER)
        return [self._peer(row) for row in rows[:limit]]

    async def get_groups(self, limit: int = 1000) -> list[Peer]:
        rows = await self._require_store().list_peers(KIND_GROUP)
        return [self._peer(row) for row in rows[:limit]]

    async def lid_for(self, jid: str) -> str | None:
        """The LID address of a phone-number JID, when the phone shared it."""
        return await self._require_store().get_lid(jid)

    async def pn_for(self, lid_jid: str) -> str | None:
        return await self._require_store().get_pn(lid_jid)

    async def get_chat(self, jid: str) -> Peer | None:
        row = await self._require_store().get_peer(jid)
        return None if row is None else self._peer(row)

    async def set_contact_name(self, jid: str, name: str) -> None:
        """Local address-book name, like a phone contact list entry."""
        await self._require_store().upsert_peer(
            jid, KIND_GROUP if jid.endswith("@g.us") else KIND_USER, contact_name=name
        )

    async def save_contact(self, jid: str, name: str, phone: str | None = None) -> None:
        await self._require_store().upsert_peer(jid, KIND_USER, contact_name=name, phone=phone)

    async def download_stored(self, message: StoredMessage) -> bytes:
        """Download the attachment of a message read back from the session file."""
        if message.media is None:
            raise ClientError("this message has no attachment")
        return await self.download_media(message.media)

    async def _record_incoming(self, received: ReceivedMessage) -> None:
        store = self._require_store()
        chat_jid = received.chat_jid
        sender_jid = received.sender_jid
        push_name = received.push_name
        is_group = chat_jid.endswith("@g.us")
        await store.upsert_peer(chat_jid, KIND_GROUP if is_group else KIND_USER)
        if is_group and sender_jid:
            await store.upsert_peer(sender_jid, KIND_USER, push_name=push_name)
        elif push_name:
            await store.upsert_peer(chat_jid, KIND_USER, push_name=push_name)

        await store.save_message(
            chat_jid,
            received.message_id,
            sender_jid=sender_jid,
            timestamp=received.timestamp,
            text=received.text,
            media_json=(
                json.dumps(media_to_dict(received.media)) if received.media is not None else None
            ),
            outgoing=False,
        )

    async def _record_outgoing(self, jid: str, message_id: str, payload: bytes) -> None:
        from wapy.protocol.messages import parse_message

        parsed = parse_message(payload)
        store = self._require_store()
        is_group = jid.endswith("@g.us")
        if not is_group:
            await store.upsert_peer(jid, KIND_USER)
        await store.save_message(
            jid,
            message_id,
            sender_jid=self.info.jid if self.info else None,
            timestamp=int(time.time()),
            text=parsed.text,
            media_json=(
                json.dumps(media_to_dict(parsed.media)) if parsed.media is not None else None
            ),
            outgoing=True,
        )

    @staticmethod
    def _stored_message(row: dict[str, Any]) -> StoredMessage:
        raw_media = row.get("media_json")
        return StoredMessage(
            chat_jid=str(row["chat_jid"]),
            message_id=str(row["message_id"]),
            sender_jid=row.get("sender_jid"),
            timestamp=row.get("timestamp"),
            text=row.get("text"),
            media=media_from_dict(json.loads(raw_media)) if raw_media else None,
            outgoing=bool(row.get("outgoing")),
        )

    @staticmethod
    def _peer(row: dict[str, Any]) -> Peer:
        return Peer(
            jid=str(row["jid"]),
            kind=str(row["kind"]),
            phone=row.get("phone"),
            push_name=row.get("push_name"),
            contact_name=row.get("contact_name"),
            subject=row.get("subject"),
            last_update_on=int(row.get("last_update_on") or 0),
            last_message_at=row.get("last_message_at"),
            total_messages=row.get("total"),
        )

    # ---------------------------------------------------------------------- groups

    async def group_info(self, group_jid: str, *, refresh: bool = False) -> GroupInfo:
        if self._groups is None:
            raise ClientError("the client is not connected")
        info = await self._groups.info(group_jid, refresh=refresh)
        with contextlib.suppress(Exception):
            await self._require_store().upsert_peer(info.jid, KIND_GROUP, subject=info.subject)
        return info

    async def joined_groups(self) -> list[GroupInfo]:
        if self._groups is None:
            raise ClientError("the client is not connected")
        return await self._groups.joined()

    async def create_group(self, subject: str, participants: list[str]) -> str:
        if self._groups is None:
            raise ClientError("the client is not connected")
        return await self._groups.create(subject, participants)

    async def update_group_participants(
        self, group_jid: str, action: str, participants: list[str]
    ) -> list[GroupParticipant]:
        if self._groups is None:
            raise ClientError("the client is not connected")
        return await self._groups.update_participants(group_jid, action, participants)

    async def leave_group(self, group_jid: str) -> None:
        if self._groups is None:
            raise ClientError("the client is not connected")
        await self._groups.leave(group_jid)

    async def _deliver(
        self,
        jid: str,
        payload: bytes,
        *,
        message_type: str,
        wait_for_message: bool,
    ) -> SendResult:
        if jid.endswith("@g.us"):
            sender = self._group_sender
            if sender is None:
                raise ClientError("the client is not connected")
            result = await sender.send_payload(
                jid, payload, message_type=message_type, wait_for_message=wait_for_message
            )
        else:
            messenger = self._require_messenger()
            result = await messenger.send_payload(
                jid,
                payload,
                message_type=message_type,
                media_type=None if message_type == "text" else message_type,
                wait_for_message=wait_for_message,
            )
        self._remember(result.message_id, jid, payload)
        with contextlib.suppress(Exception):
            await self._record_outgoing(jid, result.message_id, payload)
        return result

    async def _send_with_outbox(
        self, messenger: Messenger, jid: str, payload: bytes, *, wait_for_message: bool
    ) -> SendResult:
        result = await messenger.send_payload(jid, payload, wait_for_message=wait_for_message)
        self._remember(result.message_id, jid, payload)
        with contextlib.suppress(Exception):
            await self._record_outgoing(jid, result.message_id, payload)
        return result

    def _remember(self, message_id: str, jid: str, payload: bytes) -> None:
        self._outbox[message_id] = OutgoingMessage(chat_jid=jid, payload=payload)
        self._outbox.move_to_end(message_id)
        while len(self._outbox) > OUTBOX_LIMIT:
            self._outbox.popitem(last=False)

    async def mark_read(self, event: MessageEvent, *, receipt_type: str = RECEIPT_READ) -> None:
        """Tell the sender their message was read (or just delivered)."""
        if event.raw is None:
            raise ClientError("the event carries no node to answer")
        await self._require_stream().send(build_receipt(event.raw, receipt_type=receipt_type))

    async def send_presence(self, available: bool = True) -> None:
        state = PRESENCE_AVAILABLE if available else PRESENCE_UNAVAILABLE
        await self._require_stream().send(build_presence(state, push_name=self.push_name))

    async def subscribe_presence(self, jid: str) -> None:
        await self._require_stream().send(build_subscribe(jid))

    async def send_typing(
        self, jid: str, *, composing: bool = True, media: str | None = None
    ) -> None:
        from wapy.protocol.presence import CHAT_COMPOSING, CHAT_PAUSED

        state = CHAT_COMPOSING if composing else CHAT_PAUSED
        await self._require_stream().send(build_chat_state(jid, state, media=media))

    # ------------------------------------------------------------------- incoming

    def _enqueue(self, node: Node) -> None:
        self._queue.put_nowait(node)

    async def _process_loop(self) -> None:
        while True:
            node = await self._queue.get()
            try:
                await self._handle_node(node)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("failed to handle %s node", node.tag)

    async def _handle_node(self, node: Node) -> None:
        if node.tag == "message":
            await self._handle_message(node)
        elif node.tag == "receipt":
            await self._handle_receipt(node)
        elif node.tag == "presence":
            update = parse_presence(node)
            if update is not None:
                self._emit(
                    PresenceEvent(
                        jid=update.jid,
                        available=update.available,
                        last_seen=update.last_seen,
                        raw=node,
                    )
                )
        elif node.tag == "chatstate":
            chat = parse_chat_state(node)
            if chat is not None:
                self._emit(
                    ChatStateEvent(jid=chat.jid, state=chat.state, media=chat.media, raw=node)
                )
        elif node.tag == "notification":
            await self._handle_notification(node)
        elif node.tag == "stream:error":
            await self._handle_stream_error(node)
        elif node.tag == "iq" and node.attrs.get("type") == "set":
            await self._ack_request(node)

    async def _handle_message(self, node: Node) -> None:
        receiver = self._receiver
        if receiver is None:  # pragma: no cover - guarded by the connection
            return
        try:
            received = await receiver.receive(node)
        except DecryptError:
            await self._request_retry(node)
            return
        except ReceiveError:
            logger.debug("ignoring unusable message node %s", node.attrs.get("id"))
            return

        if received.parsed is not None and received.parsed.app_state_keys:
            await self._accept_app_state_keys(received.parsed.app_state_keys)
            return

        if (
            received.text is None
            and received.media is None
            and received.parsed is not None
            and received.parsed.sender_key_distribution
        ):
            return

        if received.parsed is not None and received.parsed.reaction is not None:
            await self._handle_reaction(received)
            return
        if received.parsed is not None and received.parsed.protocol is not None:
            await self._handle_protocol_event(received)
            return

        await self._record_incoming(received)

        if self._auto_receipts:
            with contextlib.suppress(Exception):
                await self._require_stream().send(
                    build_receipt(node, receipt_type=RECEIPT_DELIVERY)
                )
        self._emit(
            MessageEvent(
                chat_jid=received.chat_jid,
                sender_jid=received.sender_jid,
                message_id=received.message_id,
                text=received.text,
                media=received.media,
                timestamp=received.timestamp,
                from_me=received.sender_jid == (self.info.jid if self.info else None),
                raw=node,
            )
        )

    async def _handle_receipt(self, node: Node) -> None:
        receipt = parse_receipt(node)
        if receipt is None:
            return
        if receipt.receipt_type == RECEIPT_RETRY:
            await self._resend_on_retry(receipt)
            return
        self._emit(
            ReceiptEvent(
                chat_jid=receipt.chat_jid,
                sender_jid=receipt.sender_jid,
                message_ids=receipt.message_ids,
                receipt_type=receipt.receipt_type,
                timestamp=receipt.timestamp,
                raw=node,
            )
        )

    async def _handle_reaction(self, received: ReceivedMessage) -> None:
        reaction = received.parsed.reaction if received.parsed else None
        if reaction is None:  # pragma: no cover - guarded by the caller
            return
        sender = received.sender_jid
        await self._require_store().set_reaction(
            received.chat_jid,
            reaction.message_id,
            sender,
            reaction.text,
            timestamp=received.timestamp,
        )
        self._emit(
            ReactionEvent(
                chat_jid=received.chat_jid,
                sender_jid=sender,
                message_id=reaction.message_id,
                text=reaction.text,
                from_me=sender == (self.info.jid if self.info else None),
                timestamp=received.timestamp,
                raw=None,
            )
        )

    async def _handle_protocol_event(self, received: ReceivedMessage) -> None:
        protocol = received.parsed.protocol if received.parsed else None
        if protocol is None:  # pragma: no cover - guarded by the caller
            return
        store = self._require_store()
        if protocol.kind == "history_sync":
            if protocol.raw:
                task = asyncio.get_running_loop().create_task(
                    self._store_history(protocol.raw), name="wapy-history-sync"
                )
                self._track(task)
            return
        if protocol.kind == "revoke":
            await store.mark_message_deleted(received.chat_jid, protocol.message_id)
            self._emit(
                RevokeEvent(
                    chat_jid=received.chat_jid,
                    sender_jid=received.sender_jid,
                    message_id=protocol.message_id,
                )
            )
            return
        if protocol.kind == "edit":
            if protocol.text:
                await store.update_message_text(
                    received.chat_jid, protocol.message_id, protocol.text
                )
            self._emit(
                EditEvent(
                    chat_jid=received.chat_jid,
                    sender_jid=received.sender_jid,
                    message_id=protocol.message_id,
                    text=protocol.text,
                    timestamp=received.timestamp,
                )
            )

    async def _store_history(self, raw_notification: bytes) -> None:
        service = self._history
        if service is None:
            return
        try:
            result = await service.handle_raw(raw_notification)
        except Exception as exc:
            logger.warning("history sync failed: %s", exc)
            return
        self._emit(
            HistorySyncEvent(
                sync_type=result.sync_type,
                chats=result.chats,
                messages=result.messages,
                chunk_order=result.chunk_order,
                has_more=result.has_more,
            )
        )

    async def _accept_app_state_keys(self, keys: tuple[tuple[bytes, bytes], ...]) -> None:
        store = self._require_store()
        for key_id, key_data in keys:
            await store.put_app_state_key(key_id, key_data)
        logger.info("stored %d app state keys", len(keys))
        if self._app_state is not None:
            task = asyncio.get_running_loop().create_task(
                self._sync_app_state_quietly(), name="wapy-app-state-sync"
            )
            self._track(task)

    async def _sync_app_state_quietly(self) -> None:
        try:
            await self._require_app_state().sync_all()
        except Exception as exc:
            # A missing or rejected patch must not take the connection down: the
            # local copy simply stays where it was.
            logger.warning("app state sync failed: %s", exc)

    async def _handle_notification(self, node: Node) -> None:
        if child(node, "encrypt") is not None:
            # Device list changed: the cached answers are stale from now on.
            jid = node.attrs.get("from")
            if jid and self._messenger is not None:
                self._messenger.invalidate(jid)
        self._emit(
            NotificationEvent(kind=node.attrs.get("type", ""), attrs=dict(node.attrs), raw=node)
        )

    async def _handle_stream_error(self, node: Node) -> None:
        try:
            code = int(node.attrs.get("code", "0"))
        except ValueError:
            code = 0
        logger.warning("stream error %s: %s", code, node.attrs)
        self._last_error = f"stream error {code}"
        if code in LOGGED_OUT_CODES:
            # The server dropped this device: reconnecting would only repeat the
            # rejection, and pairing again is the user's decision, not ours.
            self._stop_reconnect = True
        stream = self._stream
        if stream is not None:
            # Close from a separate task: this handler runs inside the dispatch
            # worker, and that worker is cancelled as part of the shutdown.
            asyncio.get_running_loop().create_task(stream.close(), name="wapy-close")

    async def _ack_request(self, node: Node) -> None:
        await self._require_stream().send(
            Node(
                tag="iq",
                attrs={
                    "to": "@s.whatsapp.net",
                    "type": "result",
                    "id": node.attrs.get("id", ""),
                },
            )
        )

    # ---------------------------------------------------------------------- retry

    async def _request_retry(self, node: Node) -> None:
        """Ask the sender to resend: our session with them is out of sync."""
        message_id = node.attrs.get("id", "")
        count = self._incoming_retries.get(message_id, 0) + 1
        enc = child(node, "enc")
        if count == 1 and enc is not None and enc.attrs.get("count"):
            with contextlib.suppress(ValueError):
                count = int(enc.attrs["count"]) + 1
        if count > MAX_RETRY_COUNT:
            logger.warning("giving up on %s after %d retries", message_id, count)
            return
        self._incoming_retries[message_id] = count
        if len(self._incoming_retries) > MAX_TRACKED_RETRIES:
            self._incoming_retries.pop(next(iter(self._incoming_retries)))

        credentials = self._require_credentials()
        prekey: tuple[int, bytes] | None = None
        if count > 1:
            prekey = await self._allocate_prekey()
        try:
            receipt = build_retry_receipt(node, credentials, count=count, one_time_prekey=prekey)
        except Exception:
            logger.exception("cannot build a retry receipt for %s", message_id)
            return
        await self._require_stream().send(receipt)

    async def _allocate_prekey(self) -> tuple[int, bytes]:
        store = self._require_store()
        key_id = (await store.max_prekey_id() or 0) + 1
        keypair = generate_keypair()
        await store.add_prekeys([(key_id, pack_key_pair(keypair.private, keypair.public))])
        return key_id, keypair.public

    async def _resend_on_retry(self, receipt: object) -> None:
        """The other side could not decrypt: drop the session and resend once."""
        message_ids = getattr(receipt, "message_ids", ())
        chat_jid = getattr(receipt, "chat_jid", "")
        sender_jid = getattr(receipt, "sender_jid", chat_jid)
        message_id = getattr(receipt, "retry_id", None) or (message_ids[0] if message_ids else "")
        stored = self._outbox.get(message_id)
        if stored is None:
            logger.info("retry request for an unknown message %s", message_id)
            return
        if chat_jid.endswith("@g.us"):
            sender_keys = self._sender_keys
            if sender_keys is not None and self.info is not None:
                await sender_keys.forget(chat_jid, self.info.jid)
            await self._require_store().delete_sender_keys_for_group(chat_jid)
        else:
            user = sender_jid.split("@", 1)[0].split(":", 1)[0]
            await self._require_store().delete_sessions_for_user(user)
        messenger = self._require_messenger()
        messenger.invalidate(chat_jid)
        logger.info("resending %s to %s after a retry request", message_id, chat_jid)
        with contextlib.suppress(Exception):
            await messenger.send_payload(chat_jid, stored.payload, wait_for_message=False)

    # --------------------------------------------------------------------- helpers

    def _emit(self, event: AnyEvent) -> None:
        task = asyncio.get_running_loop().create_task(
            self.router.dispatch(event), name="wapy-dispatch-event"
        )
        self._track(task)

    def _track(self, task: asyncio.Task[object]) -> None:
        def _log(finished: asyncio.Task[object]) -> None:
            if finished.cancelled():
                return
            error = finished.exception()
            if error is not None:
                logger.error("event handler failed", exc_info=error)

        task.add_done_callback(_log)

    def _require_stream(self) -> NodeStream:
        if self._stream is None:
            raise ClientError("the client is not connected")
        return self._stream

    def _require_messenger(self) -> Messenger:
        if self._messenger is None:
            raise ClientError("the client is not connected")
        return self._messenger

    def _require_credentials(self) -> DeviceCredentials:
        if self._credentials is None:
            raise ClientError("the client is not connected")
        return self._credentials

    def _require_app_state(self) -> AppStateSync:
        if self._app_state is None:
            raise ClientError("the client is not connected")
        return self._app_state

    def _require_media(self) -> MediaStorage:
        if self._media is None:
            raise ClientError("the client is not connected")
        return self._media

    def _require_store(self) -> SessionStore:
        if self._store is None:
            raise ClientError("the client is not connected")
        return self._store


_DEFAULT_MIME = {
    MEDIA_IMAGE: "image/jpeg",
    MEDIA_VIDEO: "video/mp4",
    MEDIA_AUDIO: "audio/ogg",
    MEDIA_PTT: "audio/ogg; codecs=opus",
    MEDIA_DOCUMENT: "application/octet-stream",
    "sticker": "image/webp",
}


def default_mime_type(media_type: str) -> str:
    return _DEFAULT_MIME.get(media_type, "application/octet-stream")


def _encode_text_payload(text: str, quote: QuoteRef | None = None) -> bytes:
    from wapy.protocol.messages import encode_text

    return encode_text(text, quote=quote)
