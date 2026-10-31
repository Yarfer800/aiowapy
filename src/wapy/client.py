from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from wapy.creds import DeviceCredentials, generate_credentials
from wapy.crypto.primitives import generate_keypair
from wapy.errors import WapyError
from wapy.events import (
    AnyEvent,
    ChatStateEvent,
    ConnectedEvent,
    DisconnectedEvent,
    MessageEvent,
    NotificationEvent,
    PresenceEvent,
    ReceiptEvent,
)
from wapy.messaging.devices import CachedDeviceResolver
from wapy.messaging.groups import GroupSender, GroupService, StoreSenderKeys
from wapy.messaging.media import MediaStorage, MediaTransport, UrllibMediaTransport
from wapy.messaging.messenger import Messenger, SendResult
from wapy.messaging.real import (
    StoreSignalSessionsWithDecrypt,
    StreamNodeSender,
    UsyncDeviceFetcher,
)
from wapy.messaging.receiving import DecryptError, MessageReceiver, ReceiveError
from wapy.protocol.groups import GroupInfo, GroupParticipant
from wapy.protocol.media import (
    MEDIA_AUDIO,
    MEDIA_DOCUMENT,
    MEDIA_IMAGE,
    MEDIA_PTT,
    MEDIA_VIDEO,
    MediaInfo,
)
from wapy.protocol.messages import encode_media
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

        self._store: SessionStore | None = None
        self._stream: NodeStream | None = None
        self._credentials: DeviceCredentials | None = None
        self._messenger: Messenger | None = None
        self._receiver: MessageReceiver | None = None
        self._groups: GroupService | None = None
        self._group_sender: GroupSender | None = None
        self._sender_keys: StoreSenderKeys | None = None
        self._media: MediaStorage | None = None
        self._media_transport: MediaTransport = media_transport or UrllibMediaTransport()
        self._session: ClientSession | None = None

        self._ready = asyncio.Event()
        self._done = asyncio.Event()
        self._closed = False
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
            await stream.close()
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
        delay = 1.0
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
            await self.router.dispatch(DisconnectedEvent(reason=reason))
            if self._closed or not self._reconnect:
                break
            logger.info("reconnecting in %.0fs: %s", delay, reason)
            await asyncio.sleep(delay)
            delay = min(delay * 2, MAX_RECONNECT_DELAY)
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
        self._group_sender = GroupSender(
            StreamNodeSender(stream),
            self._build_resolver(stream, state),
            StoreSignalSessionsWithDecrypt(self._store, state.credentials),
            self._sender_keys,
            self._groups,
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
            for task in (self._worker, self._keepalive):
                if task is not None and not task.done():
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
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
            ack_timeout=self._ack_timeout,
        )

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

    async def send_text(self, jid: str, text: str, *, wait_for_message: bool = True) -> SendResult:
        if not text:
            raise ClientError("text must not be empty")
        return await self._deliver(
            jid,
            _encode_text_payload(text),
            message_type="text",
            wait_for_message=wait_for_message,
        )

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

    # ---------------------------------------------------------------------- groups

    async def group_info(self, group_jid: str, *, refresh: bool = False) -> GroupInfo:
        if self._groups is None:
            raise ClientError("the client is not connected")
        return await self._groups.info(group_jid, refresh=refresh)

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
                jid, payload, message_type=message_type, wait_for_message=wait_for_message
            )
        self._remember(result.message_id, jid, payload)
        return result

    async def _send_with_outbox(
        self, messenger: Messenger, jid: str, payload: bytes, *, wait_for_message: bool
    ) -> SendResult:
        result = await messenger.send_payload(jid, payload, wait_for_message=wait_for_message)
        self._remember(result.message_id, jid, payload)
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

        if (
            received.text is None
            and received.media is None
            and received.parsed is not None
            and received.parsed.sender_key_distribution
        ):
            return

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
        stream = self._stream
        if stream is not None:
            await stream.close()

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


def _encode_text_payload(text: str) -> bytes:
    from wapy.protocol.messages import encode_text

    return encode_text(text)
