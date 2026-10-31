"""Session orchestration: connect, pair if needed, survive the 515 restart.

WhatsApp closes the connection with a `stream:error` code 515 right after a device
is linked and expects the client to come back with a *login* payload. This module
owns that state machine, so the QR flow and the reconnect are testable without a
network.
"""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from wapy.creds import DeviceCredentials, generate_credentials
from wapy.crypto.primitives import generate_keypair
from wapy.errors import WapyError
from wapy.pairing import PairingQr, PairingQrSource
from wapy.protocol.client_payload import build_login_payload, build_registration_payload
from wapy.protocol.pairing import (
    PairSuccess,
    build_pair_device_sign_reply,
    parse_pair_success,
    verify_pair_success,
)
from wapy.protocol.prekeys import (
    INITIAL_PREKEY_COUNT,
    MIN_PREKEY_COUNT,
    build_upload_node,
    pack_key_pair,
    prekeys_to_upload,
    unpack_public,
)
from wapy.protocol.stream import child, children
from wapy.protocol.wabinary import Node, decode_node, encode_node
from wapy.store import SessionStore

S_WHATSAPP_NET = "@s.whatsapp.net"
DEFAULT_VERSION = (2, 3000, 1043857760)
STREAM_ERROR_RESTART = 515
STREAM_ERROR_LOGGED_OUT = {401, 403, 409}

QR_FIRST_TTL = 60
QR_NEXT_TTL = 20
KEEPALIVE_INTERVAL = 30.0
KEEPALIVE_GRACE = 5.0


def new_message_id() -> str:
    return secrets.token_hex(4)


def _reason_code(node: Node) -> int:
    try:
        return int(node.attrs.get("reason", "500"))
    except (TypeError, ValueError):
        return 500


def unified_session_id(now_seconds: float | None = None) -> str:
    """Session marker the reference client sends right after pairing."""
    now = int((now_seconds if now_seconds is not None else time.time()) * 1000)
    return str((now + 3 * 86_400_000) % 604_800_000)


def build_unified_session_node(session_id: str) -> Node:
    return Node(
        tag="ib",
        attrs={},
        content=[Node(tag="unified_session", attrs={"id": session_id})],
    )


def build_ping_node(message_id: str) -> Node:
    return Node(
        tag="iq",
        attrs={"id": message_id, "to": S_WHATSAPP_NET, "type": "get", "xmlns": "w:p"},
        content=[Node(tag="ping", attrs={})],
    )


class SessionError(WapyError):
    """The session could not be established."""


class Transport(Protocol):
    async def connect(self) -> None: ...
    async def close(self) -> None: ...
    async def handshake(
        self, key_pair: object = None, client_payload: bytes = b"", **kwargs: object
    ) -> object: ...
    async def send_encrypted(self, payload: bytes) -> None: ...
    async def recv_encrypted(self) -> bytes: ...


@dataclass(frozen=True, slots=True)
class StreamError:
    code: int
    text: str


def parse_stream_error(node: Node) -> StreamError | None:
    """Recognise a stream error given either as an attribute or as child nodes.

    Observed in the wild: `<stream:error code="515"/>`, while the reference client
    also handles `<stream:error><code>515</code><text>...</text></stream:error>`.
    """
    if node.tag != "stream:error":
        return None
    code_node = child(node, "code")
    text_node = child(node, "text")
    raw: object = code_node.content if code_node is not None else node.attrs.get("code")
    if raw is None:
        return None
    try:
        code = int(raw.decode() if isinstance(raw, bytes) else str(raw))
    except (TypeError, ValueError):
        return None
    text: object = text_node.content if text_node is not None else node.attrs.get("text", "")
    message = text.decode(errors="replace") if isinstance(text, bytes) else str(text)
    return StreamError(code=code, text=message)


@dataclass(slots=True)
class SessionState:
    credentials: DeviceCredentials
    paired: bool = False
    jid: str | None = None
    lid: str | None = None


class ClientSession:
    """One session file, one logical connection, reconnect handling included."""

    def __init__(
        self,
        path: Path | str,
        *,
        transport_factory: Callable[[], Transport],
        qr_callback: Callable[[PairingQr], Awaitable[None] | None] | None = None,
        node_observer: Callable[[Node], None] | None = None,
        sent_observer: Callable[[Node], None] | None = None,
        platform: str = "chrome",
        version: tuple[int, int, int] = DEFAULT_VERSION,
        max_attempts: int = 4,
    ) -> None:
        self._path = Path(path)
        self._factory = transport_factory
        self._qr_callback = qr_callback
        self._observer = node_observer
        self._sent_observer = sent_observer
        self._platform = platform
        self._version = version
        self._max_attempts = max_attempts
        self._last_recv = 0.0

    async def run(self) -> SessionState:
        async with SessionStore(self._path) as store:
            state = await self._load_state(store)
            for _attempt in range(self._max_attempts):
                outcome = await self._attempt(state, store)
                if outcome == "restart":
                    continue
                if outcome == "paired":
                    state.paired = True
                    continue
                return state
                # pragma: no cover - loop always returns or continues
            raise SessionError(f"gave up after {self._max_attempts} attempts")

    async def _load_state(self, store: SessionStore) -> SessionState:
        raw = await store.load_creds()
        if raw is None:
            credentials = generate_credentials()
            await store.save_creds(credentials.to_dict())
            return SessionState(credentials=credentials)
        me = raw.get("me") if isinstance(raw, dict) else None
        credentials = DeviceCredentials.from_dict(raw)
        jid = me.get("id") if isinstance(me, dict) else None
        lid = me.get("lid") if isinstance(me, dict) else None
        return SessionState(credentials=credentials, paired=jid is not None, jid=jid, lid=lid)

    def _payload(self, state: SessionState) -> bytes:
        if state.paired and state.jid:
            return build_login_payload(state.jid, version=self._version)
        return build_registration_payload(state.credentials, version=self._version)

    async def _attempt(self, state: SessionState, store: SessionStore) -> str:
        transport = self._factory()
        await transport.connect()
        keepalive = asyncio.create_task(self._keepalive_loop(transport))
        try:
            await transport.handshake(client_payload=self._payload(state))
            self._last_recv = time.monotonic()
            return await self._serve(transport, state, store)
        finally:
            keepalive.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await keepalive
            await transport.close()

    async def _keepalive_loop(self, transport: Transport) -> None:
        """Node-level keepalive: WebSocket pings are disabled, so this is the alarm.

        The reference client pings every 30 s and treats more than 35 s of silence
        as a lost connection.
        """
        while True:
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            if time.monotonic() - self._last_recv > KEEPALIVE_INTERVAL + KEEPALIVE_GRACE:
                await transport.close()
                return
            await self._send(transport, build_ping_node(new_message_id()))

    async def _serve(self, transport: Transport, state: SessionState, store: SessionStore) -> str:
        source = None
        next_rotation = 0.0
        while True:
            timeout = None
            if source is not None:
                timeout = max(0.0, next_rotation - time.monotonic())
            try:
                frame = await asyncio.wait_for(transport.recv_encrypted(), timeout=timeout)
            except TimeoutError:
                # wait_for raised: it is time to rotate the QR.
                item = source.next() if source is not None else None
                if item is None:
                    return "timeout"
                await self._emit_qr(item)
                next_rotation = time.monotonic() + item.ttl
                continue
            except (ConnectionError, OSError):
                return "closed"
            except Exception as exc:  # websockets raises its own ConnectionClosed
                if type(exc).__name__.startswith("ConnectionClosed"):
                    return "closed"
                raise

            self._last_recv = time.monotonic()
            node = decode_node(frame)
            if self._observer is not None:
                self._observer(node)
            error = parse_stream_error(node)
            if error is not None:
                if error.code in STREAM_ERROR_LOGGED_OUT:
                    if state.paired:
                        await self._forget_me(store, state)
                        return "restart"
                    raise SessionError(f"session rejected: {error.code} {error.text}")
                if error.code == STREAM_ERROR_RESTART:
                    # 515 right after pairing means the device was accepted: persist
                    # the account so the reconnect uses a login payload.
                    if state.jid:
                        await self._store_me(store, state)
                    return "restart"
                return "close"

            pair_device = child(node, "pair-device")
            if pair_device is not None:
                await self._ack(transport, node)
                refs = self._read_refs(pair_device)
                if refs:
                    source = PairingQrSource(
                        state.credentials,
                        refs,
                        platform=self._platform,
                        first_ttl=QR_FIRST_TTL,
                        next_ttl=QR_NEXT_TTL,
                    )
                    item = source.next()
                    if item is not None:
                        await self._emit_qr(item)
                        next_rotation = time.monotonic() + item.ttl
                continue

            if child(node, "pair-success") is not None:
                await self._complete_pairing(transport, node, state, store)
                state.paired = True
                # Stay on the connection: the server finalises the device and then
                # sends the 515 restart. Closing earlier can abort the registration.
                continue

            if node.tag == "success":
                await self._store_me(store, state)
                await self._ensure_prekeys(transport, state, store)
                return "connected"
            if node.tag == "failure":
                reason = _reason_code(node)
                # A paired session that suddenly cannot log in means the device was
                # unlinked or never activated: drop the account and pair again.
                if state.paired and reason in STREAM_ERROR_LOGGED_OUT | {405}:
                    await self._forget_me(store, state)
                    return "restart"
                raise SessionError(f"connection refused: {node.attrs} (paired={state.paired})")

    async def _ensure_prekeys(
        self, transport: Transport, state: SessionState, store: SessionStore
    ) -> None:
        """Publish one-time prekeys so other devices can start a session with us."""
        available = await store.count_available_prekeys()
        if available > MIN_PREKEY_COUNT:
            return
        pending = await store.pending_prekeys()
        missing = INITIAL_PREKEY_COUNT - available - len(pending)
        if missing > 0:
            start = (await store.max_prekey_id() or 0) + 1
            batch = [
                (start + offset, pack_key_pair(kp.private, kp.public))
                for offset, kp in enumerate(generate_keypair() for _ in range(missing))
            ]
            await store.add_prekeys(batch)
            pending = await store.pending_prekeys()
        if not pending:
            return
        node = build_upload_node(
            state.credentials,
            [(key_id, unpack_public(blob)) for key_id, blob in prekeys_to_upload(pending)],
            new_message_id(),
        )
        response = await self._query(transport, node)
        if response.attrs.get("type") == "error":
            raise SessionError(f"prekey upload rejected: {response.attrs}")
        await store.mark_prekeys_uploaded([key_id for key_id, _blob in pending])

    async def _query(self, transport: Transport, node: Node, *, timeout: float = 30.0) -> Node:
        message_id = node.attrs.get("id")
        if not message_id:
            raise SessionError("query node has no id")
        await transport.send_encrypted(encode_node(node))
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SessionError(f"no response to {node.attrs.get('xmlns')} query")
            frame = await asyncio.wait_for(transport.recv_encrypted(), timeout=remaining)
            response = decode_node(frame)
            if response.tag == "iq" and response.attrs.get("id") == message_id:
                return response

    async def _store_me(self, store: SessionStore, state: SessionState) -> None:
        if not state.jid:
            return
        stored = state.credentials.to_dict()
        stored["me"] = {"id": state.jid, "lid": state.lid}
        await store.save_creds(stored)

    async def _forget_me(self, store: SessionStore, state: SessionState) -> None:
        state.paired = False
        state.jid = None
        state.lid = None
        await store.save_creds(state.credentials.to_dict())

    async def _send(self, transport: Transport, node: Node) -> None:
        if self._sent_observer is not None:
            self._sent_observer(node)
        await transport.send_encrypted(encode_node(node))

    async def _ack(self, transport: Transport, node: Node) -> None:
        await self._send(
            transport,
            Node(
                tag="iq",
                attrs={"to": S_WHATSAPP_NET, "type": "result", "id": node.attrs.get("id", "")},
            ),
        )

    @staticmethod
    def _read_refs(pair_device: Node) -> list[str]:
        refs: list[str] = []
        for ref_node in children(pair_device, "ref"):
            content = ref_node.content
            refs.append(content.decode() if isinstance(content, bytes) else str(content))
        return refs

    async def _emit_qr(self, item: PairingQr) -> None:
        if self._qr_callback is None:
            return
        result = self._qr_callback(item)
        if asyncio.iscoroutine(result):
            await result

    async def _complete_pairing(
        self, transport: Transport, node: Node, state: SessionState, store: SessionStore
    ) -> None:
        pair: PairSuccess = parse_pair_success(node, message_id=node.attrs.get("id", ""))
        identity, key_index = verify_pair_success(pair, state.credentials)
        reply = build_pair_device_sign_reply(node.attrs["id"], identity, key_index=key_index)
        await self._send(transport, reply)
        await self._send(transport, build_unified_session_node(unified_session_id()))
        state.jid = pair.jid
        state.lid = pair.lid
        state.paired = True
        # `me` is written only after the server accepts the login: saving it here
        # would make every later run try to log in even if registration failed.
