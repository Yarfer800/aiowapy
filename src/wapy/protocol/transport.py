"""WebSocket transport with WhatsApp framing and the Noise handshake.

Frame layout, confirmed byte-for-byte against captured traffic:

    [ intro header, client's first frame only ] [ length: 3 bytes BE ] [ body ]

The intro header is `WA` + protocol version + token-dictionary version, optionally
preceded by `ED` and a routing blob when the endpoint uses that dialect.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from typing import Any

import websockets

from wapy.crypto.primitives import KeyPair, generate_keypair
from wapy.errors import WapyError
from wapy.protocol.noise import INTRO_MAGIC, NoiseHandshake, NoiseTransport

DEFAULT_URL = "wss://web.whatsapp.com/ws/chat"
MAX_FRAME_LEN = 1 << 24


class TransportError(WapyError):
    """Connection-level failure."""


def build_intro_header(routing_info: bytes | None = None) -> bytes:
    """`WA\\x06\\x03`, or the `ED` form that carries routing information."""
    if not routing_info:
        return INTRO_MAGIC
    if len(routing_info) > 0xFFFFFF:
        raise TransportError("routing info is too large")
    return b"ED\x00\x01" + len(routing_info).to_bytes(3, "big") + routing_info + INTRO_MAGIC


def encode_frame(payload: bytes, *, intro: bytes = b"", include_intro: bool = False) -> bytes:
    if len(payload) > MAX_FRAME_LEN:
        raise TransportError(f"frame of {len(payload)} bytes exceeds the 16 MiB limit")
    header = intro if include_intro else b""
    return header + len(payload).to_bytes(3, "big") + payload


class FrameParser:
    """Reassemble frames from WebSocket messages."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        self._buffer.extend(data)
        frames: list[bytes] = []
        while True:
            if len(self._buffer) < 3:
                return frames
            length = int.from_bytes(self._buffer[:3], "big")
            if length > MAX_FRAME_LEN:
                raise TransportError(f"declared frame length {length} is out of range")
            if len(self._buffer) < 3 + length:
                return frames
            frames.append(bytes(self._buffer[3 : 3 + length]))
            del self._buffer[: 3 + length]


class WhatsAppTransport:
    """One WebSocket connection: framing, handshake and Noise transport."""

    def __init__(
        self,
        url: str = DEFAULT_URL,
        *,
        proxy: str | None = None,
        routing_info: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 20.0,
        keypair_factory: Callable[[], KeyPair] | None = None,
        intro: bytes | None = None,
    ) -> None:
        self._url = url
        self._proxy = proxy
        self._routing_info = routing_info
        # The reference client sends no User-Agent at all on the upgrade request.
        self._headers = {
            "Origin": "https://web.whatsapp.com",
            **(headers or {}),
        }
        self._timeout = timeout
        self._keypair_factory = keypair_factory or generate_keypair
        self._intro = intro
        self._socket: Any | None = None
        self._parser = FrameParser()
        self._noise: NoiseTransport | None = None
        self._intro_sent = False

    @property
    def connected(self) -> bool:
        return self._socket is not None

    async def connect(self) -> None:
        if self._socket is not None:
            return
        try:
            self._socket = await asyncio.wait_for(
                websockets.connect(
                    self._url,
                    proxy=self._proxy,
                    additional_headers=self._headers,
                    user_agent_header=None,
                    max_size=None,
                    open_timeout=self._timeout,
                    close_timeout=2,
                ),
                timeout=self._timeout,
            )
        except (TimeoutError, OSError, websockets.WebSocketException) as exc:
            raise TransportError(f"cannot connect to {self._url}: {exc}") from exc

    async def close(self) -> None:
        socket, self._socket = self._socket, None
        self._noise = None
        self._intro_sent = False
        self._parser = FrameParser()
        if socket is not None:
            with contextlib.suppress(Exception):  # best effort on shutdown
                await socket.close()

    async def send_frame(self, payload: bytes) -> None:
        if self._socket is None:
            raise TransportError("not connected")
        frame = encode_frame(
            payload,
            intro=self._intro or build_intro_header(self._routing_info),
            include_intro=not self._intro_sent,
        )
        self._intro_sent = True
        await self._socket.send(frame)

    async def recv_frame(self) -> bytes:
        if self._socket is None:
            raise TransportError("not connected")
        while True:
            frames = self._parser.feed(await self._socket.recv())
            if frames:
                return frames[0]

    async def handshake(
        self,
        key_pair: KeyPair | None = None,
        client_payload: bytes = b"",
        *,
        trusted_root_key: bytes | None = None,
    ) -> NoiseTransport:
        """Run the Noise handshake and switch the connection into transport mode."""
        handshake = NoiseHandshake(
            key_pair or self._keypair_factory(),
            prologue=self._intro or build_intro_header(self._routing_info),
            trusted_root_key=trusted_root_key,
        )
        await self.send_frame(handshake.client_hello())
        encrypted_static = handshake.process_server_hello(await self.recv_frame())
        await self.send_frame(handshake.client_finish(client_payload, encrypted_static))
        transport = handshake.finish()
        self._noise = transport
        return transport

    async def send_encrypted(self, payload: bytes) -> None:
        if self._noise is None:
            raise TransportError("transport is not established")
        await self.send_frame(self._noise.encrypt(payload))

    async def recv_encrypted(self) -> bytes:
        if self._noise is None:
            raise TransportError("transport is not established")
        return self._noise.decrypt(await self.recv_frame())
