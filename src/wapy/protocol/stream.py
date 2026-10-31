"""Node-level stream over the transport: send, receive and correlate requests.

Everything above this layer works with `wabinary` nodes; this module is the only
place that knows about request ids, timeouts and node dispatch by tag.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Awaitable, Callable
from typing import Protocol

from wapy.errors import WapyError
from wapy.protocol.wabinary import Node, decode_node, encode_node

DEFAULT_TIMEOUT = 30.0


class StreamError(WapyError):
    """Node could not be sent, received, or was answered with an error."""


class EncryptedTransport(Protocol):
    async def send_encrypted(self, payload: bytes) -> None: ...

    async def recv_encrypted(self) -> bytes: ...


def child(node: Node, tag: str) -> Node | None:
    if not isinstance(node.content, list):
        return None
    for item in node.content:
        if item.tag == tag:
            return item
    return None


def children(node: Node, tag: str) -> list[Node]:
    if not isinstance(node.content, list):
        return []
    return [item for item in node.content if item.tag == tag]


class NodeStream:
    """Send and receive nodes, with a pending-request table keyed by node id."""

    def __init__(self, transport: EncryptedTransport) -> None:
        self._transport = transport
        self._pending: dict[str, asyncio.Future[Node]] = {}
        self._ack_waiters: dict[str, asyncio.Future[bool]] = {}
        self._listeners: list[Callable[[Node], Awaitable[None] | None]] = []
        self._reader: asyncio.Task[None] | None = None
        self._closed = False
        self._closed_event = asyncio.Event()
        self.last_activity = time.monotonic()

    async def start(self) -> None:
        if self._reader is None:
            self._reader = asyncio.create_task(self._read_loop())

    @property
    def closed(self) -> bool:
        return self._closed_event.is_set()

    async def wait_closed(self) -> None:
        await self._closed_event.wait()

    async def close(self) -> None:
        self._closed = True
        self._closed_event.set()
        if self._reader is not None:
            self._reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._reader
            self._reader = None

    def on_node(self, listener: Callable[[Node], Awaitable[None] | None]) -> None:
        self._listeners.append(listener)

    async def send(self, node: Node) -> None:
        try:
            await self._transport.send_encrypted(encode_node(node))
        except Exception as exc:
            raise StreamError(f"failed to send node {node.tag!r}: {exc}") from exc

    async def query(self, node: Node, *, timeout: float | None = DEFAULT_TIMEOUT) -> Node:
        """Send an `iq` and wait for the matching response."""
        node_id = node.attrs.get("id")
        if not node_id:
            raise StreamError("queries require an id attribute")
        future: asyncio.Future[Node] = asyncio.get_running_loop().create_future()
        self._pending[node_id] = future
        try:
            await self.send(node)
            return await asyncio.wait_for(future, timeout or DEFAULT_TIMEOUT)
        except TimeoutError as exc:
            raise StreamError(f"no response to {node.tag!r} within {timeout}s") from exc
        finally:
            self._pending.pop(node_id, None)

    async def wait_for_ack(self, message_id: str, *, timeout: float) -> bool:
        """Wait for `<ack id=...>`; a timeout returns False, not an exception."""
        loop = asyncio.get_running_loop()
        waiter: asyncio.Future[bool] = loop.create_future()
        self._ack_waiters[message_id] = waiter
        try:
            return await asyncio.wait_for(waiter, timeout=timeout)
        except TimeoutError:
            return False
        finally:
            self._ack_waiters.pop(message_id, None)

    async def _read_loop(self) -> None:
        try:
            while not self._closed:
                try:
                    frame = await self._transport.recv_encrypted()
                    node = decode_node(frame)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    return
                self.last_activity = time.monotonic()
                await self._dispatch(node)
        finally:
            self._closed_event.set()

    async def _dispatch(self, node: Node) -> None:
        node_id = node.attrs.get("id")
        if node.tag == "ack" and node_id and node_id in self._ack_waiters:
            waiter = self._ack_waiters[node_id]
            if not waiter.done():
                waiter.set_result(True)
            return
        if node.tag == "iq" and node_id and node_id in self._pending:
            future = self._pending[node_id]
            if not future.done():
                future.set_result(node)
            return
        for listener in list(self._listeners):
            result = listener(node)
            if asyncio.iscoroutine(result):
                await result
