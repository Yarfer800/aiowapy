from __future__ import annotations

import asyncio

import pytest

from aiowapy.protocol.stream import NodeStream, StreamError, child, children
from aiowapy.protocol.transport import TransportError
from aiowapy.protocol.wabinary import Node, decode_node, encode_node


class FakeTransport:
    """In-memory transport: records sent frames and replays queued ones."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.incoming: asyncio.Queue[bytes] = asyncio.Queue()

    async def send_encrypted(self, payload: bytes) -> None:
        self.sent.append(payload)

    async def recv_encrypted(self) -> bytes:
        return await self.incoming.get()


def test_child_helpers() -> None:
    node = Node(tag="iq", content=[Node(tag="pair-device"), Node(tag="other")])
    assert child(node, "pair-device") is not None
    assert child(node, "missing") is None
    assert len(children(node, "other")) == 1
    assert child(Node(tag="iq", content=b"bytes"), "x") is None


async def test_send_encodes_the_node() -> None:
    transport = FakeTransport()
    stream = NodeStream(transport)  # type: ignore[arg-type]
    node = Node(tag="presence", attrs={"type": "available"})
    await stream.send(node)
    assert decode_node(transport.sent[0]) == node


async def test_query_resolves_on_matching_id() -> None:
    transport = FakeTransport()
    stream = NodeStream(transport)  # type: ignore[arg-type]
    await stream.start()

    async def reply() -> None:
        await asyncio.sleep(0.05)
        await transport.incoming.put(
            encode_node(Node(tag="iq", attrs={"id": "42", "type": "result"}))
        )

    task = asyncio.create_task(reply())
    response = await stream.query(Node(tag="iq", attrs={"id": "42", "type": "get"}))
    assert response.attrs["type"] == "result"
    await task
    await stream.close()


async def test_query_requires_an_id() -> None:
    stream = NodeStream(FakeTransport())  # type: ignore[arg-type]
    with pytest.raises(StreamError):
        await stream.query(Node(tag="iq", attrs={"type": "get"}))


async def test_query_times_out() -> None:
    stream = NodeStream(FakeTransport())  # type: ignore[arg-type]
    with pytest.raises(StreamError):
        await stream.query(Node(tag="iq", attrs={"id": "1"}), timeout=0.05)


async def test_listeners_see_non_query_nodes() -> None:
    transport = FakeTransport()
    stream = NodeStream(transport)  # type: ignore[arg-type]
    seen: list[str] = []

    def listener(node: Node) -> None:
        seen.append(node.tag)

    stream.on_node(listener)
    await stream.start()
    await transport.incoming.put(encode_node(Node(tag="success", attrs={"lid": "1"})))
    for _ in range(50):
        if seen:
            break
        await asyncio.sleep(0.01)
    assert seen == ["success"]
    await stream.close()


async def test_send_failure_is_wrapped() -> None:
    class Broken(FakeTransport):
        async def send_encrypted(self, payload: bytes) -> None:
            raise TransportError("socket is closed")

    stream = NodeStream(Broken())  # type: ignore[arg-type]
    with pytest.raises(StreamError):
        await stream.send(Node(tag="iq"))
