"""Offline demo: a real client against a scripted server, no WhatsApp account.

    uv run python examples/offline_demo.py [session_path]

The transport is fake, but everything above it is real: the Noise handshake is skipped,
while Signal sessions, prekey messages, sender keys, stanzas and the session file are
exactly the ones used against WhatsApp. Useful for a smoke test and for the README GIF.
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path

from aiowapy import Client
from aiowapy.creds import DeviceCredentials, generate_credentials
from aiowapy.crypto.primitives import KeyPair, generate_keypair
from aiowapy.crypto.session import encrypt as signal_encrypt
from aiowapy.crypto.session import initiator_session, prekey_message
from aiowapy.crypto.xeddsa import sign
from aiowapy.events import MessageEvent
from aiowapy.protocol.messages import encode_text
from aiowapy.protocol.prekeys import pack_key_pair
from aiowapy.protocol.wabinary import Node, decode_node, encode_node
from aiowapy.store import SessionStore

ME = "491111111111:1@s.whatsapp.net"
PEER = "492222222222@s.whatsapp.net"
PEER_DEVICE = "492222222222:1@s.whatsapp.net"
GROUP = "120363000000000001@g.us"


class ScriptedServer:
    """Answers the handful of stanzas the client sends and can push a message."""

    def __init__(self) -> None:
        self.inbox: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.sent: list[Node] = []
        self.peer_identity = generate_keypair()
        self.peer_signed = generate_keypair()
        self.peer_one_time = generate_keypair()

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def handshake(self, key_pair: object = None, client_payload: bytes = b"") -> object:
        return object()

    async def send_encrypted(self, payload: bytes) -> None:
        node = decode_node(payload)
        self.sent.append(node)
        self._respond(node)

    async def recv_encrypted(self) -> bytes:
        frame = await self.inbox.get()
        if frame is None:
            raise ConnectionError("server closed")
        return frame

    def push(self, node: Node) -> None:
        self.inbox.put_nowait(encode_node(node))

    def _respond(self, node: Node) -> None:
        xmlns = node.attrs.get("xmlns")
        if xmlns == "usync":
            self.push(self._devices(node))
        elif xmlns == "encrypt" and node.attrs.get("type") == "get":
            self.push(self._bundles(node))
        elif node.tag == "iq":
            self.push(Node(tag="iq", attrs={"id": node.attrs.get("id", ""), "type": "result"}))
        elif node.tag == "message":
            self.push(Node(tag="ack", attrs={"id": node.attrs.get("id", ""), "class": "message"}))

    def _devices(self, node: Node) -> Node:
        requested = node.content[0].content[1].content[0].attrs["jid"]  # type: ignore[index,union-attr]
        device = "1"
        key_index = "1"
        return Node(
            tag="iq",
            attrs={"type": "result", "id": node.attrs.get("id", "")},
            content=[
                Node(
                    tag="usync",
                    content=[
                        Node(
                            tag="list",
                            content=[
                                Node(
                                    tag="user",
                                    attrs={"jid": requested},
                                    content=[
                                        Node(
                                            tag="devices",
                                            content=[
                                                Node(
                                                    tag="device-list",
                                                    content=[
                                                        Node(
                                                            tag="device",
                                                            attrs={
                                                                "id": device,
                                                                "key-index": key_index,
                                                            },
                                                        )
                                                    ],
                                                )
                                            ],
                                        )
                                    ],
                                )
                            ],
                        )
                    ],
                )
            ],
        )

    def _bundles(self, node: Node) -> Node:
        users = []
        for user in node.content[0].content:  # type: ignore[index,union-attr]
            users.append(
                Node(
                    tag="user",
                    attrs={"jid": user.attrs["jid"]},
                    content=[
                        Node(tag="registration", content=(7).to_bytes(4, "big")),
                        Node(tag="identity", content=self.peer_identity.public),
                        Node(
                            tag="skey",
                            content=[
                                Node(tag="id", content=(3).to_bytes(3, "big")),
                                Node(tag="value", content=self.peer_signed.public),
                                Node(
                                    tag="signature",
                                    content=sign(
                                        self.peer_identity.private,
                                        b"\x05" + self.peer_signed.public,
                                    ),
                                ),
                            ],
                        ),
                        Node(
                            tag="key",
                            content=[
                                Node(tag="id", content=(4).to_bytes(3, "big")),
                                Node(tag="value", content=self.peer_one_time.public),
                            ],
                        ),
                    ],
                )
            )
        return Node(
            tag="iq",
            attrs={"type": "result", "id": node.attrs.get("id", "")},
            content=[Node(tag="list", content=users)],
        )


@dataclass(frozen=True, slots=True)
class Seeded:
    credentials: DeviceCredentials
    one_time: KeyPair


async def seed(path: Path) -> Seeded:
    credentials = generate_credentials()
    one_time = generate_keypair()
    store = SessionStore(path)
    await store.open()
    try:
        raw = credentials.to_dict()
        raw["me"] = {"id": ME, "lid": None}
        await store.save_creds(raw)
        await store.add_prekeys([(5, pack_key_pair(one_time.private, one_time.public))])
    finally:
        await store.close()
    return Seeded(credentials=credentials, one_time=one_time)


def incoming_ping(server: ScriptedServer, seeded: Seeded) -> Node:
    peer = server.peer_identity
    state = initiator_session(
        peer,
        seeded.credentials.identity_public,
        seeded.credentials.signed_pre_key.key_pair.public,
        seeded.one_time.public,
        signed_pre_key_id=seeded.credentials.signed_pre_key.key_id,
        pre_key_id=5,
    )
    body = prekey_message(state, signal_encrypt(state, encode_text("/ping")), registration_id=9)
    return Node(
        tag="message",
        attrs={"id": "DEMO-1", "from": PEER, "t": "1700000000", "notify": "Alice"},
        content=[
            Node(
                tag="enc",
                attrs={"v": "2", "type": "pkmsg", "jid": PEER_DEVICE},
                content=body,
            )
        ],
    )


async def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "demo.session")
    if path.exists():
        path.unlink()
    seeded = await seed(path)
    server = ScriptedServer()
    client = Client(path, transport_factory=lambda: server, push_name="aiowapy")

    @client.router.message()
    async def answer(event: MessageEvent) -> None:
        print(f"  <- {event.sender_jid.split('@')[0]}: {event.text}")
        if (event.text or "").startswith("/ping"):
            result = await client.send_text(event.chat_jid, "pong")
            print(f"  -> pong (acked={result.acked}, id={result.message_id})")

    print(f"  connecting as {ME}")
    server.push(Node(tag="success", attrs={"jid": ME}))
    await asyncio.wait_for(client.connect(), timeout=10)
    print("  connected, devices discovered, keys published")

    server.push(incoming_ping(server, seeded))
    for _ in range(100):
        if any(node.tag == "message" for node in server.sent):
            break
        await asyncio.sleep(0.05)

    history = await client.get_chat_history(PEER)
    print(f"  session: {len(history)} messages stored in {path.name}")
    await client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
