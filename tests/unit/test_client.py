from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

import pytest

from wapy.client import ClientError, WhatsAppClient
from wapy.creds import DeviceCredentials, generate_credentials
from wapy.crypto.primitives import KeyPair, generate_keypair
from wapy.crypto.session import encrypt as signal_encrypt
from wapy.crypto.session import initiator_session, prekey_message
from wapy.crypto.xeddsa import sign
from wapy.events import ConnectedEvent, DisconnectedEvent, MessageEvent, ReceiptEvent
from wapy.protocol.messages import encode_text
from wapy.protocol.prekeys import pack_key_pair
from wapy.protocol.stream import child
from wapy.protocol.wabinary import Node, decode_node, encode_node
from wapy.store import SessionStore

ME = "491111111111:1@s.whatsapp.net"


@dataclass(frozen=True)
class Credentials:
    account: DeviceCredentials
    peer_identity: KeyPair
    one_time: KeyPair


PEER = "492222222222@s.whatsapp.net"
PEER_DEVICE = "492222222222:1@s.whatsapp.net"
GROUP = "120363000000000001@g.us"


class FakeServer:
    """Plays the server side of one connection: answers what the client asks."""

    def __init__(self) -> None:
        self.inbox: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.sent: list[Node] = []
        self.closed = False
        self.connected = False
        self.peer_identity = generate_keypair()
        self.peer_signed = generate_keypair()
        self.peer_one_time = generate_keypair()

    async def connect(self) -> None:
        self.connected = True

    async def close(self) -> None:
        self.closed = True

    async def handshake(self, key_pair: object = None, client_payload: bytes = b"") -> object:
        return object()

    async def send_encrypted(self, payload: bytes) -> None:
        node = decode_node(payload)
        self.sent.append(node)
        self._auto_respond(node)

    async def recv_encrypted(self) -> bytes:
        frame = await self.inbox.get()
        if frame is None:
            raise ConnectionError("closed by the test")
        return frame

    def push(self, node: Node) -> None:
        self.inbox.put_nowait(encode_node(node))

    def nodes(self, tag: str) -> list[Node]:
        return [node for node in self.sent if node.tag == tag]

    # -- server behaviour ---------------------------------------------------

    def _auto_respond(self, node: Node) -> None:
        if node.tag == "iq" and node.attrs.get("xmlns") == "w:m":
            self.push(
                Node(
                    tag="iq",
                    attrs={"type": "result", "id": node.attrs.get("id", "")},
                    content=[
                        Node(
                            tag="media_conn",
                            attrs={"auth": "auth", "ttl": "600"},
                            content=[Node(tag="host", attrs={"hostname": "media.example"})],
                        )
                    ],
                )
            )
        elif node.tag == "iq" and node.attrs.get("xmlns") == "w:g2":
            if node.attrs.get("type") == "get":
                self.push(self._group_info(node))
            else:
                action = next(
                    (
                        item
                        for item in node.content
                        if item.tag in ("add", "remove", "promote", "demote")
                    ),  # type: ignore[union-attr]
                    None,
                )
                content = []
                if action is not None:
                    content = [Node(tag=action.tag, attrs={}, content=list(action.content or []))]
                self.push(
                    Node(
                        tag="iq",
                        attrs={"type": "result", "id": node.attrs.get("id", "")},
                        content=content,
                    )
                )
        elif node.tag == "iq" and node.attrs.get("xmlns") == "usync":
            self.push(self._device_list(node))
        elif (
            node.tag == "iq"
            and node.attrs.get("xmlns") == "encrypt"
            and node.attrs.get("type") == "get"
        ):
            self.push(self._bundles(node))
        elif node.tag == "iq":
            self.push(Node(tag="iq", attrs={"id": node.attrs.get("id", ""), "type": "result"}))
        elif node.tag == "message":
            self.push(
                Node(
                    tag="ack",
                    attrs={"id": node.attrs.get("id", ""), "class": "message"},
                )
            )

    def _group_info(self, node: Node) -> Node:
        return Node(
            tag="iq",
            attrs={"type": "result", "id": node.attrs.get("id", "")},
            content=[
                Node(
                    tag="group",
                    attrs={"id": GROUP.split("@")[0], "subject": "Team"},
                    content=[
                        Node(tag="participant", attrs={"jid": PEER}),
                        Node(
                            tag="participant", attrs={"jid": ME.split(":")[0] + "@s.whatsapp.net"}
                        ),
                    ],
                )
            ],
        )

    def _device_list(self, node: Node) -> Node:
        usync = node.content[0]  # type: ignore[index]
        user = usync.content[1].content[0].attrs["jid"]  # type: ignore[index,union-attr]
        return Node(
            tag="iq",
            attrs={"type": "result", "id": node.attrs.get("id", "")},
            content=[
                Node(
                    tag="usync",
                    attrs={},
                    content=[
                        Node(
                            tag="list",
                            attrs={},
                            content=[
                                Node(
                                    tag="user",
                                    attrs={"jid": user},
                                    content=[
                                        Node(
                                            tag="devices",
                                            attrs={},
                                            content=[
                                                Node(
                                                    tag="device-list",
                                                    attrs={},
                                                    content=[
                                                        Node(
                                                            tag="device",
                                                            attrs={"id": "1", "key-index": "1"},
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
        users = [
            Node(
                tag="user",
                attrs={"jid": user.attrs["jid"]},
                content=[
                    Node(tag="registration", attrs={}, content=(7).to_bytes(4, "big")),
                    Node(tag="identity", attrs={}, content=self.peer_identity.public),
                    Node(
                        tag="skey",
                        attrs={},
                        content=[
                            Node(tag="id", attrs={}, content=(3).to_bytes(3, "big")),
                            Node(tag="value", attrs={}, content=self.peer_signed.public),
                            Node(
                                tag="signature",
                                attrs={},
                                content=sign(
                                    self.peer_identity.private, b"\x05" + self.peer_signed.public
                                ),
                            ),
                        ],
                    ),
                    Node(
                        tag="key",
                        attrs={},
                        content=[
                            Node(tag="id", attrs={}, content=(4).to_bytes(3, "big")),
                            Node(tag="value", attrs={}, content=self.peer_one_time.public),
                        ],
                    ),
                ],
            )
            for user in node.content[0].content  # type: ignore[index,union-attr]
        ]
        return Node(
            tag="iq",
            attrs={"type": "result", "id": node.attrs.get("id", "")},
            content=[Node(tag="list", attrs={}, content=users)],
        )


async def seeded_store(path: Path, credentials: DeviceCredentials) -> None:
    store = SessionStore(path)
    await store.open()
    try:
        stored = credentials.to_dict()
        stored["me"] = {"id": ME, "lid": None}
        await store.save_creds(stored)
    finally:
        await store.close()


def incoming_text(
    credentials: DeviceCredentials,
    text: str,
    *,
    peer_identity: KeyPair,
    one_time: KeyPair,
    one_time_id: int,
) -> Node:
    state = initiator_session(
        peer_identity,
        credentials.identity_public,
        credentials.signed_pre_key.key_pair.public,
        one_time.public,
        signed_pre_key_id=credentials.signed_pre_key.key_id,
        pre_key_id=one_time_id,
    )
    body = prekey_message(state, signal_encrypt(state, encode_text(text)), registration_id=9)
    return Node(
        tag="message",
        attrs={"id": "IN-1", "from": PEER, "t": "1700000000", "type": "text"},
        content=[
            Node(tag="enc", attrs={"v": "2", "type": "pkmsg", "jid": PEER_DEVICE}, content=body)
        ],
    )


async def connected_client(
    tmp_path: Path, *, auto_receipts: bool = True
) -> tuple[WhatsAppClient, FakeServer, Credentials]:
    credentials = generate_credentials()
    server = FakeServer()
    path = tmp_path / "bot.session"
    await seeded_store(path, credentials)
    store = SessionStore(path)
    await store.open()
    one_time = generate_keypair()
    await store.add_prekeys([(5, pack_key_pair(one_time.private, one_time.public))])
    await store.close()

    client = WhatsAppClient(
        path,
        transport_factory=lambda: server,
        auto_receipts=auto_receipts,
        push_name="bot",
    )
    server.push(Node(tag="success", attrs={"jid": ME, "lid": None}))
    await asyncio.wait_for(client.connect(), timeout=5)
    return client, server, Credentials(credentials, generate_keypair(), one_time)


async def test_connect_announces_presence(tmp_path: Path) -> None:
    client, server, _credentials = await connected_client(tmp_path)
    try:
        assert client.info is not None
        assert client.info.jid == ME
        presence = server.nodes("presence")
        assert presence and presence[0].attrs["type"] == "available"
        assert presence[0].attrs["name"] == "bot"
        assert client.connected
    finally:
        await client.close()


async def test_incoming_message_is_stored(tmp_path: Path) -> None:
    client, server, credentials = await connected_client(tmp_path)
    received: asyncio.Queue[MessageEvent] = asyncio.Queue()
    try:
        client.router.message()(received.put_nowait)
        node = incoming_text(
            credentials.account,
            "stored hello",
            peer_identity=credentials.peer_identity,
            one_time=credentials.one_time,
            one_time_id=5,
        )
        node.attrs["notify"] = "Alice"
        server.push(node)
        await asyncio.wait_for(received.get(), timeout=5)

        history = await client.get_chat_history(PEER)
        assert [message.text for message in history] == ["stored hello"]
        assert history[0].sender_jid == PEER
        assert history[0].timestamp == 1_700_000_000
        assert history[0].outgoing is False

        chat = await client.get_chat(PEER)
        assert chat is not None
        assert chat.push_name == "Alice"
        assert chat.name == "Alice"
    finally:
        await client.close()


async def test_sent_message_is_stored(tmp_path: Path) -> None:
    client, _server, _credentials = await connected_client(tmp_path)
    try:
        result = await client.send_text(PEER, "ping")
        history = await client.get_chat_history(PEER)
        assert len(history) == 1
        message = history[0]
        assert message.message_id == result.message_id
        assert message.text == "ping"
        assert message.outgoing is True
        assert message.sender_jid == ME

        chats = await client.get_chats()
        assert chats and chats[0].jid == PEER
        assert chats[0].total_messages == 1
    finally:
        await client.close()


async def test_contact_names_and_user_listing(tmp_path: Path) -> None:
    client, server, credentials = await connected_client(tmp_path)
    received: asyncio.Queue[MessageEvent] = asyncio.Queue()
    try:
        client.router.message()(received.put_nowait)
        server.push(
            incoming_text(
                credentials.account,
                "привет",
                peer_identity=credentials.peer_identity,
                one_time=credentials.one_time,
                one_time_id=5,
            )
        )
        await asyncio.wait_for(received.get(), timeout=5)

        await client.set_contact_name(PEER, "Мама")
        chat = await client.get_chat(PEER)
        assert chat is not None and chat.name == "Мама"

        users = await client.get_users()
        assert any(user.jid == PEER for user in users)
        assert await client.get_groups() == []
    finally:
        await client.close()


async def test_history_paging(tmp_path: Path) -> None:
    client, _server, _credentials = await connected_client(tmp_path)
    try:
        for index in range(5):
            await client._record_outgoing(PEER, f"M{index}", encode_text(f"t{index}"))
        page = await client.get_chat_history(PEER, limit=2)
        assert [message.message_id for message in page] == ["M4", "M3"]
        older = await client.get_chat_history(PEER, limit=2, before_timestamp=page[-1].timestamp)
        assert all(message.message_id not in {"M4", "M3"} for message in older)
    finally:
        await client.close()


async def test_incoming_text_reaches_the_router(tmp_path: Path) -> None:
    client, server, credentials = await connected_client(tmp_path)
    received: asyncio.Queue[MessageEvent] = asyncio.Queue()
    try:
        client.router.message()(received.put_nowait)
        server.push(
            incoming_text(
                credentials.account,
                "hello from a peer",
                peer_identity=credentials.peer_identity,
                one_time=credentials.one_time,
                one_time_id=5,
            )
        )
        event = await asyncio.wait_for(received.get(), timeout=5)
        assert event.text == "hello from a peer"
        assert event.chat_jid == PEER
        assert event.sender_jid == PEER
        assert event.timestamp == 1_700_000_000
        receipts = server.nodes("receipt")
        assert receipts and receipts[0].attrs["type"] == "delivery"
    finally:
        await client.close()


async def test_undecryptable_message_asks_for_a_retry(tmp_path: Path) -> None:
    client, server, _credentials = await connected_client(tmp_path)
    try:
        server.push(
            Node(
                tag="message",
                attrs={"id": "BROKEN", "from": PEER, "t": "1700000000"},
                content=[
                    Node(
                        tag="enc",
                        attrs={"v": "2", "type": "msg", "jid": PEER_DEVICE},
                        content=b"\x33" + b"\x00" * 40,
                    )
                ],
            )
        )
        for _ in range(100):
            if server.nodes("receipt"):
                break
            await asyncio.sleep(0.01)
        receipts = server.nodes("receipt")
        assert receipts
        receipt = receipts[0]
        assert receipt.attrs["type"] == "retry"
        assert receipt.attrs["id"] == "BROKEN"
        assert receipt.attrs["to"] == PEER
        retry = child(receipt, "retry")
        assert retry is not None and retry.attrs["count"] == "1"
        assert child(receipt, "registration") is not None
    finally:
        await client.close()


async def test_send_text_encrypts_for_every_device(tmp_path: Path) -> None:
    client, server, _credentials = await connected_client(tmp_path)
    try:
        result = await client.send_text(PEER, "ping")
        assert result.sent == [PEER_DEVICE]
        assert result.acked is True
        messages = server.nodes("message")
        assert messages and messages[0].attrs["to"] == PEER
        participants = messages[0].content[0]  # type: ignore[index]
        assert participants.tag == "participants"
        enc = participants.content[0]  # type: ignore[index,union-attr]
        assert enc.attrs["type"] == "pkmsg"
        assert enc.attrs["jid"] == PEER_DEVICE
        assert messages[0].attrs["phash"].startswith("2:")
    finally:
        await client.close()


async def test_retry_request_resends_the_message(tmp_path: Path) -> None:
    client, server, _credentials = await connected_client(tmp_path)
    try:
        result = await client.send_text(PEER, "ping")
        retries_before = len(server.nodes("message"))
        server.push(
            Node(
                tag="receipt",
                attrs={"id": result.message_id, "from": PEER, "type": "retry", "t": "1"},
                content=[
                    Node(
                        tag="retry",
                        attrs={"count": "1", "id": result.message_id, "t": "1", "v": "1"},
                    )
                ],
            )
        )
        for _ in range(100):
            if len(server.nodes("message")) > retries_before:
                break
            await asyncio.sleep(0.01)
        assert len(server.nodes("message")) > retries_before
    finally:
        await client.close()


async def test_read_receipts_reach_the_router(tmp_path: Path) -> None:
    client, server, _credentials = await connected_client(tmp_path)
    receipts: asyncio.Queue[ReceiptEvent] = asyncio.Queue()
    try:
        client.router.on(ReceiptEvent)(receipts.put_nowait)
        server.push(
            Node(
                tag="receipt",
                attrs={"id": "M1", "from": PEER, "type": "read", "t": "1700000000"},
            )
        )
        event = await asyncio.wait_for(receipts.get(), timeout=5)
        assert event.receipt_type == "read"
        assert event.message_ids == ("M1",)
    finally:
        await client.close()


async def test_mark_read_sends_a_receipt(tmp_path: Path) -> None:
    client, server, credentials = await connected_client(tmp_path, auto_receipts=False)
    received: asyncio.Queue[MessageEvent] = asyncio.Queue()
    try:
        client.router.message()(received.put_nowait)
        server.push(
            incoming_text(
                credentials.account,
                "hi",
                peer_identity=credentials.peer_identity,
                one_time=credentials.one_time,
                one_time_id=5,
            )
        )
        event = await asyncio.wait_for(received.get(), timeout=5)
        assert server.nodes("receipt") == []
        await client.mark_read(event)
        receipts = server.nodes("receipt")
        assert receipts and receipts[0].attrs["type"] == "read"
    finally:
        await client.close()


async def test_presence_and_typing_helpers(tmp_path: Path) -> None:
    client, server, _credentials = await connected_client(tmp_path)
    try:
        await client.send_presence(available=False)
        await client.subscribe_presence(PEER)
        await client.send_typing(PEER, composing=True)
        presence = server.nodes("presence")
        unavailable = [node for node in presence if node.attrs.get("type") == "unavailable"]
        assert unavailable
        subscribe = [node for node in presence if node.attrs.get("type") == "subscribe"]
        assert subscribe and subscribe[0].attrs["to"] == PEER
        chatstate = server.nodes("chatstate")
        assert chatstate and chatstate[0].content[0].tag == "composing"  # type: ignore[index]
    finally:
        await client.close()


async def test_connected_and_disconnected_events(tmp_path: Path) -> None:
    credentials = generate_credentials()
    server = FakeServer()
    path = tmp_path / "bot.session"
    await seeded_store(path, credentials)
    client = WhatsAppClient(path, transport_factory=lambda: server, reconnect=False)
    events: list[object] = []
    client.router.on(ConnectedEvent)(events.append)
    client.router.on(DisconnectedEvent)(events.append)
    server.push(Node(tag="success", attrs={"jid": ME}))
    await asyncio.wait_for(client.connect(), timeout=5)
    server.inbox.put_nowait(None)  # drop the connection
    for _ in range(100):
        if any(isinstance(event, DisconnectedEvent) for event in events):
            break
        await asyncio.sleep(0.01)
    await client.close()
    assert any(isinstance(event, ConnectedEvent) for event in events)
    assert any(isinstance(event, DisconnectedEvent) for event in events)


async def test_send_text_without_connection_fails(tmp_path: Path) -> None:
    client = WhatsAppClient(tmp_path / "bot.session")
    with pytest.raises(ClientError):
        await client.send_text(PEER, "hi")


async def test_double_connect_is_rejected(tmp_path: Path) -> None:
    client, _server, _credentials = await connected_client(tmp_path)
    try:
        with pytest.raises(ClientError):
            await client.connect()
    finally:
        await client.close()


async def test_send_text_to_a_group_uses_sender_keys(tmp_path: Path) -> None:
    client, server, _credentials = await connected_client(tmp_path)
    try:
        result = await client.send_text(GROUP, "hello group")
        assert result.acked is True
        node = server.nodes("message")[-1]
        assert node.attrs["to"] == GROUP
        assert node.attrs["phash"].startswith("2:")
        kinds = [item.attrs["type"] for item in node.content if item.tag == "enc"]
        assert kinds == ["skmsg"]
    finally:
        await client.close()


async def test_incoming_group_message_is_decrypted(tmp_path: Path) -> None:
    from wapy.crypto.sender_key import SenderKeyState, distribution_message, encrypt
    from wapy.protocol.messages import encode_sender_key_distribution, group_enc_node

    client, server, credentials = await connected_client(tmp_path)
    received: asyncio.Queue[MessageEvent] = asyncio.Queue()
    try:
        client.router.message()(received.put_nowait)

        sender_state = SenderKeyState.create(key_id=5)
        skdm = encode_sender_key_distribution(GROUP, distribution_message(sender_state))
        peer = generate_keypair()
        state = initiator_session(
            peer,
            credentials.account.identity_public,
            credentials.account.signed_pre_key.key_pair.public,
            credentials.one_time.public,
            signed_pre_key_id=credentials.account.signed_pre_key.key_id,
            pre_key_id=5,
        )
        envelope = prekey_message(state, signal_encrypt(state, skdm), registration_id=9)
        server.push(
            Node(
                tag="message",
                attrs={"id": "G-1", "from": GROUP, "participant": PEER, "t": "1700000001"},
                content=[
                    Node(
                        tag="enc",
                        attrs={"v": "2", "type": "pkmsg", "jid": PEER_DEVICE},
                        content=envelope,
                    ),
                    group_enc_node(encrypt(sender_state, encode_text("group hello"))),
                ],
            )
        )
        event = await asyncio.wait_for(received.get(), timeout=5)
        assert event.text == "group hello"
        assert event.chat_jid == GROUP
        assert event.sender_jid == PEER
    finally:
        await client.close()


class FakeMediaTransport:
    def __init__(self) -> None:
        self.posts: list[tuple[str, bytes, dict[str, str]]] = []
        self.download_payload = b""

    async def post(self, url: str, data: bytes, headers: dict[str, str]) -> bytes:
        self.posts.append((url, data, headers))
        return b'{"url": "https://mmg.example/blob", "direct_path": "/v/t62/blob"}'

    async def get(self, url: str) -> bytes:
        return self.download_payload


async def test_send_image_uploads_and_sends(tmp_path: Path) -> None:
    credentials = generate_credentials()
    server = FakeServer()
    media = FakeMediaTransport()
    path = tmp_path / "bot.session"
    await seeded_store(path, credentials)
    client = WhatsAppClient(path, transport_factory=lambda: server, media_transport=media)
    server.push(Node(tag="success", attrs={"jid": ME}))
    await asyncio.wait_for(client.connect(), timeout=5)
    try:
        picture = b"\x89PNG" + b"x" * 64
        result = await client.send_image(PEER, picture, caption="look")
        assert result.acked is True
        node = server.nodes("message")[-1]
        assert node.attrs["type"] == "image"
        url, payload, _headers = media.posts[0]
        assert "mms/image/" in url
        assert len(payload) > len(picture)
    finally:
        await client.close()


async def test_download_media_decrypts(tmp_path: Path) -> None:
    import hashlib

    from wapy.crypto.media import encrypt_media
    from wapy.protocol.media import MEDIA_IMAGE, MediaInfo

    credentials = generate_credentials()
    server = FakeServer()
    media = FakeMediaTransport()
    path = tmp_path / "bot.session"
    await seeded_store(path, credentials)
    client = WhatsAppClient(path, transport_factory=lambda: server, media_transport=media)
    server.push(Node(tag="success", attrs={"jid": ME}))
    await asyncio.wait_for(client.connect(), timeout=5)
    try:
        plaintext = b"attachment bytes"
        media_key = b"\x07" * 32
        encrypted = encrypt_media(media_key, MEDIA_IMAGE, plaintext)
        media.download_payload = encrypted.payload
        info = MediaInfo(
            media_type=MEDIA_IMAGE,
            mime_type="image/png",
            url="https://mmg.example/blob",
            direct_path="/v/t62/blob",
            media_key=media_key,
            file_sha256=hashlib.sha256(plaintext).digest(),
            file_enc_sha256=encrypted.file_enc_sha256,
            file_length=len(plaintext),
        )
        assert await client.download_media(info) == plaintext
    finally:
        await client.close()


async def test_group_helpers_use_the_group_service(tmp_path: Path) -> None:
    client, server, _credentials = await connected_client(tmp_path)
    try:
        info = await client.group_info(GROUP)
        assert info.jid == GROUP
        assert info.subject == "Team"
        participants = await client.update_group_participants(GROUP, "add", [PEER])
        assert [item.jid for item in participants] == [PEER]
    finally:
        await client.close()


async def test_app_state_keys_are_stored_and_synced(tmp_path: Path) -> None:
    from wapy.crypto.primitives import hkdf
    from wapy.pb import bytes_field, message_field, varint_field
    from wapy.protocol.appstate import expand_keys

    client, server, credentials = await connected_client(tmp_path)
    try:
        key_id = b"\x09\x08\x07\x06"
        key_data = bytes(range(32))
        share = message_field(
            1,
            bytes_field(1, bytes_field(1, key_id)) + bytes_field(2, bytes_field(1, key_data)),
        )
        protocol = varint_field(2, 6) + bytes_field(7, share)
        payload = message_field(12, protocol)

        peer = generate_keypair()
        state = initiator_session(
            peer,
            credentials.account.identity_public,
            credentials.account.signed_pre_key.key_pair.public,
            credentials.one_time.public,
            signed_pre_key_id=credentials.account.signed_pre_key.key_id,
            pre_key_id=5,
        )
        envelope = prekey_message(state, signal_encrypt(state, payload), registration_id=9)
        server.push(
            Node(
                tag="message",
                attrs={"id": "KEY-1", "from": PEER, "t": "1"},
                content=[
                    Node(
                        tag="enc",
                        attrs={"v": "2", "type": "pkmsg", "jid": PEER_DEVICE},
                        content=envelope,
                    )
                ],
            )
        )
        for _ in range(100):
            if client._store is not None:
                stored = await client._store.get_app_state_key(key_id)
                if stored == key_data:
                    break
            await asyncio.sleep(0.01)
        assert client._store is not None
        assert await client._store.get_app_state_key(key_id) == key_data
        assert expand_keys(key_data).value_mac != hkdf(key_data, 32, b"x")
    finally:
        await client.close()


async def test_reconnect_after_a_dropped_connection(tmp_path: Path) -> None:
    credentials = generate_credentials()
    server = FakeServer()
    path = tmp_path / "bot.session"
    await seeded_store(path, credentials)
    client = WhatsAppClient(
        path,
        transport_factory=lambda: server,
        push_name="bot",
        reconnect_delay=0.05,
        max_reconnect_delay=0.05,
    )
    connects: list[ConnectedEvent] = []
    client.router.on(ConnectedEvent)(connects.append)
    server.push(Node(tag="success", attrs={"jid": ME}))
    await asyncio.wait_for(client.connect(), timeout=5)
    try:
        server.inbox.put_nowait(None)  # drop the connection
        for _ in range(200):
            if connects:
                break
            await asyncio.sleep(0.01)
        server.push(Node(tag="success", attrs={"jid": ME}))
        for _ in range(200):
            if client.connected and connects:
                break
            await asyncio.sleep(0.01)
        assert connects, "the client never reconnected"
        assert client.connected
    finally:
        await client.close()


async def test_logged_out_stream_error_stops_reconnecting(tmp_path: Path) -> None:
    credentials = generate_credentials()
    server = FakeServer()
    path = tmp_path / "bot.session"
    await seeded_store(path, credentials)
    client = WhatsAppClient(
        path,
        transport_factory=lambda: server,
        reconnect_delay=0.05,
        max_reconnect_delay=0.05,
    )
    disconnects: list[DisconnectedEvent] = []
    server.push(Node(tag="success", attrs={"jid": ME}))
    await asyncio.wait_for(client.connect(), timeout=5)
    client.router.on(DisconnectedEvent)(disconnects.append)
    server.push(Node(tag="stream:error", attrs={"code": "401"}))
    for _ in range(200):
        if disconnects:
            break
        await asyncio.sleep(0.01)
    await asyncio.wait_for(client.run(), timeout=5)
    assert disconnects and "401" in disconnects[-1].reason
    assert not client.connected
