from __future__ import annotations

import pytest

from wapy.creds import generate_credentials
from wapy.crypto.primitives import generate_keypair
from wapy.crypto.session import decrypt, responder_session, signal_key
from wapy.crypto.signal_proto import decode_prekey
from wapy.messaging.devices import DeviceError, DeviceInfo
from wapy.messaging.real import (
    StoreSignalSessions,
    StreamNodeSender,
    UsyncDeviceFetcher,
)
from wapy.protocol.bundles import build_bundle_query, parse_bundles
from wapy.protocol.usync import UsyncError, build_device_query, parse_device_jids
from wapy.protocol.wabinary import Node, decode_node, encode_node
from wapy.store import SessionStore

JID = "491234567890@s.whatsapp.net"
DEVICE = "491234567890:2@s.whatsapp.net"
PEER_DEVICE = "499999999999:1@s.whatsapp.net"


def device_list_node(devices: list[tuple[str, int, str | None]]) -> Node:
    """devices: (user@server, device id, key-index or None)."""
    users = []
    for user, device_id, key_index in devices:
        attrs = {"id": str(device_id)}
        if key_index is not None:
            attrs["key-index"] = key_index
        users.append(
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
                                content=[Node(tag="device", attrs=attrs)],
                            )
                        ],
                    )
                ],
            )
        )
    return Node(
        tag="iq",
        attrs={"type": "result"},
        content=[Node(tag="usync", attrs={}, content=[Node(tag="list", attrs={}, content=users)])],
    )


def bundle_node(
    jid: str,
    *,
    identity: bytes,
    signed: bytes,
    signed_id: int,
    signature: bytes,
    pre: bytes | None,
    pre_id: int | None,
) -> Node:
    children = [
        Node(tag="registration", attrs={}, content=(42).to_bytes(4, "big")),
        Node(tag="identity", attrs={}, content=identity),
        Node(
            tag="skey",
            attrs={},
            content=[
                Node(tag="id", attrs={}, content=signed_id.to_bytes(3, "big")),
                Node(tag="value", attrs={}, content=signed),
                Node(tag="signature", attrs={}, content=signature),
            ],
        ),
    ]
    if pre is not None and pre_id is not None:
        children.append(
            Node(
                tag="key",
                attrs={},
                content=[
                    Node(tag="id", attrs={}, content=pre_id.to_bytes(3, "big")),
                    Node(tag="value", attrs={}, content=pre),
                ],
            )
        )
    return Node(
        tag="iq",
        attrs={"type": "result"},
        content=[
            Node(
                tag="list",
                attrs={},
                content=[Node(tag="user", attrs={"jid": jid}, content=children)],
            )
        ],
    )


def test_device_query_structure() -> None:
    node = build_device_query([JID], "id-1", sid="sid-1")
    assert node.tag == "iq"
    assert node.attrs == {"to": "@s.whatsapp.net", "type": "get", "xmlns": "usync", "id": "id-1"}
    usync = node.content[0]  # type: ignore[index]
    assert usync.attrs["context"] == "interactive"
    assert usync.attrs["mode"] == "query"


def test_parse_device_jids_skips_devices_without_key_index() -> None:
    node = device_list_node(
        [
            (JID, 0, None),
            (JID, 2, "8"),
            (JID, 3, None),  # no key index and not the phone: unusable
        ]
    )
    assert parse_device_jids(node) == [JID, DEVICE]


def test_parse_device_jids_honours_exclusions() -> None:
    node = device_list_node([(JID, 0, None), (JID, 2, "8")])
    assert parse_device_jids(node, exclude={DEVICE}) == [JID]


def test_parse_device_jids_without_usync() -> None:
    with pytest.raises(UsyncError):
        parse_device_jids(Node(tag="iq"))


def test_bundle_query_structure() -> None:
    node = build_bundle_query([DEVICE, JID], "id-2")
    assert node.attrs["xmlns"] == "encrypt"
    key = node.content[0]  # type: ignore[index]
    assert key.tag == "key"
    assert [child.attrs["jid"] for child in key.content] == [DEVICE, JID]  # type: ignore[union-attr]


def test_parse_bundles() -> None:
    node = bundle_node(
        DEVICE,
        identity=b"\x01" * 32,
        signed=b"\x02" * 32,
        signed_id=7,
        signature=b"\x03" * 64,
        pre=b"\x04" * 32,
        pre_id=9,
    )
    bundles = parse_bundles(node)
    assert len(bundles) == 1
    bundle = bundles[0]
    assert bundle.jid == DEVICE
    assert bundle.registration_id == 42
    assert bundle.signed_pre_key.key_id == 7
    assert bundle.pre_key is not None and bundle.pre_key.key_id == 9


def test_parse_bundles_without_one_time_key() -> None:
    node = bundle_node(
        DEVICE,
        identity=b"\x01" * 32,
        signed=b"\x02" * 32,
        signed_id=7,
        signature=b"\x03" * 64,
        pre=None,
        pre_id=None,
    )
    bundle = parse_bundles(node)[0]
    assert bundle.pre_key is None


def test_parse_bundles_skips_error_entries() -> None:
    node = Node(
        tag="iq",
        content=[
            Node(
                tag="list",
                content=[
                    Node(
                        tag="user",
                        attrs={"jid": DEVICE},
                        content=[Node(tag="error", attrs={"code": "404"})],
                    )
                ],
            )
        ],
    )
    assert parse_bundles(node) == []


class FakeQuerier:
    def __init__(self, responses: list[Node]) -> None:
        self.responses = responses
        self.queries: list[Node] = []

    async def query(self, node: Node, *, timeout: float | None = None) -> Node:
        self.queries.append(node)
        return self.responses.pop(0)


async def test_fetcher_combines_devices_and_bundles() -> None:
    credentials = generate_credentials()
    querier = FakeQuerier(
        [
            device_list_node([(JID, 2, "8")]),
            bundle_node(
                DEVICE,
                identity=b"\x01" * 32,
                signed=b"\x02" * 32,
                signed_id=7,
                signature=b"\x03" * 64,
                pre=b"\x04" * 32,
                pre_id=9,
            ),
        ]
    )
    fetcher = UsyncDeviceFetcher(querier, credentials, id_factory=lambda: "x")
    devices = await fetcher.fetch(JID)

    assert len(devices) == 1
    assert devices[0].jid == DEVICE
    assert devices[0].identity_key == b"\x01" * 32
    assert devices[0].signed_pre_key_id == 7
    assert devices[0].pre_key_id == 9
    assert len(querier.queries) == 2


async def test_fetcher_raises_when_no_devices() -> None:
    credentials = generate_credentials()
    querier = FakeQuerier([device_list_node([])])
    fetcher = UsyncDeviceFetcher(querier, credentials)
    with pytest.raises(DeviceError):
        await fetcher.fetch(JID)


def recipient_device() -> tuple[DeviceInfo, dict[str, object]]:
    identity = generate_keypair()
    signed = generate_keypair()
    one_time = generate_keypair()
    device = DeviceInfo(
        jid=DEVICE,
        identity_key=identity.public,
        signed_pre_key=signed.public,
        signed_pre_key_id=7,
        registration_id=42,
        pre_key=one_time.public,
        pre_key_id=9,
    )
    return device, {"identity": identity, "signed": signed, "one_time": one_time}


async def test_sessions_produce_a_prekey_message_receiver_can_open(tmp_path) -> None:
    sender = generate_credentials()
    device, keys = recipient_device()
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        sessions = StoreSignalSessions(store, sender)
        encrypted = await sessions.encrypt(device, b"hello")
        assert encrypted.prekey is True

        wrapped = decode_prekey(encrypted.ciphertext[1:])
        assert wrapped.base_key
        responder = responder_session(
            keys["identity"],  # type: ignore[arg-type]
            keys["signed"],  # type: ignore[arg-type]
            signed_pre_key_id=7,
            their_identity=signal_key(sender.identity_public),
            their_base_key=wrapped.base_key,
            our_one_time_pre_key=keys["one_time"],  # type: ignore[arg-type]
        )
        assert decrypt(responder, wrapped.message) == b"hello"
    finally:
        await store.close()


async def test_second_message_reuses_the_session(tmp_path) -> None:
    sender = generate_credentials()
    device, keys = recipient_device()
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        sessions = StoreSignalSessions(store, sender)
        first = await sessions.encrypt(device, b"one")
        second = await sessions.encrypt(device, b"two")
        assert first.prekey is True
        assert second.prekey is False

        wrapped = decode_prekey(first.ciphertext[1:])
        responder = responder_session(
            keys["identity"],  # type: ignore[arg-type]
            keys["signed"],  # type: ignore[arg-type]
            signed_pre_key_id=7,
            their_identity=signal_key(sender.identity_public),
            their_base_key=wrapped.base_key,
            our_one_time_pre_key=keys["one_time"],  # type: ignore[arg-type]
        )
        assert decrypt(responder, wrapped.message) == b"one"
        assert decrypt(responder, second.ciphertext) == b"two"

        stored = await store.get_session(DEVICE)
        assert stored is not None
    finally:
        await store.close()


class FakeStream:
    def __init__(self, ack: bool) -> None:
        self.ack = ack
        self.sent: list[Node] = []

    async def send(self, node: Node) -> None:
        self.sent.append(node)

    async def wait_for_ack(self, message_id: str, *, timeout: float) -> bool:
        return self.ack


async def test_stream_sender_delegates() -> None:
    stream = FakeStream(ack=True)
    sender = StreamNodeSender(stream)
    node = Node(tag="message", attrs={"id": "1"})
    await sender.send(node)
    assert stream.sent == [node]
    assert await sender.wait_for_ack("1", timeout=1.0) is True


def test_message_node_roundtrips_before_send() -> None:
    node = build_bundle_query([DEVICE], "id")
    assert decode_node(encode_node(node)) == node


async def _pair_with_peer(tmp_path, *, prekey_id: int = 5):
    """Set up our credentials plus one stored one-time prekey, and a peer session."""
    from wapy.crypto.primitives import generate_keypair
    from wapy.crypto.session import initiator_session
    from wapy.protocol.prekeys import pack_key_pair

    ours = generate_credentials()
    one_time = generate_keypair()
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    await store.save_creds(ours.to_dict())
    await store.add_prekeys([(prekey_id, pack_key_pair(one_time.private, one_time.public))])

    peer_identity = generate_keypair()
    peer_state = initiator_session(
        peer_identity,
        ours.identity_public,
        ours.signed_pre_key.key_pair.public,
        one_time.public,
        signed_pre_key_id=ours.signed_pre_key.key_id,
        pre_key_id=prekey_id,
    )
    return ours, store, peer_identity, peer_state


async def test_decrypt_prekey_message_and_then_normal_one(tmp_path) -> None:
    from wapy.crypto.session import encrypt as signal_encrypt
    from wapy.crypto.session import prekey_message
    from wapy.messaging.real import StoreSignalSessionsWithDecrypt

    ours, store, peer_identity, peer_state = await _pair_with_peer(tmp_path)
    try:
        session_client = StoreSignalSessionsWithDecrypt(store, ours)
        first = signal_encrypt(peer_state, b"hello")
        wrapped = prekey_message(peer_state, first, registration_id=99)

        assert await session_client.decrypt(PEER_DEVICE, wrapped, prekey=True) == b"hello"
        second = signal_encrypt(peer_state, b"again")
        assert await session_client.decrypt(PEER_DEVICE, second, prekey=False) == b"again"
    finally:
        await store.close()


async def test_decrypt_consumes_the_one_time_prekey(tmp_path) -> None:
    from wapy.crypto.session import encrypt as signal_encrypt
    from wapy.crypto.session import prekey_message
    from wapy.messaging.real import StoreSignalSessionsWithDecrypt

    ours, store, _peer_identity, peer_state = await _pair_with_peer(tmp_path)
    try:
        session_client = StoreSignalSessionsWithDecrypt(store, ours)
        wrapped = prekey_message(peer_state, signal_encrypt(peer_state, b"x"), registration_id=1)
        await session_client.decrypt(PEER_DEVICE, wrapped, prekey=True)
        assert await store.get_prekey(5) is None
    finally:
        await store.close()


async def test_decrypt_without_session_fails(tmp_path) -> None:
    from wapy.messaging.real import SessionSendError, StoreSignalSessionsWithDecrypt

    ours = generate_credentials()
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        session_client = StoreSignalSessionsWithDecrypt(store, ours)
        with pytest.raises(SessionSendError):
            await session_client.decrypt(PEER_DEVICE, b"\x33" + bytes(40), prekey=False)
    finally:
        await store.close()


class FakeSessionsForReceive:
    def __init__(self, plaintext: bytes | None) -> None:
        self.plaintext = plaintext

    async def encrypt(self, device, plaintext):  # pragma: no cover - not used
        raise NotImplementedError

    async def decrypt(self, device_jid: str, ciphertext: bytes, *, prekey: bool) -> bytes:
        if self.plaintext is None:
            raise RuntimeError("no session")
        return self.plaintext


async def test_receiver_extracts_text() -> None:
    from wapy.messaging.receiving import MessageReceiver
    from wapy.protocol.messages import EncryptedDevice, build_message_node, encode_text

    node = build_message_node(
        "me@s.whatsapp.net",
        "MSG-1",
        [EncryptedDevice(PEER_DEVICE, b"ignored")],
    )
    node.attrs["from"] = "peer@s.whatsapp.net"
    node.attrs.pop("to", None)

    receiver = MessageReceiver(FakeSessionsForReceive(encode_text("hi there")))
    received = await receiver.receive(node)

    assert received.text == "hi there"
    assert received.message_id == "MSG-1"
    assert received.chat_jid == "peer@s.whatsapp.net"
    assert received.device_jid == PEER_DEVICE


async def test_receiver_reports_devices_when_all_fail() -> None:
    from wapy.messaging.receiving import DecryptError, MessageReceiver
    from wapy.protocol.messages import EncryptedDevice, build_message_node

    node = build_message_node(
        "me@s.whatsapp.net",
        "MSG-2",
        [EncryptedDevice(PEER_DEVICE, b"a"), EncryptedDevice("other:1@s.whatsapp.net", b"b")],
    )
    node.attrs["from"] = "peer@s.whatsapp.net"

    receiver = MessageReceiver(FakeSessionsForReceive(None))
    with pytest.raises(DecryptError) as error:
        await receiver.receive(node)
    assert error.value.devices == [PEER_DEVICE, "other:1@s.whatsapp.net"]
