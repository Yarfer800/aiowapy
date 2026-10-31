from __future__ import annotations

import pytest

from wapy.crypto.sender_key import (
    SenderKeyState,
    distribution_message,
    encrypt,
    from_distribution,
)
from wapy.crypto.sender_key import (
    decrypt as sk_decrypt,
)
from wapy.messaging.devices import DeviceInfo
from wapy.messaging.groups import (
    GroupSender,
    GroupSendError,
    GroupService,
    StoreSenderKeys,
    group_info_from_dict,
    group_info_to_dict,
    participant_hash,
)
from wapy.messaging.receiving import DecryptError, MessageReceiver
from wapy.protocol.groups import (
    ACTION_ADD,
    ACTION_REMOVE,
    ADMIN,
    SUPERADMIN,
    GroupError,
    build_create_group,
    build_group_info_query,
    build_joined_groups_query,
    build_leave_group,
    build_participants_update,
    parse_created_group,
    parse_group_info,
    parse_joined_groups,
    parse_participants_update,
)
from wapy.protocol.messages import (
    EncryptedDevice,
    encode_text,
    group_enc_node,
    parse_message,
)
from wapy.protocol.wabinary import Node, decode_node, encode_node
from wapy.store import SessionStore

GROUP = "120363000000000001@g.us"
OWN = "491111111111:1@s.whatsapp.net"
PEER = "492222222222@s.whatsapp.net"
PEER_DEVICE = "492222222222:1@s.whatsapp.net"


def group_node() -> Node:
    return Node(
        tag="iq",
        attrs={"type": "result"},
        content=[
            Node(
                tag="group",
                attrs={"id": GROUP.split("@")[0], "subject": "Team", "size": "3", "creator": PEER},
                content=[
                    Node(tag="participant", attrs={"jid": PEER, "type": ADMIN}),
                    Node(tag="participant", attrs={"jid": OWN, "type": SUPERADMIN}),
                    Node(tag="participant", attrs={"jid": "493333333333@s.whatsapp.net"}),
                    Node(tag="announcement", attrs={}),
                    Node(tag="ephemeral", attrs={"expiration": "86400"}),
                    Node(
                        tag="description",
                        attrs={"id": "D1"},
                        content=[Node(tag="body", attrs={}, content=b"hello")],
                    ),
                ],
            )
        ],
    )


def test_group_info_query_shape() -> None:
    node = build_group_info_query(GROUP, "id-1")
    assert node.tag == "iq"
    assert node.attrs == {"to": GROUP, "type": "get", "xmlns": "w:g2", "id": "id-1"}
    assert node.content[0].tag == "query"  # type: ignore[index]


def test_parse_group_info() -> None:
    info = parse_group_info(group_node())
    assert info.jid == GROUP
    assert info.subject == "Team"
    assert info.owner_jid == PEER
    assert len(info.participants) == 3
    assert info.participants[0].is_admin
    assert info.participants[1].is_super_admin
    assert info.is_announce is True
    assert info.is_ephemeral is True
    assert info.disappearing_timer == 86400
    assert info.topic == "hello"
    assert info.topic_id == "D1"
    assert info.participant_count == 3


def test_parse_group_info_requires_a_group_node() -> None:
    with pytest.raises(GroupError):
        parse_group_info(Node(tag="iq"))


def test_group_info_survives_the_cache_format() -> None:
    info = parse_group_info(group_node())
    restored = group_info_from_dict(group_info_to_dict(info))
    assert restored == info


def test_create_group_node() -> None:
    node = build_create_group("Team", [PEER, PEER_DEVICE], "id-2")
    create = node.content[0]  # type: ignore[index]
    assert create.tag == "create"
    assert create.attrs["subject"] == "Team"
    assert [item.attrs["jid"] for item in create.content] == [PEER, PEER]  # devices stripped


def test_create_group_needs_participants() -> None:
    with pytest.raises(GroupError):
        build_create_group("Team", [], "id")


def test_participants_update_node() -> None:
    node = build_participants_update(GROUP, ACTION_ADD, [PEER], "id-3")
    assert node.attrs["type"] == "set"
    assert node.content[0].tag == "add"  # type: ignore[index]


def test_unknown_participant_action_is_rejected() -> None:
    with pytest.raises(GroupError):
        build_participants_update(GROUP, "kick", [PEER], "id")


def test_parse_participants_update() -> None:
    node = Node(
        tag="iq",
        content=[
            Node(
                tag=ACTION_REMOVE,
                content=[Node(tag="participant", attrs={"jid": PEER})],
            )
        ],
    )
    participants = parse_participants_update(node, ACTION_REMOVE)
    assert participants[0].jid == PEER


def test_leave_and_joined_groups_nodes() -> None:
    leave = build_leave_group(GROUP, "id-4")
    assert leave.attrs["to"] == "@g.us"
    assert leave.content[0].tag == "leave"  # type: ignore[index]
    joined = build_joined_groups_query("id-5")
    assert joined.content[0].tag == "participating"  # type: ignore[index]


def test_parse_created_group() -> None:
    node = Node(tag="iq", content=[Node(tag="group", attrs={"id": "123"})])
    assert parse_created_group(node) == "123@g.us"
    with pytest.raises(GroupError):
        parse_created_group(Node(tag="iq"))


def test_parse_joined_groups() -> None:
    node = Node(
        tag="iq",
        content=[Node(tag="groups", content=[group_node().content[0], group_node().content[0]])],  # type: ignore[index]
    )
    assert len(parse_joined_groups(node)) == 2


def test_group_nodes_roundtrip() -> None:
    for node in (
        build_group_info_query(GROUP, "1"),
        build_create_group("T", [PEER], "2"),
        build_leave_group(GROUP, "3"),
        build_participants_update(GROUP, ACTION_ADD, [PEER], "4"),
    ):
        assert decode_node(encode_node(node)) == node


def test_participant_hash_is_stable_and_sorted() -> None:
    first = participant_hash(["b@s", "a@s"])
    second = participant_hash(["a@s", "b@s"])
    assert first == second
    assert first.startswith("2:")
    assert len(first) == 10


class FakeSessions:
    def __init__(self) -> None:
        self.plaintexts: list[bytes] = []

    async def encrypt(self, device: DeviceInfo, plaintext: bytes) -> EncryptedDevice:
        self.plaintexts.append(plaintext)
        return EncryptedDevice(device_jid=device.jid, ciphertext=b"cipher")

    async def decrypt(self, device_jid: str, ciphertext: bytes, *, prekey: bool) -> bytes:
        raise NotImplementedError


class FakeResolver:
    def __init__(self, devices: dict[str, list[DeviceInfo]]) -> None:
        self._devices = devices

    async def devices(self, jid: str) -> list[DeviceInfo]:
        return self._devices.get(jid, [])


class FakeDirectory:
    def __init__(self, participants: list[str]) -> None:
        self._participants = participants
        self.invalidated: list[str] = []

    async def participants(self, group_jid: str) -> list[str]:
        return self._participants

    def invalidate(self, group_jid: str) -> None:
        self.invalidated.append(group_jid)


class FakeNodeSender:
    def __init__(self) -> None:
        self.sent: list[Node] = []

    async def send(self, node: Node) -> None:
        self.sent.append(node)

    async def wait_for_ack(self, message_id: str, *, timeout: float) -> bool:
        return True


def device(jid: str, tag: int) -> DeviceInfo:
    return DeviceInfo(
        jid=jid,
        identity_key=bytes([tag]) * 32,
        signed_pre_key=bytes([tag + 1]) * 32,
        signed_pre_key_id=1,
        registration_id=1,
    )


async def test_group_sender_attaches_distribution_and_ciphertext(tmp_path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        sessions = FakeSessions()
        sender = FakeNodeSender()
        resolver = FakeResolver({PEER: [device(PEER_DEVICE, 1)], OWN: [device(OWN, 2)]})
        sender_keys = StoreSenderKeys(store, OWN)
        group_sender = GroupSender(
            sender, resolver, sessions, sender_keys, FakeDirectory([PEER, OWN])
        )
        result = await group_sender.send_text(GROUP, "hello group")

        assert result.acked is True
        assert sorted(result.sent) == sorted([PEER_DEVICE, OWN])

        node = sender.sent[0]
        assert node.attrs["to"] == GROUP
        assert node.attrs["phash"].startswith("2:")

        skmsg = [
            item for item in node.content if item.tag == "enc" and item.attrs["type"] == "skmsg"
        ]  # type: ignore[union-attr]
        assert len(skmsg) == 1

        skdm_payload = sessions.plaintexts[0]
        parsed = parse_message(skdm_payload)
        assert parsed.sender_key_distribution is not None
        assert parsed.sender_key_group == GROUP

        receiver_state = from_distribution(parsed.sender_key_distribution)
        assert sk_decrypt(receiver_state, skmsg[0].content) == encode_text("hello group")
    finally:
        await store.close()


async def test_group_sender_fails_when_no_device_can_be_encrypted(tmp_path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        resolver = FakeResolver({})
        sender_keys = StoreSenderKeys(store, OWN)
        group_sender = GroupSender(
            FakeNodeSender(), resolver, FakeSessions(), sender_keys, FakeDirectory([PEER])
        )
        with pytest.raises(GroupSendError):
            await group_sender.send_text(GROUP, "hello")
    finally:
        await store.close()


async def test_sender_key_store_roundtrip(tmp_path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        keys = StoreSenderKeys(store, OWN)
        distribution = await keys.prepare(GROUP)
        ciphertext = await keys.encrypt(GROUP, b"one")

        receiver = from_distribution(distribution)
        assert sk_decrypt(receiver, ciphertext) == b"one"

        await store.put_sender_key(
            GROUP, PEER, __import__("wapy").crypto.sender_key.serialize_state(receiver)
        )

        second = await keys.encrypt(GROUP, b"two")
        assert sk_decrypt(receiver, second) == b"two"

        persisted = await store.get_sender_key(GROUP, OWN)
        assert persisted is not None
        assert await store.get_sender_key(GROUP, PEER) is not None
        await keys.forget(GROUP, PEER)
        assert await store.get_sender_key(GROUP, PEER) is None
    finally:
        await store.close()


async def test_group_message_reaches_the_receiver(tmp_path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        keys = StoreSenderKeys(store, OWN)
        sender_state = SenderKeyState.create(key_id=5)
        await keys.accept_distribution(GROUP, PEER, distribution_message(sender_state))
        ciphertext = encrypt(sender_state, encode_text("from the group"))

        receiver = MessageReceiver(FakeSessions(), keys)  # type: ignore[arg-type]
        node = Node(
            tag="message",
            attrs={"id": "G1", "from": GROUP, "participant": PEER, "t": "1700000000"},
            content=[group_enc_node(ciphertext)],
        )
        received = await receiver.receive(node)
        assert received.text == "from the group"
        assert received.chat_jid == GROUP
        assert received.sender_jid == PEER
    finally:
        await store.close()


async def test_group_message_without_a_sender_key_fails(tmp_path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        keys = StoreSenderKeys(store, OWN)
        receiver = MessageReceiver(FakeSessions(), keys)  # type: ignore[arg-type]
        node = Node(
            tag="message",
            attrs={"id": "G2", "from": GROUP, "participant": PEER},
            content=[group_enc_node(b"\x33" + b"\x00" * 100)],
        )
        with pytest.raises(DecryptError):
            await receiver.receive(node)
    finally:
        await store.close()


async def test_group_service_caches_group_info(tmp_path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        calls: list[Node] = []

        class Querier:
            async def query(self, node: Node, *, timeout: float | None = None) -> Node:
                calls.append(node)
                return group_node()

        service = GroupService(Querier(), store, id_factory=lambda: "id")
        first = await service.info(GROUP)
        second = await service.info(GROUP)
        assert first == second
        assert len(calls) == 1
        service.invalidate(GROUP)
        await service.info(GROUP)
        assert len(calls) == 2
    finally:
        await store.close()


async def test_group_service_updates_and_leaves(tmp_path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:

        class Querier:
            def __init__(self) -> None:
                self.nodes: list[Node] = []

            async def query(self, node: Node, *, timeout: float | None = None) -> Node:
                self.nodes.append(node)
                return Node(
                    tag="iq",
                    content=[
                        Node(
                            tag=ACTION_ADD,
                            content=[Node(tag="participant", attrs={"jid": PEER})],
                        )
                    ],
                )

        querier = Querier()
        service = GroupService(querier, store, id_factory=lambda: "id")
        participants = await service.update_participants(GROUP, ACTION_ADD, [PEER])
        assert participants[0].jid == PEER
        await service.leave(GROUP)
        assert querier.nodes[-1].content[0].tag == "leave"  # type: ignore[index]
    finally:
        await store.close()
