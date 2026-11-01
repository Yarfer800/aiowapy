from __future__ import annotations

import hmac

import pytest

from aiowapy.messaging.appstate import AppStateSync, AppStateSyncError
from aiowapy.protocol.appstate import (
    LTHASH_SIZE,
    MUTATION_REMOVE,
    MUTATION_SET,
    REGULAR_HIGH,
    REGULAR_LOW,
    AppStateError,
    build_patch,
    decode_mutation,
    encode_mutation,
    expand_keys,
    lthash_subtract_then_add,
    mute_action,
    parse_action_value,
    parse_mutation,
    parse_patch,
    patch_mac,
    pin_action,
    read_action,
    snapshot_mac,
)
from aiowapy.protocol.wabinary import Node
from aiowapy.store import SessionStore

KEY_ID = b"\x01\x02\x03\x04"
KEY_DATA = bytes(range(32))
CHAT = "491234567890@s.whatsapp.net"


def test_expand_keys_is_deterministic() -> None:
    first = expand_keys(KEY_DATA)
    second = expand_keys(KEY_DATA)
    assert first == second
    assert len(first.index) == 32
    assert len(first.patch_mac) == 32
    with pytest.raises(AppStateError):
        expand_keys(b"short")


def keys():
    return expand_keys(KEY_DATA)


def test_mutation_roundtrip() -> None:
    encoded = encode_mutation(
        MUTATION_SET,
        ("mute", CHAT),
        KEY_ID,
        keys(),
        value=mute_action(True).encode(1700000000000),
        version=2,
    )
    raw = parse_mutation(encoded)
    assert raw.operation == MUTATION_SET
    assert raw.key_id == KEY_ID
    decoded = decode_mutation(raw, keys())
    assert decoded.index == ("mute", CHAT)
    assert decoded.timestamp == 1700000000000
    action = parse_action_value(decoded.value)
    assert action.mute == (True, -1)


def test_mutation_remove_roundtrip() -> None:
    encoded = encode_mutation(MUTATION_REMOVE, ("contact", CHAT), KEY_ID, keys(), version=1)
    decoded = decode_mutation(parse_mutation(encoded), keys())
    assert decoded.is_remove
    assert decoded.index == ("contact", CHAT)


def test_tampered_value_is_rejected() -> None:
    encoded = bytearray(
        encode_mutation(MUTATION_SET, ("mute", CHAT), KEY_ID, keys(), value=b"\x08\x01")
    )
    encoded[-1] ^= 0xFF
    with pytest.raises(AppStateError, match="value MAC"):
        decode_mutation(parse_mutation(bytes(encoded)), keys())


def test_tampered_index_is_rejected() -> None:
    encoded = encode_mutation(MUTATION_SET, ("mute", CHAT), KEY_ID, keys(), value=b"\x08\x01")
    raw = parse_mutation(encoded)
    forged = type(raw)(
        operation=raw.operation,
        index_mac=b"\x00" * 32,
        blob=raw.blob,
        key_id=raw.key_id,
    )
    with pytest.raises(AppStateError, match="index MAC"):
        decode_mutation(forged, keys())


def test_lthash_add_then_subtract_returns_the_original() -> None:
    base = bytes(LTHASH_SIZE)
    mac_a = b"a" * 32
    mac_b = b"b" * 32
    added = lthash_subtract_then_add(base, add=[mac_a, mac_b])
    assert added != base
    restored = lthash_subtract_then_add(added, subtract=[mac_a, mac_b])
    assert restored == base


def test_patch_roundtrip_and_mac() -> None:
    mutation = encode_mutation(
        MUTATION_SET, ("pin_v1", CHAT), KEY_ID, keys(), value=pin_action(True).encode(1), version=5
    )
    value_macs = [parse_mutation(mutation).value_mac]
    digest = lthash_subtract_then_add(bytes(LTHASH_SIZE), add=value_macs)
    snap = snapshot_mac(digest, 4, REGULAR_LOW, keys().snapshot_mac)
    dig = patch_mac(snap, value_macs, 4, REGULAR_LOW, keys().patch_mac)

    raw = build_patch(
        [mutation],
        snapshot_mac_value=snap,
        key_id=KEY_ID,
        patch_mac_value=dig,
        version=4,
    )
    patch = parse_patch(raw)
    assert patch.version == 4
    assert patch.key_id == KEY_ID
    assert patch.snapshot_mac == snap
    assert hmac.compare_digest(
        patch_mac(
            patch.snapshot_mac, patch.value_macs, patch.version, REGULAR_LOW, keys().patch_mac
        ),
        patch.patch_mac,
    )


def test_action_builders() -> None:
    assert parse_action_value(read_action(True, last_message_ts=42).encode(1)).mark_read is True
    mute = parse_action_value(mute_action(False).encode(1))
    assert mute.mute == (False, None)
    pinned = parse_action_value(pin_action(True).encode(1))
    assert pinned.pin is True


def patch_node(*, name: str, patch_bytes: bytes, version: int) -> Node:
    return Node(
        tag="iq",
        attrs={"type": "result"},
        content=[
            Node(
                tag="sync",
                attrs={},
                content=[
                    Node(
                        tag="collection",
                        attrs={"name": name, "version": str(version)},
                        content=[
                            Node(
                                tag="patches",
                                attrs={},
                                content=[Node(tag="patch", attrs={}, content=patch_bytes)],
                            )
                        ],
                    )
                ],
            )
        ],
    )


def build_server_patch(
    name: str, version: int, *, patch_mac_value: bytes | None = None
) -> tuple[bytes, bytes]:
    mutation = encode_mutation(
        MUTATION_SET,
        ("mute", CHAT),
        KEY_ID,
        keys(),
        value=mute_action(True).encode(1_700_000_000_000),
        version=2,
    )
    value_macs = [parse_mutation(mutation).value_mac]
    digest = lthash_subtract_then_add(bytes(LTHASH_SIZE), add=value_macs)
    snap = snapshot_mac(digest, version, name, keys().snapshot_mac)
    dig = patch_mac(snap, value_macs, version, name, keys().patch_mac)
    raw = build_patch(
        [mutation],
        snapshot_mac_value=snap,
        key_id=KEY_ID,
        patch_mac_value=patch_mac_value if patch_mac_value is not None else dig,
        version=version,
    )
    return raw, digest


class FakeQuerier:
    def __init__(self, response: Node) -> None:
        self.response = response
        self.queries: list[Node] = []

    async def query(self, node: Node, *, timeout: float | None = None) -> Node:
        self.queries.append(node)
        return self.response


async def seeded_store(tmp_path) -> SessionStore:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    await store.put_app_state_key(KEY_ID, KEY_DATA)
    return store


async def test_sync_applies_patches(tmp_path) -> None:
    store = await seeded_store(tmp_path)
    try:
        raw, digest = build_server_patch(REGULAR_HIGH, 3)
        querier = FakeQuerier(patch_node(name=REGULAR_HIGH, patch_bytes=raw, version=3))
        sync = AppStateSync(querier, store)
        result = await sync.sync(REGULAR_HIGH)

        assert result.applied == 1
        assert result.version == 3
        assert len(await sync.entries(REGULAR_HIGH)) == 1
        stored = await store.get_app_state_version(REGULAR_HIGH)
        assert stored == (3, digest)
        request = querier.queries[0]
        collection = request.content[0].content[0]  # type: ignore[index,union-attr]
        assert collection.attrs["name"] == REGULAR_HIGH
        assert collection.attrs["version"] == "0"
    finally:
        await store.close()


async def test_sync_skips_patches_we_already_have(tmp_path) -> None:
    store = await seeded_store(tmp_path)
    try:
        raw, _digest = build_server_patch(REGULAR_HIGH, 1)
        querier = FakeQuerier(patch_node(name=REGULAR_HIGH, patch_bytes=raw, version=1))
        sync = AppStateSync(querier, store)
        first = await sync.sync(REGULAR_HIGH)
        assert first.applied == 1
        second = await sync.sync(REGULAR_HIGH)
        assert second.applied == 0
        assert second.skipped == 1
    finally:
        await store.close()


async def test_sync_rejects_a_bad_patch_mac(tmp_path) -> None:
    store = await seeded_store(tmp_path)
    try:
        raw, _digest = build_server_patch(REGULAR_HIGH, 3, patch_mac_value=b"\x00" * 32)
        querier = FakeQuerier(patch_node(name=REGULAR_HIGH, patch_bytes=raw, version=3))
        sync = AppStateSync(querier, store)
        with pytest.raises(AppStateSyncError, match="MAC"):
            await sync.sync(REGULAR_HIGH)
    finally:
        await store.close()


async def test_sync_without_a_key_fails(tmp_path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        raw, _digest = build_server_patch(REGULAR_HIGH, 3)
        querier = FakeQuerier(patch_node(name=REGULAR_HIGH, patch_bytes=raw, version=3))
        sync = AppStateSync(querier, store)
        with pytest.raises(AppStateSyncError, match="unknown"):
            await sync.sync(REGULAR_HIGH)
    finally:
        await store.close()


async def test_unknown_collection_is_rejected(tmp_path) -> None:
    store = await seeded_store(tmp_path)
    try:
        sync = AppStateSync(FakeQuerier(Node(tag="iq")), store)
        with pytest.raises(AppStateSyncError):
            await sync.sync("nonsense")
    finally:
        await store.close()


async def test_send_patch_produces_a_verifiable_patch(tmp_path) -> None:
    store = await seeded_store(tmp_path)
    try:
        querier = FakeQuerier(Node(tag="iq", attrs={"type": "result"}))
        sync = AppStateSync(querier, store, clock=lambda: 1_700_000_000.0)
        version = await sync.send_patch(REGULAR_LOW, [(("pin_v1", CHAT), pin_action(True))])
        assert version == 1

        request = querier.queries[0]
        assert request.attrs["xmlns"] == "w:sync:app:state"
        collection = request.content[0].content[0]  # type: ignore[index,union-attr]
        assert collection.attrs["version"] == "1"
        raw = collection.content[0].content  # type: ignore[index,union-attr]
        patch = parse_patch(raw)
        assert patch.version == 1
        assert hmac.compare_digest(
            patch_mac(
                patch.snapshot_mac,
                patch.value_macs,
                patch.version,
                REGULAR_LOW,
                keys().patch_mac,
            ),
            patch.patch_mac,
        )
        decoded = decode_mutation(patch.mutations[0], keys())
        assert decoded.index == ("pin_v1", CHAT)
        assert parse_action_value(decoded.value).pin is True

        stored = await store.get_app_state_version(REGULAR_LOW)
        assert stored is not None and stored[0] == 1
    finally:
        await store.close()


async def test_send_patch_reports_a_server_error(tmp_path) -> None:
    store = await seeded_store(tmp_path)
    try:
        error = Node(
            tag="iq",
            attrs={"type": "result"},
            content=[
                Node(
                    tag="sync",
                    attrs={},
                    content=[
                        Node(
                            tag="collection",
                            attrs={"name": REGULAR_LOW, "type": "error"},
                            content=[Node(tag="error", attrs={"code": "409", "text": "conflict"})],
                        )
                    ],
                )
            ],
        )
        sync = AppStateSync(FakeQuerier(error), store)
        with pytest.raises(AppStateSyncError, match="409"):
            await sync.send_patch(REGULAR_LOW, [(("pin_v1", CHAT), pin_action(True))])
    finally:
        await store.close()


async def test_send_patch_needs_a_key(tmp_path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        sync = AppStateSync(FakeQuerier(Node(tag="iq")), store)
        with pytest.raises(AppStateSyncError, match="no app state key"):
            await sync.send_patch(REGULAR_LOW, [(("pin_v1", CHAT), pin_action(True))])
    finally:
        await store.close()


async def test_helpers_build_the_right_indexes(tmp_path) -> None:
    store = await seeded_store(tmp_path)
    try:
        querier = FakeQuerier(Node(tag="iq", attrs={"type": "result"}))
        sync = AppStateSync(querier, store)
        await sync.mute(CHAT, True)
        await sync.pin(CHAT, False)
        await sync.mark_chat_read(CHAT, True, last_message_ts=99)
        await sync.set_push_name("bot")

        indexes = []
        for request in querier.queries:
            collection = request.content[0].content[0]  # type: ignore[index,union-attr]
            patch = parse_patch(collection.content[0].content)  # type: ignore[union-attr,index]
            indexes.append(decode_mutation(patch.mutations[0], keys()).index)
        assert indexes == [
            ("mute", CHAT),
            ("pin_v1", CHAT),
            ("markChatAsRead", CHAT),
            ("setting_pushName",),
        ]
    finally:
        await store.close()
