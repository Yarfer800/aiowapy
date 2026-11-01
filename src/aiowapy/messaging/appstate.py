from __future__ import annotations

import hmac
import json
import logging
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

from aiowapy.errors import WapyError
from aiowapy.messaging.real import NodeQuerier
from aiowapy.protocol.appstate import (
    ALL_COLLECTIONS,
    CRITICAL_BLOCK,
    INDEX_MARK_READ,
    INDEX_MUTE,
    INDEX_PIN,
    INDEX_PUSH_NAME,
    LTHASH_SIZE,
    MUTATION_SET,
    REGULAR_HIGH,
    REGULAR_LOW,
    AppStateError,
    AppStateKeys,
    DecodedMutation,
    SyncAction,
    build_patch,
    build_patch_push,
    build_sync_request,
    decode_mutation,
    encode_mutation,
    expand_keys,
    lthash_subtract_then_add,
    mute_action,
    parse_mutation,
    parse_patch_list,
    patch_mac,
    pin_action,
    push_name_action,
    read_action,
    snapshot_mac,
)
from aiowapy.protocol.stream import child
from aiowapy.store import SessionStore

logger = logging.getLogger("aiowapy")


class AppStateSyncError(WapyError):
    """App state cannot be fetched, verified or sent."""


@dataclass(frozen=True, slots=True)
class SyncedCollection:
    name: str
    version: int
    applied: int
    skipped: int
    has_more: bool


class AppStateSync:
    """Fetches app state patches, verifies them and keeps a local copy in SQLite.

    The integrity hash (`LTHash`) is maintained per collection: SET mutations add
    their value MAC, REMOVE mutations subtract the MAC of the value they replace.
    That is what makes a later patch verifiable against the state we actually hold.
    """

    def __init__(
        self,
        querier: NodeQuerier,
        store: SessionStore,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._querier = querier
        self._store = store
        self._clock = clock

    async def sync(self, name: str) -> SyncedCollection:
        """Fetch and apply every patch newer than the stored version."""
        _require_collection(name)
        version, digest = await self._state(name)
        request = build_sync_request(name, version=version)
        request.attrs["id"] = secrets.token_hex(4)
        response = await self._querier.query(request)
        patch_list = parse_patch_list(response)

        applied = skipped = 0
        for patch in patch_list.patches:
            if patch.version and patch.version <= version:
                skipped += len(patch.mutations)
                continue
            keys = await self._keys_for(patch.key_id)
            self._verify_patch(name, patch, keys)
            removed: list[bytes] = []
            added: list[bytes] = []
            for raw in patch.mutations:
                try:
                    mutation = decode_mutation(raw, keys)
                except AppStateError as exc:
                    logger.warning("skipping a mutation in %s: %s", name, exc)
                    skipped += 1
                    continue
                if mutation.is_remove:
                    previous = await self._store.delete_app_state(name, _index(mutation))
                    if previous is not None:
                        removed.append(previous)
                else:
                    await self._store.put_app_state(
                        name,
                        _index(mutation),
                        mutation.value,
                        mutation.timestamp,
                        mutation.value_mac,
                    )
                    added.append(mutation.value_mac)
                applied += 1
            digest = lthash_subtract_then_add(digest, subtract=removed, add=added)
            version = patch.version or version

        await self._store.set_app_state_version(name, version, digest)
        return SyncedCollection(
            name=name,
            version=version,
            applied=applied,
            skipped=skipped,
            has_more=patch_list.has_more_patches,
        )

    async def sync_all(self) -> list[SyncedCollection]:
        return [await self.sync(name) for name in ALL_COLLECTIONS]

    async def entries(self, name: str) -> list[tuple[str, bytes, int]]:
        """The local copy: (index json, SyncActionValue bytes, timestamp)."""
        return await self._store.list_app_state(name)

    async def send_patch(
        self,
        name: str,
        mutations: list[tuple[tuple[str, ...], SyncAction]],
        *,
        version: int = 2,
    ) -> int:
        """Push SET mutations for one collection and return the new version.

        `version` is the per-index protocol version the reference client uses for the
        action (mute 2, mark-as-read 3, pin 5, push name 1); it is not the patch
        version, which is derived from the local state.
        """
        _require_collection(name)
        if not mutations:
            raise AppStateSyncError("nothing to send")
        key_id = await self._store.latest_app_state_key_id()
        if key_id is None:
            raise AppStateSyncError(
                "no app state key: they arrive from the phone in a key share notification"
            )
        keys = await self._keys_for(key_id)
        timestamp = int(self._clock() * 1000)
        encoded = [
            encode_mutation(
                MUTATION_SET,
                index,
                key_id,
                keys,
                value=action.encode(timestamp),
                version=version,
            )
            for index, action in mutations
        ]
        value_macs = [parse_mutation(item).value_mac for item in encoded]

        current_version, digest = await self._state(name)
        next_version = current_version + 1
        digest = lthash_subtract_then_add(digest, add=value_macs)
        snapshot = snapshot_mac(digest, next_version, name, keys.snapshot_mac)
        encoded_patch = build_patch(
            encoded,
            snapshot_mac_value=snapshot,
            key_id=key_id,
            patch_mac_value=patch_mac(snapshot, value_macs, next_version, name, keys.patch_mac),
            version=next_version,
        )

        request = build_patch_push(name, next_version, encoded_patch)
        request.attrs["id"] = secrets.token_hex(4)
        response = await self._querier.query(request)
        _raise_on_collection_error(response)
        await self._store.set_app_state_version(name, next_version, digest)
        return next_version

    async def mute(self, chat_jid: str, muted: bool, *, until_ms: int | None = None) -> int:
        return await self.send_patch(
            REGULAR_HIGH,
            [(("mute", chat_jid), mute_action(muted, until_ms=until_ms))],
            version=2,
        )

    async def pin(self, chat_jid: str, pinned: bool) -> int:
        return await self.send_patch(
            REGULAR_LOW, [(("pin_v1", chat_jid), pin_action(pinned))], version=5
        )

    async def mark_chat_read(
        self, chat_jid: str, read: bool, *, last_message_ts: int | None = None
    ) -> int:
        return await self.send_patch(
            REGULAR_LOW,
            [(("markChatAsRead", chat_jid), read_action(read, last_message_ts=last_message_ts))],
            version=3,
        )

    async def set_push_name(self, name: str) -> int:
        return await self.send_patch(
            CRITICAL_BLOCK, [(("setting_pushName",), push_name_action(name))], version=1
        )

    # -- internals ----------------------------------------------------------

    async def _state(self, name: str) -> tuple[int, bytes]:
        stored = await self._store.get_app_state_version(name)
        if stored is None:
            return 0, bytes(LTHASH_SIZE)
        return stored

    async def _keys_for(self, key_id: bytes) -> AppStateKeys:
        if not key_id:
            raise AppStateSyncError("patch carries no key id")
        key_data = await self._store.get_app_state_key(key_id)
        if key_data is None:
            raise AppStateSyncError(f"app state key {key_id.hex()} is unknown")
        return expand_keys(key_data)

    def _verify_patch(self, name: str, patch: object, keys: AppStateKeys) -> None:
        snapshot = getattr(patch, "snapshot_mac", b"")
        received = getattr(patch, "patch_mac", b"")
        version = getattr(patch, "version", 0)
        value_macs = getattr(patch, "value_macs", [])
        if not received:
            return
        expected = patch_mac(snapshot, value_macs, version, name, keys.patch_mac)
        if not hmac.compare_digest(expected, received):
            raise AppStateSyncError(f"patch {version} of {name} fails its MAC check")


def _require_collection(name: str) -> None:
    if name not in ALL_COLLECTIONS:
        raise AppStateSyncError(f"unknown app state collection: {name!r}")


def _index(mutation: DecodedMutation) -> str:
    return json.dumps(list(mutation.index), separators=(",", ":"))


def _raise_on_collection_error(node: object) -> None:
    if not hasattr(node, "tag"):  # pragma: no cover - defensive
        return
    sync = child(node, "sync")  # type: ignore[arg-type]
    collection = child(sync, "collection") if sync is not None else None
    if collection is None or collection.attrs.get("type") != "error":
        return
    error = child(collection, "error")
    code = error.attrs.get("code", "?") if error is not None else "?"
    text = error.attrs.get("text", "") if error is not None else ""
    raise AppStateSyncError(f"app state update rejected: {code} {text}".strip())


__all__ = [
    "AppStateSync",
    "AppStateSyncError",
    "SyncedCollection",
    "INDEX_MARK_READ",
    "INDEX_MUTE",
    "INDEX_PIN",
    "INDEX_PUSH_NAME",
]
