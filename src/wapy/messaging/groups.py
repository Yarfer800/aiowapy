from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import asdict
from typing import Protocol

from wapy.crypto.sender_key import (
    SenderKeyState,
    deserialize_state,
    distribution_message,
    from_distribution,
    serialize_state,
)
from wapy.crypto.sender_key import (
    decrypt as sender_key_decrypt,
)
from wapy.crypto.sender_key import (
    encrypt as sender_key_encrypt,
)
from wapy.errors import WapyError
from wapy.messaging.devices import DeviceInfo, DeviceResolver
from wapy.messaging.messenger import NodeSender, SendResult
from wapy.messaging.real import NodeQuerier
from wapy.messaging.signals import SignalSessions
from wapy.protocol.groups import (
    GroupInfo,
    GroupParticipant,
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
    build_message_node,
    encode_sender_key_distribution,
    encode_text,
    group_enc_node,
)
from wapy.store import SessionStore

GROUP_TTL = 300.0
DEFAULT_ACK_TIMEOUT = 5.0


class GroupSendError(WapyError):
    """The group message cannot be sent or the group data is unusable."""


class GroupDirectory(Protocol):
    async def participants(self, group_jid: str) -> list[str]: ...

    def invalidate(self, group_jid: str) -> None: ...


def group_info_to_dict(info: GroupInfo) -> bytes:
    return json.dumps(asdict(info), ensure_ascii=False).encode("utf-8")


def group_info_from_dict(record: bytes) -> GroupInfo:
    try:
        data = json.loads(record.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise GroupSendError("stored group record is not valid JSON") from exc
    participants = [
        GroupParticipant(
            jid=str(item["jid"]),
            is_admin=bool(item.get("is_admin")),
            is_super_admin=bool(item.get("is_super_admin")),
            lid=item.get("lid"),
            phone_number=item.get("phone_number"),
        )
        for item in data.get("participants", [])
    ]
    return GroupInfo(
        jid=str(data["jid"]),
        subject=str(data.get("subject", "")),
        owner_jid=data.get("owner_jid"),
        participants=participants,
        topic=data.get("topic"),
        topic_id=data.get("topic_id"),
        is_locked=bool(data.get("is_locked")),
        is_announce=bool(data.get("is_announce")),
        is_ephemeral=bool(data.get("is_ephemeral")),
        disappearing_timer=int(data.get("disappearing_timer", 0)),
        participant_count=int(data.get("participant_count", 0)),
        addressing_mode=data.get("addressing_mode"),
    )


class GroupService:
    """Group queries and membership changes over the node stream."""

    def __init__(
        self,
        querier: NodeQuerier,
        store: SessionStore,
        *,
        ttl: float = GROUP_TTL,
        clock: Callable[[], float] = time.monotonic,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._querier = querier
        self._store = store
        self._ttl = ttl
        self._clock = clock
        self._new_id = id_factory or (lambda: secrets.token_hex(4))
        self._pending_invalidations: set[str] = set()

    async def info(self, group_jid: str, *, refresh: bool = False) -> GroupInfo:
        if group_jid in self._pending_invalidations:
            self._pending_invalidations.discard(group_jid)
            refresh = True
        if not refresh:
            cached = await self._store.get_group(group_jid)
            if cached is not None:
                record, fetched = cached
                if self._clock() - fetched < self._ttl:
                    return group_info_from_dict(record)
        response = await self._querier.query(build_group_info_query(group_jid, self._new_id()))
        info = parse_group_info(response)
        await self._store.put_group(group_jid, group_info_to_dict(info), self._clock())
        return info

    async def participants(self, group_jid: str) -> list[str]:
        return (await self.info(group_jid)).participant_jids

    def invalidate(self, group_jid: str) -> None:
        """Drop the cached answer; the next read goes to the server."""
        self._pending_invalidations.add(group_jid)

    async def joined(self) -> list[GroupInfo]:
        response = await self._querier.query(build_joined_groups_query(self._new_id()))
        groups = parse_joined_groups(response)
        for info in groups:
            await self._store.put_group(info.jid, group_info_to_dict(info), self._clock())
        return groups

    async def create(self, subject: str, participants: list[str]) -> str:
        response = await self._querier.query(
            build_create_group(subject, participants, self._new_id())
        )
        return parse_created_group(response)

    async def update_participants(
        self, group_jid: str, action: str, participants: list[str]
    ) -> list[GroupParticipant]:
        response = await self._querier.query(
            build_participants_update(group_jid, action, participants, self._new_id())
        )
        self.invalidate(group_jid)
        await self._store.delete_group(group_jid)
        return parse_participants_update(response, action)

    async def leave(self, group_jid: str) -> None:
        await self._querier.query(build_leave_group(group_jid, self._new_id()))
        self.invalidate(group_jid)
        await self._store.delete_group(group_jid)


class StoreSenderKeys:
    """Sender key chains, one per (group, member), persisted in the session file."""

    def __init__(
        self,
        store: SessionStore,
        own_jid: str,
        *,
        key_id_factory: Callable[[], int] | None = None,
    ) -> None:
        self._store = store
        self._own_jid = own_jid
        self._new_key_id = key_id_factory or (lambda: secrets.randbits(32))

    async def prepare(self, group_jid: str) -> bytes:
        """The distribution message for the current chain, created if needed.

        It must be produced *before* encrypting: the receiver starts its chain on the
        iteration the distribution carries, so a message and its distribution have to
        describe the same point in the chain.
        """
        record = await self._store.get_sender_key(group_jid, self._own_jid)
        if record is None:
            state = SenderKeyState.create(key_id=self._new_key_id())
            await self._store.put_sender_key(group_jid, self._own_jid, serialize_state(state))
            return distribution_message(state)
        return distribution_message(deserialize_state(record))

    async def encrypt(self, group_jid: str, plaintext: bytes) -> bytes:
        state = await self._load_or_create(group_jid, self._own_jid)
        ciphertext = sender_key_encrypt(state, plaintext)
        await self._store.put_sender_key(group_jid, self._own_jid, serialize_state(state))
        return ciphertext

    async def decrypt(self, group_jid: str, sender_jid: str, ciphertext: bytes) -> bytes:
        record = await self._store.get_sender_key(group_jid, sender_jid)
        if record is None:
            raise GroupSendError(f"no sender key from {sender_jid} in {group_jid}")
        state = deserialize_state(record)
        plaintext = sender_key_decrypt(state, ciphertext)
        await self._store.put_sender_key(group_jid, sender_jid, serialize_state(state))
        return plaintext

    async def accept_distribution(self, group_jid: str, sender_jid: str, serialized: bytes) -> None:
        state = from_distribution(serialized)
        await self._store.put_sender_key(group_jid, sender_jid, serialize_state(state))

    async def forget(self, group_jid: str, sender_jid: str) -> None:
        await self._store.delete_sender_key(group_jid, sender_jid)

    async def _load_or_create(self, group_jid: str, sender: str) -> SenderKeyState:
        record = await self._store.get_sender_key(group_jid, sender)
        if record is None:
            return SenderKeyState.create(key_id=self._new_key_id())
        state = deserialize_state(record)
        if state.signing_private is None:  # our own record must be sendable
            return SenderKeyState.create(key_id=self._new_key_id())
        return state


class GroupSender:
    """Sends one group message: a sender key ciphertext plus the distribution message."""

    def __init__(
        self,
        sender: NodeSender,
        devices: DeviceResolver,
        sessions: SignalSessions,
        sender_keys: StoreSenderKeys,
        directory: GroupDirectory,
        *,
        ack_timeout: float = DEFAULT_ACK_TIMEOUT,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._sender = sender
        self._devices = devices
        self._sessions = sessions
        self._sender_keys = sender_keys
        self._directory = directory
        self._ack_timeout = ack_timeout
        self._new_id = id_factory or _default_message_id

    async def send_text(
        self, group_jid: str, text: str, *, wait_for_message: bool = True
    ) -> SendResult:
        return await self.send_payload(
            group_jid, encode_text(text), wait_for_message=wait_for_message
        )

    async def send_payload(
        self, group_jid: str, payload: bytes, *, wait_for_message: bool = True
    ) -> SendResult:
        participants = await self._directory.participants(group_jid)
        if not participants:
            raise GroupSendError(f"group {group_jid} has no participants")

        distribution = await self._sender_keys.prepare(group_jid)
        ciphertext = await self._sender_keys.encrypt(group_jid, payload)
        skdm_payload = encode_sender_key_distribution(group_jid, distribution)

        encrypted, sent, failed = await self._encrypt_distribution(participants, skdm_payload)
        if not encrypted:
            raise GroupSendError(
                f"could not encrypt the sender key for any device of {group_jid}: {failed}"
            )

        message_id = self._new_id()
        node = build_message_node(
            group_jid,
            message_id,
            encrypted,
            extra=[group_enc_node(ciphertext)],
        )
        node.attrs["phash"] = participant_hash(sent)
        await self._sender.send(node)

        acked: bool | None = None
        if wait_for_message:
            acked = await self._sender.wait_for_ack(message_id, timeout=self._ack_timeout)
        return SendResult(message_id=message_id, sent=sent, failed=failed, acked=acked)

    async def _encrypt_distribution(
        self, participants: list[str], payload: bytes
    ) -> tuple[list[EncryptedDevice], list[str], list[tuple[str, str]]]:
        encrypted: list[EncryptedDevice] = []
        sent: list[str] = []
        failed: list[tuple[str, str]] = []
        for participant in participants:
            try:
                devices: list[DeviceInfo] = await self._devices.devices(participant)
            except Exception as exc:
                failed.append((participant, str(exc)))
                continue
            for device in devices:
                try:
                    encrypted.append(await self._sessions.encrypt(device, payload))
                except Exception as exc:
                    failed.append((device.jid, str(exc)))
                    continue
                sent.append(device.jid)
        return encrypted, sent, failed


def participant_hash(device_jids: list[str]) -> str:
    """`phash`: the server uses it to detect a stale participant list."""
    digest = hashlib.sha256("".join(sorted(device_jids)).encode("utf-8")).digest()
    return "2:" + base64.b64encode(digest[:6]).decode("ascii").rstrip("=")


def _default_message_id() -> str:
    return secrets.token_hex(8).upper()
