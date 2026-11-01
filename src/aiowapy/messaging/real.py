"""Real implementations of the three seams the messenger depends on.

- `UsyncDeviceFetcher` turns a recipient JID into `DeviceInfo` objects: one `usync`
  query for the device list, one bundle request for all of them.
- `StoreSignalSessions` keeps Signal state in the session file and produces one
  ciphertext per device, wrapping the first message as a prekey message.
- `StreamNodeSender` sends a node over the transport and maps `<ack>` to a boolean.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Protocol

from aiowapy.creds import DeviceCredentials
from aiowapy.crypto.primitives import KeyPair
from aiowapy.crypto.session import decrypt as signal_decrypt
from aiowapy.crypto.session import (
    deserialize,
    initiator_session,
    prekey_message,
    responder_session,
    serialize,
)
from aiowapy.crypto.session import encrypt as signal_encrypt
from aiowapy.crypto.signal_proto import decode_prekey
from aiowapy.errors import WapyError
from aiowapy.messaging.devices import DeviceError, DeviceInfo
from aiowapy.protocol.bundles import PreKeyBundle, build_bundle_query, parse_bundles
from aiowapy.protocol.messages import EncryptedDevice
from aiowapy.protocol.usync import build_device_query, parse_device_jids
from aiowapy.protocol.wabinary import Node
from aiowapy.store import SessionStore


class NodeQuerier(Protocol):
    """Request/response over the node stream; `NodeStream` satisfies this."""

    async def query(self, node: Node, *, timeout: float | None = ...) -> Node: ...


class AckableSender(Protocol):
    """`NodeStream` satisfies this too, via send + wait_for_ack."""

    async def send(self, node: Node) -> None: ...

    async def wait_for_ack(self, message_id: str, *, timeout: float) -> bool: ...


class SessionSendError(WapyError):
    """Signal state could not be produced for a device."""


class UsyncDeviceFetcher:
    """`usync` + bundle request, combined into `DeviceInfo` objects."""

    def __init__(
        self,
        querier: NodeQuerier,
        credentials: DeviceCredentials,
        *,
        own_jid: str | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._querier = querier
        self._credentials = credentials
        self._own_jid = own_jid
        self._new_id = id_factory or (lambda: secrets.token_hex(4))

    async def fetch(self, jid: str) -> list[DeviceInfo]:
        device_response = await self._querier.query(
            build_device_query([jid], self._new_id(), sid=self._new_id())
        )
        exclude = {self._own_jid} if self._own_jid else set()
        device_jids = parse_device_jids(device_response, exclude=exclude)
        if not device_jids:
            raise DeviceError(f"no devices reported for {jid}")

        bundle_response = await self._querier.query(build_bundle_query(device_jids, self._new_id()))
        bundles = parse_bundles(bundle_response)
        if not bundles:
            raise DeviceError(f"no prekey bundles returned for {jid}")
        return [self._to_device_info(bundle) for bundle in bundles]

    @staticmethod
    def _to_device_info(bundle: PreKeyBundle) -> DeviceInfo:
        return DeviceInfo(
            jid=bundle.jid,
            identity_key=bundle.identity_key,
            signed_pre_key=bundle.signed_pre_key.public,
            signed_pre_key_id=bundle.signed_pre_key.key_id,
            registration_id=bundle.registration_id,
            pre_key=bundle.pre_key.public if bundle.pre_key else None,
            pre_key_id=bundle.pre_key.key_id if bundle.pre_key else None,
        )


class StoreSignalSessions:
    """Signal sessions persisted in the `.session` file."""

    def __init__(self, store: SessionStore, credentials: DeviceCredentials) -> None:
        self._store = store
        self._credentials = credentials

    async def encrypt(self, device: DeviceInfo, plaintext: bytes) -> EncryptedDevice:
        stored = await self._store.get_session(device.jid)
        if stored is not None:
            state = deserialize(stored)
            message = signal_encrypt(state, plaintext)
            await self._store.put_session(device.jid, serialize(state))
            return EncryptedDevice(device_jid=device.jid, ciphertext=message)

        state = initiator_session(
            self._credentials.identity_key,
            device.identity_key,
            device.signed_pre_key,
            device.pre_key,
            signed_pre_key_id=device.signed_pre_key_id,
            pre_key_id=device.pre_key_id,
        )
        message = signal_encrypt(state, plaintext)
        body = prekey_message(state, message, registration_id=self._credentials.registration_id)
        await self._store.put_session(device.jid, serialize(state))
        return EncryptedDevice(device_jid=device.jid, ciphertext=body, prekey=True)


class StoreSignalSessionsWithDecrypt(StoreSignalSessions):
    """Adds the receiving half: prekey messages create the session."""

    async def decrypt(self, device_jid: str, ciphertext: bytes, *, prekey: bool) -> bytes:
        if not prekey:
            stored = await self._store.get_session(device_jid)
            if stored is None:
                raise SessionSendError(f"no session for {device_jid}")
            state = deserialize(stored)
            plaintext = signal_decrypt(state, ciphertext)
            await self._store.put_session(device_jid, serialize(state))
            return plaintext

        wrapped = decode_prekey(ciphertext[1:])
        signed = self._credentials.signed_pre_key
        if wrapped.signed_pre_key_id != signed.key_id:
            raise SessionSendError(
                f"unknown signed prekey {wrapped.signed_pre_key_id} (have {signed.key_id})"
            )
        one_time = None
        if wrapped.pre_key_id is not None:
            blob = await self._store.consume_prekey(wrapped.pre_key_id)
            if blob is None:
                raise SessionSendError(f"one-time prekey {wrapped.pre_key_id} is gone")
            one_time = KeyPair(private=blob[:32], public=blob[32:])

        state = responder_session(
            self._credentials.identity_key,
            signed.key_pair,
            signed_pre_key_id=signed.key_id,
            their_identity=wrapped.identity_key,
            their_base_key=wrapped.base_key,
            our_one_time_pre_key=one_time,
        )
        plaintext = signal_decrypt(state, wrapped.message)
        await self._store.put_session(device_jid, serialize(state))
        return plaintext


class StreamNodeSender:
    """Sends over the node stream and maps `<ack>` to a boolean."""

    def __init__(self, stream: AckableSender) -> None:
        self._stream = stream

    async def send(self, node: Node) -> None:
        await self._stream.send(node)

    async def wait_for_ack(self, message_id: str, *, timeout: float) -> bool:
        return await self._stream.wait_for_ack(message_id, timeout=timeout)
