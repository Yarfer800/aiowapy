"""Sending one logical message to all devices of a recipient.

The messenger owns the pipeline the architecture decision put in one place:

    recipient -> devices -> per-device ciphertext -> one <message> node -> send

It knows nothing about Noise, SQLite or the wire format: those live behind the
`NodeSender`, `DeviceResolver` and `SignalSessions` seams, which is what keeps
tests down to a few lines of fakes.

Confirmation semantics: WhatsApp answers a `<message>` with `<ack class="message">`,
not with an iq result. `wait_for_message=True` waits for that ack, but a missing
ack is *not* a send failure — the frame is already on the wire and the message may
still be delivered.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from aiowapy.errors import WapyError
from aiowapy.messaging.devices import DeviceInfo, DeviceResolver
from aiowapy.messaging.signals import SignalSessions
from aiowapy.protocol.groups import participant_hash
from aiowapy.protocol.messages import (
    EncryptedDevice,
    build_message_node,
    encode_device_sent,
    encode_text,
)
from aiowapy.protocol.wabinary import Node

DEFAULT_ACK_TIMEOUT = 5.0


class MessagingError(WapyError):
    """The message cannot be built or delivered to any device."""


class NodeSender(Protocol):
    """The wire: send an encrypted node, wait for an ack by message id."""

    async def send(self, node: Node) -> None: ...

    async def wait_for_ack(self, message_id: str, *, timeout: float) -> bool: ...


@dataclass(frozen=True, slots=True)
class SendResult:
    """`acked` is None when the caller did not ask to wait for the ack."""

    message_id: str
    sent: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    acked: bool | None = None

    @property
    def delivered_to_someone(self) -> bool:
        return bool(self.sent)


class Messenger:
    def __init__(
        self,
        sender: NodeSender,
        devices: DeviceResolver,
        sessions: SignalSessions,
        *,
        own_jid: str | None = None,
        device_identity: bytes | None = None,
        ack_timeout: float = DEFAULT_ACK_TIMEOUT,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._sender = sender
        self._devices = devices
        self._sessions = sessions
        self._own_jid = own_jid
        self._device_identity = device_identity
        self._ack_timeout = ack_timeout
        self._new_id = id_factory or _default_message_id

    async def send_text(self, jid: str, text: str, *, wait_for_message: bool = True) -> SendResult:
        return await self.send_payload(jid, encode_text(text), wait_for_message=wait_for_message)

    async def send_payload(
        self,
        jid: str,
        payload: bytes,
        *,
        message_type: str = "text",
        media_type: str | None = None,
        wait_for_message: bool = True,
    ) -> SendResult:
        devices = await self._devices.devices(jid)
        if not devices:
            raise MessagingError(f"no devices known for {jid}")

        encrypted, sent, failed = await self._encrypt_for(devices, payload)

        # Our own other devices need their own copy, wrapped in a DeviceSentMessage:
        # without it the phone never sees what the bot sent from this device.
        own_devices = await self._own_devices(jid)
        if own_devices:
            wrapped = encode_device_sent(jid, payload)
            own_encrypted, own_sent, own_failed = await self._encrypt_for(own_devices, wrapped)
            encrypted += own_encrypted
            sent += own_sent
            failed += own_failed

        if not encrypted:
            raise MessagingError(f"could not encrypt for any device of {jid}: {failed}")

        message_id = self._new_id()
        node = build_message_node(
            jid,
            message_id,
            encrypted,
            message_type=message_type,
            media_type=media_type,
            device_identity=(
                self._device_identity if any(item.prekey for item in encrypted) else None
            ),
        )
        node.attrs["phash"] = participant_hash(sent)
        await self._sender.send(node)

        acked: bool | None = None
        if wait_for_message:
            acked = await self._sender.wait_for_ack(message_id, timeout=self._ack_timeout)
        return SendResult(message_id=message_id, sent=sent, failed=failed, acked=acked)

    async def _own_devices(self, jid: str) -> list[DeviceInfo]:
        if not self._own_jid or self._own_jid == jid:
            return []
        bare = self._own_jid.split(":", 1)[0] + "@" + self._own_jid.split("@", 1)[1]
        try:
            devices = await self._devices.devices(bare)
        except Exception:
            return []
        return [device for device in devices if device.jid != self._own_jid]

    def invalidate(self, jid: str) -> None:
        """Forget the cached device list of a recipient."""
        invalidate = getattr(self._devices, "invalidate", None)
        if invalidate is not None:
            invalidate(jid)

    async def _encrypt_for(
        self, devices: list[DeviceInfo], payload: bytes
    ) -> tuple[list[EncryptedDevice], list[str], list[tuple[str, str]]]:
        encrypted: list[EncryptedDevice] = []
        sent: list[str] = []
        failed: list[tuple[str, str]] = []
        for device in devices:
            try:
                result = await self._sessions.encrypt(device, payload)
            except Exception as exc:  # one bad device must not sink the message
                failed.append((device.jid, str(exc)))
                continue
            encrypted.append(result)
            sent.append(device.jid)
        return encrypted, sent, failed


def _default_message_id() -> str:
    return secrets.token_hex(8).upper()
