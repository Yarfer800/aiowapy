"""Receiving: from a `<message>` node to plaintext.

A message node carries one `<enc>` per device of the receiver (us). Exactly one of
them is addressed to our device, but the node does not say which, so we try them
until one decrypts. A failure on every entry is reported with the failing device
JIDs, because the caller then owes the sender a retry receipt.
"""

from __future__ import annotations

from dataclasses import dataclass

from wapy.errors import WapyError
from wapy.messaging.signals import SignalSessions
from wapy.protocol.messages import IncomingMessage, decode_text, parse_incoming
from wapy.protocol.wabinary import Node


class ReceiveError(WapyError):
    """The node is not a message we can use."""


class DecryptError(ReceiveError):
    """No `<enc>` entry could be decrypted."""

    def __init__(self, message: str, *, devices: list[str]) -> None:
        super().__init__(message)
        self.devices = devices


@dataclass(frozen=True, slots=True)
class ReceivedMessage:
    chat_jid: str
    sender_jid: str
    message_id: str
    device_jid: str
    text: str | None
    prekey: bool


class MessageReceiver:
    def __init__(self, sessions: SignalSessions) -> None:
        self._sessions = sessions

    async def receive(self, node: Node) -> ReceivedMessage:
        incoming: IncomingMessage = parse_incoming(node)
        if not incoming.devices:
            raise ReceiveError("message node carries no encrypted payloads")

        failures: list[str] = []
        for device in incoming.devices:
            try:
                plaintext = await self._sessions.decrypt(
                    device.device_jid, device.ciphertext, prekey=device.prekey
                )
            except Exception:
                failures.append(device.device_jid)
                continue
            return ReceivedMessage(
                chat_jid=incoming.from_jid,
                sender_jid=incoming.from_jid,
                message_id=incoming.message_id,
                device_jid=device.device_jid,
                text=decode_text(plaintext),
                prekey=device.prekey,
            )
        raise DecryptError("could not decrypt any payload", devices=failures)
