from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from wapy.errors import WapyError
from wapy.messaging.signals import SignalSessions
from wapy.protocol.media import MediaInfo
from wapy.protocol.messages import IncomingMessage, ParsedMessage, parse_incoming, parse_message
from wapy.protocol.wabinary import Node


class ReceiveError(WapyError):
    """The node is not a message we can use."""


class DecryptError(ReceiveError):
    """No `<enc>` entry could be decrypted."""

    def __init__(self, message: str, *, devices: list[str]) -> None:
        super().__init__(message)
        self.devices = devices


class GroupSessions(Protocol):
    """Sender key state: decryption and distribution messages, per group member."""

    async def decrypt(self, group_jid: str, sender_jid: str, ciphertext: bytes) -> bytes: ...

    async def accept_distribution(
        self, group_jid: str, sender_jid: str, serialized: bytes
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ReceivedMessage:
    chat_jid: str
    sender_jid: str
    message_id: str
    device_jid: str
    text: str | None
    prekey: bool
    media: MediaInfo | None = None
    timestamp: int | None = None
    parsed: ParsedMessage | None = None


class MessageReceiver:
    def __init__(self, sessions: SignalSessions, groups: GroupSessions | None = None) -> None:
        self._sessions = sessions
        self._groups = groups

    async def receive(self, node: Node) -> ReceivedMessage:
        incoming = parse_incoming(node)
        sender_jid = incoming.participant or incoming.from_jid
        if not incoming.devices and incoming.sender_key is None:
            raise ReceiveError("message node carries no encrypted payloads")

        failures: list[str] = []
        distribution: ParsedMessage | None = None
        for device in incoming.devices:
            try:
                plaintext = await self._sessions.decrypt(
                    device.device_jid, device.ciphertext, prekey=device.prekey
                )
            except Exception:
                failures.append(device.device_jid)
                continue
            parsed = parse_message(plaintext)
            if parsed.sender_key_distribution:
                # The sender key attached to a group message: store it, then decrypt
                # the group ciphertext below instead of returning this envelope.
                if self._groups is not None:
                    await self._groups.accept_distribution(
                        parsed.sender_key_group or incoming.from_jid,
                        sender_jid,
                        parsed.sender_key_distribution,
                    )
                    distribution = parsed
                continue
            return self._received(
                incoming, device.device_jid, parsed, sender_jid, prekey=device.prekey
            )

        if incoming.sender_key is not None:
            if self._groups is None:
                raise DecryptError(
                    "group message but no sender keys are available", devices=failures
                )
            try:
                plaintext = await self._groups.decrypt(
                    incoming.from_jid, sender_jid, incoming.sender_key
                )
            except Exception as exc:
                raise DecryptError(f"group decryption failed: {exc}", devices=failures) from exc
            return self._received(incoming, "", parse_message(plaintext), sender_jid, prekey=False)

        if distribution is not None:
            return self._received(incoming, "", distribution, sender_jid, prekey=False)
        raise DecryptError("could not decrypt any payload", devices=failures)

    def _received(
        self,
        incoming: IncomingMessage,
        device_jid: str,
        parsed: ParsedMessage,
        sender_jid: str,
        *,
        prekey: bool,
    ) -> ReceivedMessage:
        return ReceivedMessage(
            chat_jid=incoming.from_jid,
            sender_jid=sender_jid,
            message_id=incoming.message_id,
            device_jid=device_jid,
            text=parsed.text,
            prekey=prekey,
            media=parsed.media,
            timestamp=incoming.timestamp,
            parsed=parsed,
        )
