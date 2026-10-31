"""Encryption boundary for outgoing messages.

The messenger does not know how Signal works: it asks for a ciphertext per device
and gets back an `EncryptedDevice`, ready to become an `<enc>` child. The real
implementation lives in `wapy.messaging.store_sessions` and is backed by the
Signal state in `SessionStore`.
"""

from __future__ import annotations

from typing import Protocol

from wapy.messaging.devices import DeviceInfo
from wapy.protocol.messages import EncryptedDevice


class SignalSessions(Protocol):
    async def encrypt(self, device: DeviceInfo, plaintext: bytes) -> EncryptedDevice:
        """Encrypt one payload for one device, establishing a session if needed."""
        ...
