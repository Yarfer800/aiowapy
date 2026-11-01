"""Which devices belong to a recipient, and how long we trust that answer.

A WhatsApp account is a set of devices (phone plus companions). Every device gets
its own Signal session, so sending one message means enumerating them first.
Enumeration is a `usync` round trip; doing it per message would add latency and
traffic, so answers are cached with a short TTL.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from aiowapy.errors import WapyError

DEFAULT_DEVICE_TTL = 300.0


class DeviceError(WapyError):
    """The device list for a recipient cannot be obtained."""


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """One device of one account, with what Signal needs to start a session."""

    jid: str
    identity_key: bytes
    signed_pre_key: bytes
    signed_pre_key_id: int
    registration_id: int
    pre_key: bytes | None = None
    pre_key_id: int | None = None


class DeviceFetcher(Protocol):
    """The network half: a `usync` query plus prekey bundles."""

    async def fetch(self, jid: str) -> list[DeviceInfo]: ...


class DeviceResolver(Protocol):
    async def devices(self, jid: str) -> list[DeviceInfo]: ...


@dataclass(slots=True)
class _Entry:
    devices: list[DeviceInfo]
    expires_at: float


class CachedDeviceResolver:
    """Caches device lists per recipient for a fixed time.

    `invalidate` is what the caller uses when the cached answer turns out to be
    wrong: a device disappeared (`item-not-found` on send) or its identity key
    changed, which Signal reports as a new session.
    """

    def __init__(
        self,
        fetcher: DeviceFetcher,
        *,
        ttl: float = DEFAULT_DEVICE_TTL,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if ttl <= 0:
            raise DeviceError("ttl must be positive")
        self._fetcher = fetcher
        self._ttl = ttl
        self._clock = clock
        self._entries: dict[str, _Entry] = {}

    async def devices(self, jid: str) -> list[DeviceInfo]:
        entry = self._entries.get(jid)
        now = self._clock()
        if entry is not None and entry.expires_at > now:
            return entry.devices
        devices = await self._fetcher.fetch(jid)
        self._entries[jid] = _Entry(devices=list(devices), expires_at=now + self._ttl)
        return list(devices)

    def invalidate(self, jid: str) -> None:
        self._entries.pop(jid, None)

    def invalidate_all(self) -> None:
        self._entries.clear()
