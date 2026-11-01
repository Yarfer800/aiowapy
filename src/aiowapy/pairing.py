"""QR codes for WhatsApp Multi-Device pairing.

The payload is fixed by the protocol: a landing URL, then a comma-separated list
of the pairing reference issued by the server, the Noise public key, the signed
identity public key, the advanced secret key and a companion platform id. Base64
key material is what makes the string long enough to need QR versions 5-10.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Final

from aiowapy.creds import DeviceCredentials
from aiowapy.errors import WapyError
from aiowapy.qr.encoder import QrCode, encode

PAIRING_URL: Final = "https://wa.me/settings/linked_devices#"

PLATFORM_IDS: Final[dict[str, int]] = {
    "unknown": 0,
    "chrome": 1,
    "edge": 2,
    "firefox": 3,
    "ie": 4,
    "opera": 5,
    "safari": 6,
    "electron": 7,
    "uwp": 8,
    "other": 9,
}


class PairingQrError(WapyError):
    """The inputs cannot form a valid pairing payload."""


def _base64_key(key: bytes, name: str) -> str:
    if len(key) != 32:
        raise PairingQrError(f"{name} must be 32 bytes, got {len(key)}")
    return base64.b64encode(key).decode("ascii")


def build_pairing_payload(
    ref: str,
    noise_public: bytes,
    identity_public: bytes,
    adv_secret: str,
    *,
    platform: str = "chrome",
) -> str:
    """Assemble the string that a phone scans during device linking."""
    if not ref:
        raise PairingQrError("pairing ref must not be empty")
    if "," in ref:
        raise PairingQrError("pairing ref must not contain a comma")
    if platform not in PLATFORM_IDS:
        raise PairingQrError(f"unknown platform: {platform!r}")
    if not adv_secret:
        raise PairingQrError("advanced secret key must not be empty")
    parts = (
        ref,
        _base64_key(noise_public, "noise public key"),
        _base64_key(identity_public, "identity public key"),
        adv_secret,
        str(PLATFORM_IDS[platform]),
    )
    return PAIRING_URL + ",".join(parts)


def pairing_qr(
    ref: str,
    credentials: DeviceCredentials,
    *,
    platform: str = "chrome",
    level: str = "M",
) -> tuple[str, QrCode]:
    """Build the pairing payload from generated credentials and encode it."""
    payload = build_pairing_payload(
        ref,
        credentials.noise_public,
        credentials.identity_public,
        credentials.adv_secret_key,
        platform=platform,
    )
    return payload, encode(payload, level=level)


QR_FIRST_TTL = 60
QR_NEXT_TTL = 20


@dataclass(frozen=True, slots=True)
class PairingQr:
    """One QR to show. `ttl` is how long the caller may keep it on screen."""

    payload: str
    qr: QrCode
    ttl: int


class PairingQrSource:
    """Rotate through the server-issued pairing refs.

    The server sends a batch of refs in the `pair-device` node; each one is a
    short-lived routing token, so the client shows them one by one on a timer.
    The timing is a client policy: 60 s for the first QR, 20 s for the rest,
    matching the official web client.

    Nothing here sleeps — the caller owns the clock. `next()` returns None when
    the batch is exhausted, which is a terminal condition: fresh refs require a
    new connection.
    """

    def __init__(
        self,
        credentials: DeviceCredentials,
        refs: Iterable[str],
        *,
        platform: str = "chrome",
        level: str = "M",
        first_ttl: int = QR_FIRST_TTL,
        next_ttl: int = QR_NEXT_TTL,
    ) -> None:
        self._refs = list(refs)
        if not self._refs:
            raise PairingQrError("the server issued no pairing refs")
        self._credentials = credentials
        self._platform = platform
        self._level = level
        self._first_ttl = first_ttl
        self._next_ttl = next_ttl
        self._index = 0

    def __len__(self) -> int:
        return len(self._refs)

    @property
    def remaining(self) -> int:
        return len(self._refs) - self._index

    def next(self) -> PairingQr | None:
        if self._index >= len(self._refs):
            return None
        ref = self._refs[self._index]
        ttl = self._first_ttl if self._index == 0 else self._next_ttl
        self._index += 1
        payload, qr = pairing_qr(ref, self._credentials, platform=self._platform, level=self._level)
        return PairingQr(payload=payload, qr=qr, ttl=ttl)

    def __iter__(self) -> Iterator[PairingQr]:
        while True:
            item = self.next()
            if item is None:
                return
            yield item
