"""QR codes for WhatsApp Multi-Device pairing.

The payload is fixed by the protocol: a landing URL, then a comma-separated list
of the pairing reference issued by the server, the Noise public key, the signed
identity public key, the advanced secret key and a companion platform id. Base64
key material is what makes the string long enough to need QR versions 5-10.
"""

from __future__ import annotations

import base64
from typing import Final

from wapy.creds import DeviceCredentials
from wapy.errors import WapyError
from wapy.qr.encoder import QrCode, encode

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
