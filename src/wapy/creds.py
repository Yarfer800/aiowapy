"""Device credentials: the key material a companion device owns.

Everything here is generated locally on first run and then persisted in the
session file. Only `ref` in the pairing QR comes from the server; the keys and
the advanced secret are ours.

The JSON representation is what `SessionStore` keeps in the `creds` table: all
binary values are base64, so the blob stays readable and stable across versions.
"""

from __future__ import annotations

import base64
import binascii
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from wapy.crypto.primitives import CryptoError, KeyPair, generate_keypair
from wapy.crypto.xeddsa import sign, verify
from wapy.errors import WapyError

SIGNAL_KEY_PREFIX = b"\x05"
REGISTRATION_ID_MAX = 16383
ADV_SECRET_LEN = 32


class CredentialsError(WapyError):
    """Stored credentials are malformed or fail verification."""


@dataclass(frozen=True, slots=True)
class SignedPreKey:
    key_id: int
    key_pair: KeyPair
    signature: bytes

    @property
    def signal_public(self) -> bytes:
        return SIGNAL_KEY_PREFIX + self.key_pair.public


@dataclass(frozen=True, slots=True)
class DeviceCredentials:
    noise_key: KeyPair
    identity_key: KeyPair
    signed_pre_key: SignedPreKey
    registration_id: int
    adv_secret_key: str

    @property
    def noise_public(self) -> bytes:
        return self.noise_key.public

    @property
    def identity_public(self) -> bytes:
        return self.identity_key.public

    @property
    def identity_signal_public(self) -> bytes:
        """Identity key in the 33-byte form used on the wire."""
        return SIGNAL_KEY_PREFIX + self.identity_public

    def verify(self) -> bool:
        """Check that the signed prekey really belongs to this identity."""
        return verify(
            self.identity_public,
            self.signed_pre_key.signal_public,
            self.signed_pre_key.signature,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "noise_private": _b64(self.noise_key.private),
            "noise_public": _b64(self.noise_key.public),
            "identity_private": _b64(self.identity_key.private),
            "identity_public": _b64(self.identity_key.public),
            "signed_pre_key_id": self.signed_pre_key.key_id,
            "signed_pre_key_private": _b64(self.signed_pre_key.key_pair.private),
            "signed_pre_key_public": _b64(self.signed_pre_key.key_pair.public),
            "signed_pre_key_signature": _b64(self.signed_pre_key.signature),
            "registration_id": self.registration_id,
            "adv_secret_key": self.adv_secret_key,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DeviceCredentials:
        try:
            credentials = cls(
                noise_key=KeyPair(
                    private=_unb64(data["noise_private"], 32),
                    public=_unb64(data["noise_public"], 32),
                ),
                identity_key=KeyPair(
                    private=_unb64(data["identity_private"], 32),
                    public=_unb64(data["identity_public"], 32),
                ),
                signed_pre_key=SignedPreKey(
                    key_id=int(data["signed_pre_key_id"]),
                    key_pair=KeyPair(
                        private=_unb64(data["signed_pre_key_private"], 32),
                        public=_unb64(data["signed_pre_key_public"], 32),
                    ),
                    signature=_unb64(data["signed_pre_key_signature"], 64),
                ),
                registration_id=int(data["registration_id"]),
                adv_secret_key=str(data["adv_secret_key"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CredentialsError(f"malformed credentials: {exc}") from exc
        if not 0 <= credentials.registration_id <= REGISTRATION_ID_MAX:
            raise CredentialsError("registration_id is out of range")
        try:
            secret = base64.b64decode(credentials.adv_secret_key, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CredentialsError("adv_secret_key is not valid base64") from exc
        if len(secret) != ADV_SECRET_LEN:
            raise CredentialsError("adv_secret_key must decode to 32 bytes")
        return credentials


def signal_public_key(public: bytes) -> bytes:
    """Key bundle prefix used by Signal keys on the wire."""
    if len(public) == 33 and public[:1] == SIGNAL_KEY_PREFIX:
        return public
    if len(public) != 32:
        raise CredentialsError(f"expected a 32-byte key, got {len(public)}")
    return SIGNAL_KEY_PREFIX + public


def generate_credentials(
    *,
    signed_pre_key_id: int = 1,
    registration_id: int | None = None,
) -> DeviceCredentials:
    """Create fresh credentials. Call this once, on first run, then persist them."""
    identity_key = generate_keypair()
    signed_pre_key_pair = generate_keypair()
    try:
        signature = sign(identity_key.private, signal_public_key(signed_pre_key_pair.public))
    except CryptoError as exc:  # pragma: no cover - key material comes from us
        raise CredentialsError("failed to sign the signed prekey") from exc
    if registration_id is None:
        registration_id = secrets.randbits(16) & REGISTRATION_ID_MAX
    if not 0 <= registration_id <= REGISTRATION_ID_MAX:
        raise CredentialsError("registration_id is out of range")
    return DeviceCredentials(
        noise_key=generate_keypair(),
        identity_key=identity_key,
        signed_pre_key=SignedPreKey(
            key_id=signed_pre_key_id,
            key_pair=signed_pre_key_pair,
            signature=signature,
        ),
        registration_id=registration_id,
        adv_secret_key=base64.b64encode(secrets.token_bytes(ADV_SECRET_LEN)).decode("ascii"),
    )


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object, expected_length: int) -> bytes:
    if not isinstance(value, str):
        raise CredentialsError("expected a base64 string")
    raw = base64.b64decode(value, validate=True)
    if len(raw) != expected_length:
        raise CredentialsError(f"expected {expected_length} bytes, got {len(raw)}")
    return raw
