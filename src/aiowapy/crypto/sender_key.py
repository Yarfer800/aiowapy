from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from aiowapy.crypto.primitives import (
    KeyPair,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    generate_keypair,
    hkdf,
    hmac_sha256,
)
from aiowapy.crypto.xeddsa import sign, verify
from aiowapy.errors import WapyError
from aiowapy.pb import bytes_field, first_bytes, first_int, parse_fields, varint_field

MESSAGE_VERSION = 3
VERSION_BYTE = ((MESSAGE_VERSION << 4) | MESSAGE_VERSION) & 0xFF
SIGNATURE_LENGTH = 64
MAX_FORWARD_JUMP = 2000
KDF_INFO = b"WhisperGroup"
CHAIN_KEY_SEED = b"\x02"
MESSAGE_KEY_SEED = b"\x01"

_FIELD_KEY_ID = 1
_FIELD_ITERATION = 2
_FIELD_CIPHERTEXT = 3
_FIELD_CHAIN_KEY = 3
_FIELD_SIGNING_KEY = 4

MAX_PAD = 15


class SenderKeyError(WapyError):
    """Sender key state is missing, corrupted or used out of order."""


@dataclass(frozen=True, slots=True)
class SenderMessageKey:
    iteration: int
    seed: bytes

    @property
    def iv(self) -> bytes:
        return self._expanded()[:16]

    @property
    def cipher_key(self) -> bytes:
        return self._expanded()[16:48]

    def _expanded(self) -> bytes:
        return hkdf(self.seed, 64, KDF_INFO, bytes(32))


@dataclass
class SenderKeyState:
    """The sending chain of one member in one group.

    The same record serves both directions: sending needs `signing_private`, receiving
    only the public half. `message_keys` keeps the keys of skipped iterations so a
    message that arrives late can still be opened.
    """

    key_id: int
    iteration: int
    chain_key: bytes
    signing_public: bytes
    signing_private: KeyPair | None = None
    message_keys: list[SenderMessageKey] = field(default_factory=list)

    @classmethod
    def create(cls, *, key_id: int | None = None) -> SenderKeyState:
        signing = generate_keypair()
        return cls(
            key_id=key_id if key_id is not None else secrets.randbits(32),
            iteration=0,
            chain_key=secrets.token_bytes(32),
            signing_public=signing.public,
            signing_private=signing,
        )

    def next_message_key(self, target: int) -> SenderMessageKey:
        if not target >= 0:
            raise SenderKeyError("iteration must not be negative")
        if self.iteration > target:
            for index, key in enumerate(self.message_keys):
                if key.iteration == target:
                    return self.message_keys.pop(index)
            raise SenderKeyError(f"iteration {target} is older than the chain ({self.iteration})")
        if target - self.iteration > MAX_FORWARD_JUMP:
            raise SenderKeyError(f"more than {MAX_FORWARD_JUMP} messages into the future")
        while self.iteration < target:
            self.message_keys.append(SenderMessageKey(self.iteration, self.chain_key_seed()))
            self.advance()
        key = SenderMessageKey(self.iteration, self.chain_key_seed())
        self.advance()
        return key

    def chain_key_seed(self) -> bytes:
        return hmac_sha256(self.chain_key, MESSAGE_KEY_SEED)

    def advance(self) -> None:
        self.chain_key = hmac_sha256(self.chain_key, CHAIN_KEY_SEED)
        self.iteration += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "iteration": self.iteration,
            "chain_key": _b64(self.chain_key),
            "signing_public": _b64(self.signing_public),
            "signing_private": _b64(self.signing_private.private) if self.signing_private else None,
            "message_keys": [
                {"iteration": key.iteration, "seed": _b64(key.seed)} for key in self.message_keys
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SenderKeyState:
        private = data.get("signing_private")
        public = _unb64(data["signing_public"], 32)
        return cls(
            key_id=int(data["key_id"]),
            iteration=int(data["iteration"]),
            chain_key=_unb64(data["chain_key"], 32),
            signing_public=public,
            signing_private=KeyPair(private=_unb64(private, 32), public=public)
            if private
            else None,
            message_keys=[
                SenderMessageKey(iteration=int(item["iteration"]), seed=_unb64(item["seed"], 32))
                for item in data.get("message_keys", [])
            ],
        )


def encrypt(state: SenderKeyState, plaintext: bytes) -> bytes:
    """One group ciphertext, signed with the sender's signing key."""
    if state.signing_private is None:
        raise SenderKeyError("cannot encrypt without the signing key")
    # The reference implementation always burns one iteration after the first, so
    # iterations go 0, 2, 4... Late messages then land on a stored key instead of
    # rewinding the chain.
    target = 0 if state.iteration == 0 else state.iteration + 1
    message_key = state.next_message_key(target)
    ciphertext = aes_cbc_encrypt(message_key.cipher_key, message_key.iv, pad(plaintext))
    body = b"".join(
        (
            varint_field(_FIELD_KEY_ID, state.key_id),
            varint_field(_FIELD_ITERATION, message_key.iteration),
            bytes_field(_FIELD_CIPHERTEXT, ciphertext),
        )
    )
    signed = bytes((VERSION_BYTE,)) + body
    return signed + sign(state.signing_private.private, signed)


def decrypt(state: SenderKeyState, serialized: bytes) -> bytes:
    if len(serialized) <= 1 + SIGNATURE_LENGTH:
        raise SenderKeyError("sender key message is too short")
    signed = serialized[:-SIGNATURE_LENGTH]
    signature = serialized[-SIGNATURE_LENGTH:]
    if signed[0] != VERSION_BYTE:
        raise SenderKeyError(f"unsupported sender key version: {signed[0]:#04x}")
    if not verify(state.signing_public, signed, signature):
        raise SenderKeyError("sender key signature does not match the signing key")

    fields = parse_fields(signed[1:])
    key_id = first_int(fields, _FIELD_KEY_ID)
    if key_id != state.key_id:
        raise SenderKeyError(f"message is for key {key_id}, state holds {state.key_id}")
    message_key = state.next_message_key(first_int(fields, _FIELD_ITERATION))
    ciphertext = first_bytes(fields, _FIELD_CIPHERTEXT)
    return unpad(aes_cbc_decrypt(message_key.cipher_key, message_key.iv, ciphertext))


def distribution_message(state: SenderKeyState) -> bytes:
    """The sender key distribution message: everything a member needs to listen."""
    body = b"".join(
        (
            varint_field(_FIELD_KEY_ID, state.key_id),
            varint_field(_FIELD_ITERATION, state.iteration),
            bytes_field(_FIELD_CHAIN_KEY, state.chain_key),
            bytes_field(_FIELD_SIGNING_KEY, state.signing_public),
        )
    )
    return bytes((VERSION_BYTE,)) + body


def from_distribution(serialized: bytes) -> SenderKeyState:
    if len(serialized) < 2:
        raise SenderKeyError("distribution message is too short")
    if serialized[0] != VERSION_BYTE:
        raise SenderKeyError(f"unsupported sender key version: {serialized[0]:#04x}")
    fields = parse_fields(serialized[1:])
    chain_key = first_bytes(fields, _FIELD_CHAIN_KEY)
    signing_key = first_bytes(fields, _FIELD_SIGNING_KEY)
    if len(chain_key) != 32 or len(signing_key) != 32:
        raise SenderKeyError("distribution message carries keys of the wrong size")
    return SenderKeyState(
        key_id=first_int(fields, _FIELD_KEY_ID),
        iteration=first_int(fields, _FIELD_ITERATION),
        chain_key=chain_key,
        signing_public=signing_key,
    )


def pad(plaintext: bytes) -> bytes:
    """Random 1..15 byte padding, on top of the CBC padding the cipher adds."""
    size = secrets.randbelow(MAX_PAD) + 1
    return plaintext + bytes((size,)) * size


def unpad(padded: bytes) -> bytes:
    if not padded:
        raise SenderKeyError("plaintext is empty")
    size = padded[-1]
    if not 1 <= size <= MAX_PAD or size > len(padded):
        raise SenderKeyError(f"invalid padding length: {size}")
    return padded[:-size]


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: object, expected: int) -> bytes:
    if not isinstance(value, str):
        raise SenderKeyError("expected a base64 string")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise SenderKeyError("value is not valid base64") from exc
    if len(raw) != expected:
        raise SenderKeyError(f"expected {expected} bytes, got {len(raw)}")
    return raw


def serialize_state(state: SenderKeyState) -> bytes:
    return json.dumps(state.to_dict()).encode("utf-8")


def deserialize_state(record: bytes) -> SenderKeyState:
    try:
        data = json.loads(record.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SenderKeyError("sender key record is not valid JSON") from exc
    if not isinstance(data, dict):
        raise SenderKeyError("sender key record is not an object")
    return SenderKeyState.from_dict(data)


def validate_state(state: SenderKeyState) -> None:
    """Cheap sanity check used when loading a persisted record."""
    if len(state.chain_key) != 32:
        raise SenderKeyError("the chain key is corrupted")
    if len(state.signing_public) != 32:
        raise SenderKeyError("the signing key is corrupted")
    if state.signing_private is not None and state.signing_private.public != state.signing_public:
        raise SenderKeyError("signing key pair does not match")
    if state.key_id < 0:
        raise SenderKeyError("key id must not be negative")
    if state.iteration < 0:
        raise SenderKeyError("iteration must not be negative")
