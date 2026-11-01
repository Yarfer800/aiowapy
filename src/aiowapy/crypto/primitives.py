"""Cryptographic primitives: HKDF, HMAC, AES, X25519.

Everything the protocol needs lives in one place, so callers never import
`cryptography` directly and error handling does not spread across layers.
"""

from __future__ import annotations

import hashlib
import hmac as stdlib_hmac
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from aiowapy.errors import WapyError

KEY_LEN = 32
IV_LEN = 16
_BLOCK = 16
_HASH_LEN = 32


class CryptoError(WapyError):
    """Cryptographic operation is impossible or the data is corrupted."""


@dataclass(frozen=True, slots=True)
class KeyPair:
    private: bytes
    public: bytes


def sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return stdlib_hmac.new(key, data, "sha256").digest()


def hkdf(ikm: bytes, length: int, info: bytes, salt: bytes | None = None) -> bytes:
    """HKDF-SHA256 (RFC 5869). salt=None means 32 zero bytes, as WhatsApp uses."""
    if length <= 0:
        raise CryptoError("HKDF output length must be positive")
    if length > 255 * _HASH_LEN:
        raise CryptoError("requested more bytes than HKDF-SHA256 allows")
    actual_salt = bytes(_HASH_LEN) if salt is None else salt
    prk = hmac_sha256(actual_salt, ikm)
    blocks: list[bytes] = []
    previous = b""
    produced = 0
    counter = 1
    while produced < length:
        previous = hmac_sha256(prk, previous + info + bytes([counter]))
        blocks.append(previous)
        produced += len(previous)
        counter += 1
    return b"".join(blocks)[:length]


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes, *, pad: bool = True) -> bytes:
    _require_length(key, KEY_LEN, "key")
    _require_length(iv, IV_LEN, "IV")
    payload = data
    if pad:
        padder = symmetric_padding.PKCS7(_BLOCK * 8).padder()
        payload = padder.update(data) + padder.finalize()
    elif len(payload) % _BLOCK != 0:
        raise CryptoError("data is not block aligned and padding is disabled")
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(payload) + encryptor.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes, *, unpad: bool = True) -> bytes:
    _require_length(key, KEY_LEN, "key")
    _require_length(iv, IV_LEN, "IV")
    if not data or len(data) % _BLOCK != 0:
        raise CryptoError("ciphertext is not block aligned")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    payload = decryptor.update(data) + decryptor.finalize()
    if not unpad:
        return payload
    unpadder = symmetric_padding.PKCS7(_BLOCK * 8).unpadder()
    try:
        return unpadder.update(payload) + unpadder.finalize()
    except ValueError as exc:
        raise CryptoError("invalid padding in decrypted data") from exc


def aes_gcm_encrypt(key: bytes, iv: bytes, data: bytes, aad: bytes = b"") -> bytes:
    _require_length(key, KEY_LEN, "key")
    try:
        return AESGCM(key).encrypt(iv, data, aad)
    except (ValueError, InvalidTag) as exc:  # pragma: no cover - guards against wrong lengths
        raise CryptoError("failed to encrypt data with AES-GCM") from exc


def aes_gcm_decrypt(key: bytes, iv: bytes, data: bytes, aad: bytes = b"") -> bytes:
    _require_length(key, KEY_LEN, "key")
    try:
        return AESGCM(key).decrypt(iv, data, aad)
    except (ValueError, InvalidTag) as exc:
        raise CryptoError("data is corrupted or the key is wrong") from exc


def aes_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-256-CTR is symmetric: the same call encrypts and decrypts."""
    _require_length(key, KEY_LEN, "key")
    if len(iv) != IV_LEN:
        raise CryptoError(f"IV: expected {IV_LEN} bytes, got {len(iv)}")
    transformer = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return transformer.update(data) + transformer.finalize()


def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, length: int = 32) -> bytes:
    if iterations < 1:
        raise CryptoError("PBKDF2 iterations must be positive")
    if length < 1:
        raise CryptoError("PBKDF2 output length must be positive")
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, length)


def generate_keypair() -> KeyPair:
    private = X25519PrivateKey.generate()
    raw_private = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return KeyPair(private=raw_private, public=_public_bytes(private))


def public_from_private(private: bytes) -> bytes:
    _require_length(private, KEY_LEN, "private key")
    try:
        key = X25519PrivateKey.from_private_bytes(private)
    except ValueError as exc:
        raise CryptoError("invalid X25519 private key") from exc
    return _public_bytes(key)


def dh(private: bytes, public: bytes) -> bytes:
    _require_length(private, KEY_LEN, "private key")
    _require_length(public, KEY_LEN, "public key")
    try:
        key = X25519PrivateKey.from_private_bytes(private)
        peer = X25519PublicKey.from_public_bytes(public)
        shared = key.exchange(peer)
    except (ValueError, TypeError) as exc:
        raise CryptoError("failed to compute the X25519 shared secret") from exc
    if not any(shared):
        raise CryptoError("X25519 shared secret is degenerate (all zeros)")
    return shared


def _public_bytes(private: X25519PrivateKey) -> bytes:
    public = private.public_key()
    raw: bytes = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw


def _require_length(value: bytes, expected: int, name: str) -> None:
    if len(value) != expected:
        raise CryptoError(f"{name}: expected {expected} bytes, got {len(value)}")
