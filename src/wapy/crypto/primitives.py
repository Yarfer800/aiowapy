"""Криптопримитивы: HKDF, HMAC, AES, X25519.

Всё, что нужно протоколу, в одной точке — чтобы вызывающий код не тянул
`cryptography` напрямую и не разносил обработку ошибок по слоям.
"""

from __future__ import annotations

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

from wapy.errors import WapyError

KEY_LEN = 32
IV_LEN = 16
_BLOCK = 16
_HASH_LEN = 32


class CryptoError(WapyError):
    """Криптографическая операция невозможна или данные повреждены."""


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
    """HKDF-SHA256 (RFC 5869). salt=None — 32 нулевых байта, как в WhatsApp."""
    if length <= 0:
        raise CryptoError("длина вывода HKDF должна быть положительной")
    if length > 255 * _HASH_LEN:
        raise CryptoError("запрошено больше байтов, чем допускает HKDF-SHA256")
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
    _require_length(key, KEY_LEN, "ключ")
    _require_length(iv, IV_LEN, "IV")
    payload = data
    if pad:
        padder = symmetric_padding.PKCS7(_BLOCK * 8).padder()
        payload = padder.update(data) + padder.finalize()
    elif len(payload) % _BLOCK != 0:
        raise CryptoError("данные не выровнены по блоку, а padding отключён")
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(payload) + encryptor.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes, *, unpad: bool = True) -> bytes:
    _require_length(key, KEY_LEN, "ключ")
    _require_length(iv, IV_LEN, "IV")
    if not data or len(data) % _BLOCK != 0:
        raise CryptoError("шифртекст не выровнен по блоку")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    payload = decryptor.update(data) + decryptor.finalize()
    if not unpad:
        return payload
    unpadder = symmetric_padding.PKCS7(_BLOCK * 8).unpadder()
    try:
        return unpadder.update(payload) + unpadder.finalize()
    except ValueError as exc:
        raise CryptoError("некорректный padding в расшифрованных данных") from exc


def aes_gcm_encrypt(key: bytes, iv: bytes, data: bytes, aad: bytes = b"") -> bytes:
    _require_length(key, KEY_LEN, "ключ")
    try:
        return AESGCM(key).encrypt(iv, data, aad)
    except (ValueError, InvalidTag) as exc:  # pragma: no cover - защита от неверных длин
        raise CryptoError("не удалось зашифровать данные AES-GCM") from exc


def aes_gcm_decrypt(key: bytes, iv: bytes, data: bytes, aad: bytes = b"") -> bytes:
    _require_length(key, KEY_LEN, "ключ")
    try:
        return AESGCM(key).decrypt(iv, data, aad)
    except (ValueError, InvalidTag) as exc:
        raise CryptoError("данные повреждены или ключ неверен") from exc


def generate_keypair() -> KeyPair:
    private = X25519PrivateKey.generate()
    raw_private = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return KeyPair(private=raw_private, public=_public_bytes(private))


def public_from_private(private: bytes) -> bytes:
    _require_length(private, KEY_LEN, "приватный ключ")
    try:
        key = X25519PrivateKey.from_private_bytes(private)
    except ValueError as exc:
        raise CryptoError("некорректный приватный ключ X25519") from exc
    return _public_bytes(key)


def dh(private: bytes, public: bytes) -> bytes:
    _require_length(private, KEY_LEN, "приватный ключ")
    _require_length(public, KEY_LEN, "публичный ключ")
    try:
        key = X25519PrivateKey.from_private_bytes(private)
        peer = X25519PublicKey.from_public_bytes(public)
        shared = key.exchange(peer)
    except (ValueError, TypeError) as exc:
        raise CryptoError("не удалось вычислить общий секрет X25519") from exc
    if not any(shared):
        raise CryptoError("общий секрет X25519 вырожден (нулевой)")
    return shared


def _public_bytes(private: X25519PrivateKey) -> bytes:
    public = private.public_key()
    raw: bytes = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return raw


def _require_length(value: bytes, expected: int, name: str) -> None:
    if len(value) != expected:
        raise CryptoError(f"{name}: ожидалось {expected} байт, получено {len(value)}")
