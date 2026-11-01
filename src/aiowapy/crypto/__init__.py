"""Cryptographic layer of aiowapy."""

from __future__ import annotations

from aiowapy.crypto.media import (
    MEDIA_MAC_LEN,
    EncryptedMedia,
    MediaCryptoError,
    MediaKeys,
    decrypt_media,
    derive_media_keys,
    encrypt_media,
    media_info,
)
from aiowapy.crypto.primitives import (
    CryptoError,
    KeyPair,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    dh,
    generate_keypair,
    hkdf,
    hmac_sha256,
    public_from_private,
    sha256,
)
from aiowapy.crypto.signal_proto import (
    PreKeyWhisperMessage,
    SignalProtoError,
    WhisperMessage,
    decode_prekey,
    decode_whisper,
    encode_prekey,
    encode_whisper,
)
from aiowapy.crypto.xeddsa import XEdDSAError, montgomery_to_edwards, sign, verify

__all__ = [
    "MEDIA_MAC_LEN",
    "CryptoError",
    "EncryptedMedia",
    "KeyPair",
    "MediaCryptoError",
    "MediaKeys",
    "PreKeyWhisperMessage",
    "SignalProtoError",
    "WhisperMessage",
    "XEdDSAError",
    "aes_cbc_decrypt",
    "aes_cbc_encrypt",
    "aes_gcm_decrypt",
    "aes_gcm_encrypt",
    "decode_prekey",
    "decode_whisper",
    "decrypt_media",
    "derive_media_keys",
    "dh",
    "encode_prekey",
    "encode_whisper",
    "encrypt_media",
    "generate_keypair",
    "hkdf",
    "hmac_sha256",
    "media_info",
    "montgomery_to_edwards",
    "public_from_private",
    "sha256",
    "sign",
    "verify",
]
