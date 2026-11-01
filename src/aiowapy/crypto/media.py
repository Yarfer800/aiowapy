"""WhatsApp media encryption: HKDF + AES-256-CBC + truncated HMAC."""

from __future__ import annotations

import hmac as stdlib_hmac
from dataclasses import dataclass

from aiowapy.crypto.primitives import (
    CryptoError,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    hkdf,
    hmac_sha256,
    sha256,
)

MEDIA_MAC_LEN = 10
_MEDIA_KEY_LEN = 32

# Media type to HKDF info mapping, matching the reference implementation.
MEDIA_INFO: dict[str, str] = {
    "audio": "Audio",
    "document": "Document",
    "gif": "Video",
    "image": "Image",
    "ppic": "",
    "product": "Image",
    "ptt": "Audio",
    "sticker": "Image",
    "video": "Video",
    "thumbnail-document": "Document Thumbnail",
    "thumbnail-image": "Image Thumbnail",
    "thumbnail-video": "Video Thumbnail",
    "thumbnail-link": "Link Thumbnail",
    "md-app-state": "App State",
    "md-msg-hist": "Message History",
    "product-image": "Product Image",
    "product-catalog-image": "Product Catalog Image",
}


class MediaCryptoError(CryptoError):
    """Media data is corrupted or the parameters are invalid."""


@dataclass(frozen=True, slots=True)
class MediaKeys:
    iv: bytes
    cipher_key: bytes
    mac_key: bytes
    ref_key: bytes


@dataclass(frozen=True, slots=True)
class EncryptedMedia:
    ciphertext: bytes
    mac: bytes
    file_sha256: bytes
    file_enc_sha256: bytes

    @property
    def payload(self) -> bytes:
        """Bytes uploaded to the CDN: ciphertext followed by the MAC."""
        return self.ciphertext + self.mac


def media_info(media_type: str) -> str:
    label = MEDIA_INFO.get(media_type)
    if label is None:
        raise MediaCryptoError(f"unknown media type: {media_type!r}")
    return f"WhatsApp {label} Keys"


def derive_media_keys(media_key: bytes, media_type: str) -> MediaKeys:
    if len(media_key) != _MEDIA_KEY_LEN:
        raise MediaCryptoError(f"mediaKey: expected {_MEDIA_KEY_LEN} bytes, got {len(media_key)}")
    expanded = hkdf(media_key, 112, media_info(media_type).encode("utf-8"))
    return MediaKeys(
        iv=expanded[0:16],
        cipher_key=expanded[16:48],
        mac_key=expanded[48:80],
        ref_key=expanded[80:112],
    )


def encrypt_media(media_key: bytes, media_type: str, plaintext: bytes) -> EncryptedMedia:
    keys = derive_media_keys(media_key, media_type)
    ciphertext = aes_cbc_encrypt(keys.cipher_key, keys.iv, plaintext)
    mac = hmac_sha256(keys.mac_key, keys.iv + ciphertext)[:MEDIA_MAC_LEN]
    return EncryptedMedia(
        ciphertext=ciphertext,
        mac=mac,
        file_sha256=sha256(plaintext),
        file_enc_sha256=sha256(ciphertext + mac),
    )


def decrypt_media(media_key: bytes, media_type: str, payload: bytes) -> bytes:
    if len(payload) <= MEDIA_MAC_LEN:
        raise MediaCryptoError("media payload is shorter than the MAC")
    keys = derive_media_keys(media_key, media_type)
    ciphertext = payload[:-MEDIA_MAC_LEN]
    mac = payload[-MEDIA_MAC_LEN:]
    expected = hmac_sha256(keys.mac_key, keys.iv + ciphertext)[:MEDIA_MAC_LEN]
    if not stdlib_hmac.compare_digest(mac, expected):
        raise MediaCryptoError("media MAC mismatch: data is corrupted")
    return aes_cbc_decrypt(keys.cipher_key, keys.iv, ciphertext)
