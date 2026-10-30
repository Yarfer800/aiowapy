from __future__ import annotations

import pytest

from wapy.crypto.media import (
    MEDIA_MAC_LEN,
    MediaCryptoError,
    decrypt_media,
    derive_media_keys,
    encrypt_media,
    media_info,
)

# Вектор сгенерирован эталонной реализацией (@whiskeysockets/baileys@7.0.0-rc14):
# mediaKey = 01..20, type = image, plaintext = "hello media".
REF_MEDIA_KEY = bytes(range(1, 33))
REF_IV = bytes.fromhex("3b9f9f4d37282def2d0991b71465445d")
REF_CIPHER_KEY = bytes.fromhex("b9f77e196a7f6c73c65b21b72f6d6e5374cf4e9f7abafc6979d03712ce54f608")
REF_MAC_KEY = bytes.fromhex("ff4838374597f9a73b627dc218c459b8615dc6bdce9153804a532593d00a1af1")
REF_REF_KEY = bytes.fromhex("2cb9c176c5aee4c1680af853f439e408a42a467122d83f37d0dabd1284a809e9")
REF_CIPHERTEXT = bytes.fromhex("c6e696a58f2432a2cdc48420076c9f26")
REF_MAC = bytes.fromhex("e002a4417bce3e4eb612")
REF_FILE_ENC_SHA256 = bytes.fromhex(
    "887c9d8dfd8db3feeca886a4af633c70dc0f21a3f000962b9e1dfba78b8e2eed"
)


def test_info_strings_match_reference() -> None:
    assert media_info("image") == "WhatsApp Image Keys"
    assert media_info("video") == "WhatsApp Video Keys"
    assert media_info("audio") == "WhatsApp Audio Keys"
    assert media_info("document") == "WhatsApp Document Keys"
    assert media_info("gif") == "WhatsApp Video Keys"
    assert media_info("ptt") == "WhatsApp Audio Keys"
    assert media_info("sticker") == "WhatsApp Image Keys"


def test_unknown_media_type_raises() -> None:
    with pytest.raises(MediaCryptoError):
        media_info("unknown")


def test_derive_media_keys_matches_reference() -> None:
    keys = derive_media_keys(REF_MEDIA_KEY, "image")
    assert keys.iv == REF_IV
    assert keys.cipher_key == REF_CIPHER_KEY
    assert keys.mac_key == REF_MAC_KEY
    assert keys.ref_key == REF_REF_KEY


def test_encrypt_media_matches_reference_bytes() -> None:
    encrypted = encrypt_media(REF_MEDIA_KEY, "image", b"hello media")
    assert encrypted.ciphertext == REF_CIPHERTEXT
    assert encrypted.mac == REF_MAC
    assert encrypted.payload == REF_CIPHERTEXT + REF_MAC
    assert encrypted.file_enc_sha256 == REF_FILE_ENC_SHA256
    assert len(encrypted.mac) == MEDIA_MAC_LEN


def test_encrypt_media_reports_plaintext_hash() -> None:
    encrypted = encrypt_media(REF_MEDIA_KEY, "image", b"hello media")
    assert encrypted.file_sha256.hex() == (
        "d28d2954ff97ac68052c4beff8c84ad0960d1408540fc486256cdd7cd68dd1fe"
    )


def test_media_roundtrip() -> None:
    for media_type in ("image", "video", "audio", "document"):
        for payload in (b"", b"x", bytes(15), bytes(16), bytes(17), bytes(5000)):
            encrypted = encrypt_media(REF_MEDIA_KEY, media_type, payload)
            assert decrypt_media(REF_MEDIA_KEY, media_type, encrypted.payload) == payload


def test_decrypt_rejects_tampered_mac() -> None:
    encrypted = encrypt_media(REF_MEDIA_KEY, "image", b"hello media")
    tampered = bytearray(encrypted.payload)
    tampered[-1] ^= 0xFF
    with pytest.raises(MediaCryptoError):
        decrypt_media(REF_MEDIA_KEY, "image", bytes(tampered))


def test_decrypt_rejects_tampered_ciphertext() -> None:
    encrypted = encrypt_media(REF_MEDIA_KEY, "image", b"hello media")
    tampered = bytearray(encrypted.payload)
    tampered[0] ^= 0xFF
    with pytest.raises(MediaCryptoError):
        decrypt_media(REF_MEDIA_KEY, "image", bytes(tampered))


def test_decrypt_rejects_short_payload() -> None:
    with pytest.raises(MediaCryptoError):
        decrypt_media(REF_MEDIA_KEY, "image", bytes(MEDIA_MAC_LEN))


def test_decrypt_rejects_wrong_media_type() -> None:
    encrypted = encrypt_media(REF_MEDIA_KEY, "image", b"hello media")
    with pytest.raises(MediaCryptoError):
        decrypt_media(REF_MEDIA_KEY, "video", encrypted.payload)


def test_encrypt_rejects_wrong_media_key_length() -> None:
    with pytest.raises(MediaCryptoError):
        encrypt_media(b"short", "image", b"data")
