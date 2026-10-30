from __future__ import annotations

import pytest

from wapy.crypto.primitives import (
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


def test_hkdf_rfc5869_case_1() -> None:
    okm = hkdf(
        bytes.fromhex("0b" * 22),
        42,
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        bytes.fromhex("000102030405060708090a0b0c"),
    )
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_hkdf_rfc5869_case_2_long_inputs() -> None:
    ikm = bytes(range(0x00, 0x50))
    salt = bytes(range(0x60, 0xB0))
    info = bytes(range(0xB0, 0x100))
    okm = hkdf(ikm, 82, info, salt)
    assert okm.hex() == (
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87"
    )


def test_hkdf_rfc5869_case_3_empty_salt_and_info() -> None:
    okm = hkdf(bytes.fromhex("0b" * 22), 42, b"", b"")
    assert okm.hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    )


def test_hkdf_default_salt_is_32_zero_bytes() -> None:
    assert hkdf(b"key", 32, b"info") == hkdf(b"key", 32, b"info", b"\x00" * 32)


def test_hmac_sha256_rfc4231_case_2() -> None:
    mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?")
    assert mac.hex() == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"


def test_sha256() -> None:
    assert sha256(b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_aes_256_cbc_nist_vector_without_padding() -> None:
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    ciphertext = aes_cbc_encrypt(key, iv, plaintext, pad=False)
    assert ciphertext.hex() == "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
    assert aes_cbc_decrypt(key, iv, ciphertext, unpad=False) == plaintext


def test_aes_cbc_roundtrip_with_padding() -> None:
    key = bytes(range(32))
    iv = bytes(range(16))
    for size in (0, 1, 15, 16, 17, 4096):
        plaintext = bytes(size)
        encrypted = aes_cbc_encrypt(key, iv, plaintext)
        assert len(encrypted) % 16 == 0
        assert aes_cbc_decrypt(key, iv, encrypted) == plaintext


def test_aes_cbc_rejects_bad_padding() -> None:
    key = bytes(range(32))
    iv = bytes(range(16))
    ciphertext = aes_cbc_encrypt(key, iv, b"data")
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xFF])
    with pytest.raises(CryptoError):
        aes_cbc_decrypt(key, iv, tampered)


def test_aes_cbc_requires_block_aligned_payload_without_padding() -> None:
    with pytest.raises(CryptoError):
        aes_cbc_decrypt(bytes(32), bytes(16), b"short", unpad=False)


def test_aes_gcm_roundtrip_with_aad() -> None:
    key = bytes(range(32))
    iv = bytes(range(12))
    encrypted = aes_gcm_encrypt(key, iv, b"secret", b"header")
    assert aes_gcm_decrypt(key, iv, encrypted, b"header") == b"secret"


def test_aes_gcm_rejects_wrong_aad() -> None:
    key = bytes(range(32))
    iv = bytes(range(12))
    encrypted = aes_gcm_encrypt(key, iv, b"secret", b"header")
    with pytest.raises(CryptoError):
        aes_gcm_decrypt(key, iv, encrypted, b"other")


def test_aes_gcm_rejects_tampered_ciphertext() -> None:
    key = bytes(range(32))
    iv = bytes(range(12))
    encrypted = bytearray(aes_gcm_encrypt(key, iv, b"secret"))
    encrypted[0] ^= 0xFF
    with pytest.raises(CryptoError):
        aes_gcm_decrypt(key, iv, bytes(encrypted))


def test_x25519_rfc7748_vector() -> None:
    alice_private = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    alice_public = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    bob_private = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    bob_public = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert public_from_private(alice_private) == alice_public
    assert public_from_private(bob_private) == bob_public
    assert dh(alice_private, bob_public).hex() == shared
    assert dh(bob_private, alice_public).hex() == shared


def test_generate_keypair_is_usable_for_dh() -> None:
    alice = generate_keypair()
    bob = generate_keypair()
    assert isinstance(alice, KeyPair)
    assert len(alice.private) == 32
    assert len(alice.public) == 32
    assert dh(alice.private, bob.public) == dh(bob.private, alice.public)


def test_dh_rejects_invalid_public_key() -> None:
    keypair = generate_keypair()
    with pytest.raises(CryptoError):
        dh(keypair.private, b"\x00" * 32)
