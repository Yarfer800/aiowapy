from __future__ import annotations

import pytest

from aiowapy.creds import DeviceCredentials, generate_credentials
from aiowapy.crypto.primitives import aes_ctr, dh, hkdf, pbkdf2_sha256
from aiowapy.protocol.pairing_code import (
    ADV_SECRET_INFO,
    CROCKFORD_ALPHABET,
    KEY_BUNDLE_INFO,
    PAIRING_KEY_ITERATIONS,
    CompanionFinishRequest,
    PairingCodeError,
    build_companion_finish,
    build_companion_hello,
    decode_wrapped_bundle,
    derive_pairing_key,
    encode_crockford,
    generate_pairing_code,
    parse_companion_finish,
    unwrap_ephemeral_public,
    validate_pairing_code,
    wrap_ephemeral_public,
)
from aiowapy.protocol.stream import child
from aiowapy.protocol.wabinary import Node, decode_node, encode_node

CODE = "ABCD1234"
SALT = bytes(range(32))
IV = bytes(range(16))


def test_crockford_uses_the_pairing_alphabet() -> None:
    assert CROCKFORD_ALPHABET == "123456789ABCDEFGHJKLMNPQRSTVWXYZ"
    assert set(encode_crockford(b"\x00\x00\x00\x00\x00")) <= set(CROCKFORD_ALPHABET)


def test_pairing_code_is_eight_characters() -> None:
    code = generate_pairing_code(bytes(5))
    assert len(code) == 8
    assert all(char in CROCKFORD_ALPHABET for char in code)
    assert generate_pairing_code(bytes.fromhex("ffffffffff")) == "ZZZZZZZZ"


def test_pairing_code_requires_five_bytes() -> None:
    with pytest.raises(PairingCodeError):
        generate_pairing_code(bytes(4))


def test_validate_rejects_wrong_length_and_alphabet() -> None:
    with pytest.raises(PairingCodeError):
        validate_pairing_code("ABC")
    with pytest.raises(PairingCodeError):
        validate_pairing_code("ABCD123I")  # I is not in the alphabet


def test_pairing_key_is_pbkdf2_with_whatsapp_parameters() -> None:
    derived = derive_pairing_key(CODE, SALT)
    assert derived == pbkdf2_sha256(CODE.encode(), SALT, PAIRING_KEY_ITERATIONS, 32)
    assert len(derived) == 32


def test_wrap_and_unwrap_roundtrip() -> None:
    public = bytes(range(32))
    wrapped = wrap_ephemeral_public(CODE, public, salt=SALT, iv=IV)
    assert len(wrapped) == 32 + 16 + 32
    assert unwrap_ephemeral_public(CODE, wrapped) == public


def test_unwrap_rejects_a_wrong_code() -> None:
    wrapped = wrap_ephemeral_public(CODE, bytes(range(32)), salt=SALT, iv=IV)
    # AES-CTR has no authentication: a wrong code yields garbage, not an error.
    assert unwrap_ephemeral_public("ZZZZZZZZ", wrapped) != bytes(range(32))


def test_unwrap_rejects_wrong_length() -> None:
    with pytest.raises(PairingCodeError):
        unwrap_ephemeral_public(CODE, bytes(10))


def test_companion_hello_structure() -> None:
    credentials = generate_credentials()
    node = build_companion_hello(
        credentials, "79646669102@s.whatsapp.net", CODE, "msg-1", salt=SALT, iv=IV
    )
    assert node.tag == "iq"
    assert node.attrs == {
        "to": "@s.whatsapp.net",
        "type": "set",
        "id": "msg-1",
        "xmlns": "md",
    }
    registration = child(node, "link_code_companion_reg")
    assert registration is not None
    assert registration.attrs["jid"] == "79646669102@s.whatsapp.net"
    assert registration.attrs["stage"] == "companion_hello"
    assert registration.attrs["should_show_push_notification"] == "true"

    wrapped = child(registration, "link_code_pairing_wrapped_companion_ephemeral_pub")
    assert wrapped is not None and isinstance(wrapped.content, bytes)
    assert unwrap_ephemeral_public(CODE, wrapped.content) == (
        credentials.pairing_ephemeral_key.public  # type: ignore[union-attr]
    )
    assert child(registration, "companion_server_auth_key_pub").content == (  # type: ignore[union-attr]
        credentials.noise_public
    )
    assert child(registration, "link_code_pairing_nonce").content == b"0"  # type: ignore[union-attr]


def test_companion_hello_requires_the_pairing_key() -> None:
    credentials = generate_credentials()
    stripped = DeviceCredentials(
        noise_key=credentials.noise_key,
        identity_key=credentials.identity_key,
        signed_pre_key=credentials.signed_pre_key,
        registration_id=credentials.registration_id,
        adv_secret_key=credentials.adv_secret_key,
        pairing_ephemeral_key=None,
    )
    with pytest.raises(PairingCodeError):
        build_companion_hello(stripped, "1@s.whatsapp.net", CODE, "id", salt=SALT, iv=IV)


def test_parse_companion_finish() -> None:
    node = Node(
        tag="iq",
        attrs={"type": "set", "xmlns": "md"},
        content=[
            Node(
                tag="link_code_companion_reg",
                attrs={"stage": "companion_finish"},
                content=[
                    Node(tag="link_code_pairing_ref", attrs={}, content=b"ref"),
                    Node(tag="primary_identity_pub", attrs={}, content=b"\x11" * 32),
                    Node(
                        tag="link_code_pairing_wrapped_primary_ephemeral_pub",
                        attrs={},
                        content=b"\x22" * 80,
                    ),
                ],
            )
        ],
    )
    request = parse_companion_finish(node)
    assert request.ref == b"ref"
    assert request.primary_identity_public == b"\x11" * 32
    assert len(request.wrapped_primary_ephemeral_public) == 80


def test_parse_companion_finish_rejects_other_stages() -> None:
    node = Node(
        tag="iq",
        content=[Node(tag="link_code_companion_reg", attrs={"stage": "companion_hello"})],
    )
    with pytest.raises(PairingCodeError):
        parse_companion_finish(node)


def test_companion_finish_produces_a_decryptable_bundle() -> None:
    credentials = generate_credentials()
    # The server side: its own ephemeral pair and the primary identity key.
    from aiowapy.crypto.primitives import generate_keypair

    server_ephemeral = generate_keypair()
    primary_identity = generate_keypair()

    request = CompanionFinishRequest(
        ref=b"ref-1",
        primary_identity_public=primary_identity.public,
        wrapped_primary_ephemeral_public=wrap_ephemeral_public(
            CODE, server_ephemeral.public, salt=SALT, iv=IV
        ),
    )
    random = bytes(range(32))
    node, adv_secret = build_companion_finish(
        credentials,
        request,
        CODE,
        "79646669102@s.whatsapp.net",
        "msg-2",
        random=random,
        link_code_salt=SALT,
        iv=bytes(12),
    )

    registration = child(node, "link_code_companion_reg")
    assert registration is not None and registration.attrs["stage"] == "companion_finish"
    wrapped = child(registration, "link_code_pairing_wrapped_key_bundle")
    assert wrapped is not None and isinstance(wrapped.content, bytes)

    companion_shared = dh(
        server_ephemeral.private,
        credentials.pairing_ephemeral_key.public,  # type: ignore[union-attr]
    )
    plaintext = decode_wrapped_bundle(wrapped.content, companion_shared=companion_shared)
    assert plaintext == credentials.identity_public + primary_identity.public + random

    identity_shared = dh(primary_identity.private, credentials.identity_public)
    expected_adv = hkdf(companion_shared + identity_shared + random, 32, ADV_SECRET_INFO)
    assert adv_secret == expected_adv


def test_companion_finish_node_encodes() -> None:
    credentials = generate_credentials()
    from aiowapy.crypto.primitives import generate_keypair

    server_ephemeral = generate_keypair()
    primary_identity = generate_keypair()
    request = CompanionFinishRequest(
        ref=b"ref",
        primary_identity_public=primary_identity.public,
        wrapped_primary_ephemeral_public=wrap_ephemeral_public(
            CODE, server_ephemeral.public, salt=SALT, iv=IV
        ),
    )
    node, _ = build_companion_finish(
        credentials,
        request,
        CODE,
        "1@s.whatsapp.net",
        "id",
        random=bytes(32),
        link_code_salt=SALT,
        iv=bytes(12),
    )
    assert decode_node(encode_node(node)) == node


def test_bundle_key_info_string() -> None:
    assert KEY_BUNDLE_INFO == b"link_code_pairing_key_bundle_encryption_key"
    assert aes_ctr(bytes(32), bytes(16), b"x") != b"x"


def test_parse_companion_finish_accepts_a_stageless_notification() -> None:
    node = Node(
        tag="notification",
        attrs={"type": "link_code_companion_reg"},
        content=[
            Node(
                tag="link_code_companion_reg",
                attrs={},
                content=[
                    Node(tag="link_code_pairing_ref", attrs={}, content=b"ref"),
                    Node(tag="primary_identity_pub", attrs={}, content=b"\x11" * 32),
                    Node(
                        tag="link_code_pairing_wrapped_primary_ephemeral_pub",
                        attrs={},
                        content=b"\x22" * 80,
                    ),
                ],
            )
        ],
    )
    request = parse_companion_finish(node)
    assert request.ref == b"ref"
