from __future__ import annotations

import base64
from dataclasses import replace

import pytest

from wapy.creds import DeviceCredentials, SignedPreKey
from wapy.crypto.primitives import KeyPair, generate_keypair, hmac_sha256
from wapy.crypto.xeddsa import sign, verify
from wapy.pb import bytes_field, varint_field
from wapy.protocol.pairing import (
    ACCOUNT_SIG_PREFIX,
    DEVICE_SIG_PREFIX,
    PairingError,
    build_pair_device_sign_reply,
    encode_signed_device_identity,
    parse_pair_success,
    verify_pair_success,
)
from wapy.protocol.wabinary import Node, decode_node, encode_node


def make_credentials(account_key: KeyPair) -> DeviceCredentials:
    return DeviceCredentials(
        noise_key=generate_keypair(),
        identity_key=generate_keypair(),
        signed_pre_key=SignedPreKey(1, generate_keypair(), b"\x00" * 64),
        registration_id=42,
        adv_secret_key=base64.b64encode(b"\x07" * 32).decode(),
    )


def device_identity_details(key_index: int = 0, device_type: int = 0) -> bytes:
    return (
        varint_field(1, 12345)
        + varint_field(2, 1_700_000_000)
        + varint_field(3, key_index)
        + varint_field(5, device_type)
    )


def build_pair_success_node(credentials: DeviceCredentials, account_key: KeyPair) -> Node:
    details = device_identity_details()
    account_signature = sign(
        account_key.private,
        ACCOUNT_SIG_PREFIX + details + credentials.identity_public,
    )
    signed_identity = (
        bytes_field(1, details)
        + bytes_field(2, account_key.public)
        + bytes_field(3, account_signature)
    )
    secret = base64.b64decode(credentials.adv_secret_key)
    hmac_value = hmac_sha256(secret, signed_identity)
    identity_payload = bytes_field(1, signed_identity) + bytes_field(2, hmac_value)
    return Node(
        tag="iq",
        attrs={"id": "pair-1", "type": "set"},
        content=[
            Node(
                tag="pair-success",
                attrs={},
                content=[
                    Node(tag="device-identity", attrs={}, content=identity_payload),
                    Node(
                        tag="device",
                        attrs={"jid": "491234567890:3@s.whatsapp.net", "lid": "12:3@lid"},
                    ),
                    Node(tag="platform", attrs={"name": "android"}),
                    Node(tag="biz", attrs={"name": "Acme"}),
                ],
            )
        ],
    )


def test_parse_pair_success_extracts_fields() -> None:
    account_key = generate_keypair()
    credentials = make_credentials(account_key)
    pair = parse_pair_success(
        build_pair_success_node(credentials, account_key), message_id="pair-1"
    )
    assert pair.jid == "491234567890:3@s.whatsapp.net"
    assert pair.lid == "12:3@lid"
    assert pair.platform == "android"
    assert pair.business_name == "Acme"
    assert pair.hmac


def test_parse_rejects_id_mismatch() -> None:
    account_key = generate_keypair()
    credentials = make_credentials(account_key)
    node = build_pair_success_node(credentials, account_key)
    with pytest.raises(PairingError):
        parse_pair_success(node, message_id="other")


def test_verify_produces_a_valid_device_signature() -> None:
    account_key = generate_keypair()
    credentials = make_credentials(account_key)
    pair = parse_pair_success(
        build_pair_success_node(credentials, account_key), message_id="pair-1"
    )
    identity = verify_pair_success(pair, credentials)

    device_message = (
        DEVICE_SIG_PREFIX + identity.details + credentials.identity_public + account_key.public
    )
    assert verify(credentials.identity_public, device_message, identity.device_signature)


def test_tampered_hmac_is_rejected() -> None:
    account_key = generate_keypair()
    credentials = make_credentials(account_key)
    node = build_pair_success_node(credentials, account_key)
    pair = parse_pair_success(node, message_id="pair-1")
    tampered = replace(pair, hmac=bytes(32))
    with pytest.raises(PairingError):
        verify_pair_success(tampered, credentials)


def test_wrong_adv_secret_is_rejected() -> None:
    account_key = generate_keypair()
    credentials = make_credentials(account_key)
    node = build_pair_success_node(credentials, account_key)
    pair = parse_pair_success(node, message_id="pair-1")
    other = DeviceCredentials(
        noise_key=credentials.noise_key,
        identity_key=credentials.identity_key,
        signed_pre_key=credentials.signed_pre_key,
        registration_id=credentials.registration_id,
        adv_secret_key=base64.b64encode(b"\x08" * 32).decode(),
    )
    with pytest.raises(PairingError):
        verify_pair_success(pair, other)


def test_tampered_account_signature_is_rejected() -> None:
    account_key = generate_keypair()
    credentials = make_credentials(account_key)
    details = device_identity_details()
    forged = (
        bytes_field(1, details)
        + bytes_field(2, account_key.public)
        + bytes_field(3, sign(generate_keypair().private, ACCOUNT_SIG_PREFIX + details))
    )
    secret = base64.b64decode(credentials.adv_secret_key)
    payload = bytes_field(1, forged) + bytes_field(2, hmac_sha256(secret, forged))
    node = Node(
        tag="iq",
        attrs={"id": "pair-1"},
        content=[
            Node(
                tag="pair-success",
                attrs={},
                content=[
                    Node(tag="device-identity", attrs={}, content=payload),
                    Node(tag="device", attrs={"jid": "1@s.whatsapp.net"}),
                ],
            )
        ],
    )
    pair = parse_pair_success(node, message_id="pair-1")
    with pytest.raises(PairingError):
        verify_pair_success(pair, credentials)


def test_reply_node_structure() -> None:
    account_key = generate_keypair()
    credentials = make_credentials(account_key)
    pair = parse_pair_success(
        build_pair_success_node(credentials, account_key), message_id="pair-1"
    )
    identity = verify_pair_success(pair, credentials)
    reply = build_pair_device_sign_reply("pair-1", identity, key_index=3)

    assert reply.tag == "iq"
    assert reply.attrs == {"to": "s.whatsapp.net", "type": "result", "id": "pair-1"}
    assert isinstance(reply.content, list)
    sign_node = reply.content[0]
    assert sign_node.tag == "pair-device-sign"
    identity_node = sign_node.content[0]  # type: ignore[index]
    assert identity_node.tag == "device-identity"
    assert identity_node.attrs["key-index"] == "3"

    encoded = encode_signed_device_identity(identity)
    assert encoded == identity_node.content
    # decoded payload carries details, account signature and device signature
    decoded = decode_node(encode_node(reply))
    assert decoded.attrs["type"] == "result"


def test_encoded_identity_omits_the_account_key() -> None:
    account_key = generate_keypair()
    credentials = make_credentials(account_key)
    pair = parse_pair_success(
        build_pair_success_node(credentials, account_key), message_id="pair-1"
    )
    identity = verify_pair_success(pair, credentials)
    encoded = encode_signed_device_identity(identity)
    assert account_key.public not in encoded
