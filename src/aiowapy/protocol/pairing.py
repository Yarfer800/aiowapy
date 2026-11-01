"""Completing companion pairing: verify the server's account signature, sign the
device identity, and build the reply that finalises linking.

The flow, mirroring the reference client:

1. the server sends `pair-success` with `device-identity` (details + HMAC),
   `device` (jid/lid) and `platform`;
2. we check `HMAC(prefix || details, adv_secret)` — this binds the response to the
   pairing attempt whose QR we displayed;
3. we verify the account's signature over `details || our identity key`;
4. we sign `details || our identity key || account key` with our identity key and
   send it back in `pair-device-sign`.
"""

from __future__ import annotations

import hmac as stdlib_hmac
from dataclasses import dataclass

from aiowapy.creds import DeviceCredentials
from aiowapy.crypto.primitives import hmac_sha256
from aiowapy.crypto.xeddsa import sign, verify
from aiowapy.errors import WapyError
from aiowapy.pb import bytes_field, first_bytes, first_int, parse_fields
from aiowapy.protocol.stream import child
from aiowapy.protocol.wabinary import Node

S_WHATSAPP_NET = "@s.whatsapp.net"

ACCOUNT_SIG_PREFIX = bytes([6, 0])
DEVICE_SIG_PREFIX = bytes([6, 1])
HOSTED_ACCOUNT_SIG_PREFIX = bytes([6, 5])
HOSTED_DEVICE_SIG_PREFIX = bytes([6, 6])

ADV_E2EE = 0
ADV_HOSTED = 1


class PairingError(WapyError):
    """Pairing data does not verify."""


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    raw_id: int
    timestamp: int
    key_index: int
    device_type: int


@dataclass(frozen=True, slots=True)
class SignedDeviceIdentity:
    details: bytes
    account_signature_key: bytes
    account_signature: bytes
    device_signature: bytes = b""


@dataclass(frozen=True, slots=True)
class PairSuccess:
    jid: str
    lid: str | None
    platform: str | None
    business_name: str | None
    details: bytes
    hmac: bytes
    account_type: int


def parse_pair_success(node: Node, *, message_id: str) -> PairSuccess:
    if node.tag != "iq":
        raise PairingError(f"expected an iq node, got {node.tag!r}")
    if node.attrs.get("id") != message_id:
        raise PairingError("pair-success id does not match the request")
    pair_success = child(node, "pair-success")
    if pair_success is None:
        raise PairingError("pair-success node is missing")
    identity_node = child(pair_success, "device-identity")
    device_node = child(pair_success, "device")
    if identity_node is None or device_node is None:
        raise PairingError("pair-success is missing device-identity or device")

    payload = identity_node.content
    if not isinstance(payload, bytes):
        raise PairingError("device-identity content must be bytes")
    fields = parse_fields(payload)
    platform_node = child(pair_success, "platform")
    business_node = child(pair_success, "biz")
    return PairSuccess(
        jid=device_node.attrs.get("jid", ""),
        lid=device_node.attrs.get("lid"),
        platform=platform_node.attrs.get("name") if platform_node else None,
        business_name=business_node.attrs.get("name") if business_node else None,
        details=first_bytes(fields, 1),
        hmac=first_bytes(fields, 2),
        account_type=first_int(fields, 3),
    )


def _account_sig_prefix(device_type: int) -> bytes:
    return HOSTED_ACCOUNT_SIG_PREFIX if device_type == ADV_HOSTED else ACCOUNT_SIG_PREFIX


def parse_signed_device_identity(details: bytes) -> SignedDeviceIdentity:
    fields = parse_fields(details)
    return SignedDeviceIdentity(
        details=first_bytes(fields, 1),
        account_signature_key=first_bytes(fields, 2),
        account_signature=first_bytes(fields, 3),
    )


def parse_device_identity(details: bytes) -> DeviceIdentity:
    fields = parse_fields(details)
    return DeviceIdentity(
        raw_id=first_int(fields, 1),
        timestamp=first_int(fields, 2),
        key_index=first_int(fields, 3),
        device_type=first_int(fields, 5) or first_int(fields, 4),
    )


def verify_pair_success(
    pair: PairSuccess, credentials: DeviceCredentials
) -> tuple[SignedDeviceIdentity, int]:
    """Check the HMAC and account signature, then sign the device identity."""
    prefix = HOSTED_ACCOUNT_SIG_PREFIX if pair.account_type == ADV_HOSTED else b""
    expected = hmac_sha256(_adv_secret_bytes(credentials), prefix + pair.details)
    if not stdlib_hmac.compare_digest(expected, pair.hmac):
        raise PairingError("pair-success HMAC does not match the advanced secret")

    account = parse_signed_device_identity(pair.details)
    device_identity = parse_device_identity(account.details)
    # The signed message uses the raw 32-byte identity key, not the 0x05-prefixed
    # wire form: the reference client only prefixes keys for signed prekes.
    signed_message = (
        _account_sig_prefix(device_identity.device_type)
        + account.details
        + credentials.identity_public
    )
    if not verify(account.account_signature_key, signed_message, account.account_signature):
        raise PairingError("account signature over the device identity is invalid")

    device_prefix = (
        HOSTED_DEVICE_SIG_PREFIX if device_identity.device_type == ADV_HOSTED else DEVICE_SIG_PREFIX
    )
    device_message = (
        device_prefix
        + account.details
        + credentials.identity_public
        + account.account_signature_key
    )
    device_signature = sign(credentials.identity_key.private, device_message)
    return (
        SignedDeviceIdentity(
            details=account.details,
            account_signature_key=account.account_signature_key,
            account_signature=account.account_signature,
            device_signature=device_signature,
        ),
        device_identity.key_index,
    )


def encode_signed_device_identity(identity: SignedDeviceIdentity) -> bytes:
    """Encode without the account signature key, as the reply requires."""
    return b"".join(
        (
            bytes_field(1, identity.details),
            bytes_field(3, identity.account_signature),
            bytes_field(4, identity.device_signature),
        )
    )


def encode_account_identity(identity: SignedDeviceIdentity) -> bytes:
    """Full `ADVSignedDeviceIdentity`, as sent inside every prekey message."""
    return b"".join(
        (
            bytes_field(1, identity.details),
            bytes_field(2, identity.account_signature_key),
            bytes_field(3, identity.account_signature),
            bytes_field(4, identity.device_signature),
        )
    )


def build_pair_device_sign_reply(
    message_id: str, identity: SignedDeviceIdentity, key_index: int
) -> Node:
    return Node(
        tag="iq",
        attrs={"to": S_WHATSAPP_NET, "type": "result", "id": message_id},
        content=[
            Node(
                tag="pair-device-sign",
                attrs={},
                content=[
                    Node(
                        tag="device-identity",
                        attrs={"key-index": str(key_index)},
                        content=encode_signed_device_identity(identity),
                    )
                ],
            )
        ],
    )


def _adv_secret_bytes(credentials: DeviceCredentials) -> bytes:
    import base64

    try:
        return base64.b64decode(credentials.adv_secret_key, validate=True)
    except Exception as exc:  # pragma: no cover - credentials are validated on load
        raise PairingError("advanced secret is not valid base64") from exc
