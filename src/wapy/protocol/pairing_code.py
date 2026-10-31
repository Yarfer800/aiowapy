"""Linking a device with an 8-character code instead of a QR.

The flow, mirroring the reference client:

1. the companion picks a code from five random bytes, encodes it in Crockford
   base32 and shows it to the user, who types it on the phone;
2. the code is stretched with PBKDF2 and used to wrap our pairing ephemeral
   public key, which goes to the server in `companion_hello`;
3. the server answers with the primary device's identity key and its ephemeral
   key, itself wrapped under the same code;
4. the companion unwraps it, derives the advanced secret and sends
   `companion_finish` with the key bundle encrypted under the resulting shared
   key.

Everything here is testable with injected randomness, which is why the functions
take explicit `random`, `salt` and `iv` arguments instead of generating them.
"""

from __future__ import annotations

from dataclasses import dataclass

from wapy.creds import DeviceCredentials
from wapy.crypto.primitives import (
    aes_ctr,
    aes_gcm_encrypt,
    dh,
    hkdf,
    pbkdf2_sha256,
)
from wapy.errors import WapyError
from wapy.protocol.stream import child
from wapy.protocol.wabinary import Node

S_WHATSAPP_NET = "@s.whatsapp.net"
CROCKFORD_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTVWXYZ"
PAIRING_CODE_LEN = 8
PAIRING_KEY_ITERATIONS = 2 << 16
KEY_BUNDLE_INFO = b"link_code_pairing_key_bundle_encryption_key"
ADV_SECRET_INFO = b"adv_secret"


class PairingCodeError(WapyError):
    """The pairing code exchange cannot proceed."""


def encode_crockford(data: bytes) -> str:
    """Base32 with Crockford's alphabet, as used for the pairing code."""
    value = 0
    bits = 0
    out: list[str] = []
    for byte in data:
        value = (value << 8) | (byte & 0xFF)
        bits += 8
        while bits >= 5:
            out.append(CROCKFORD_ALPHABET[(value >> (bits - 5)) & 31])
            bits -= 5
    if bits > 0:
        out.append(CROCKFORD_ALPHABET[(value << (5 - bits)) & 31])
    return "".join(out)


def generate_pairing_code(random_bytes: bytes | None = None) -> str:
    """Eight characters, the length WhatsApp's UI expects."""
    import secrets

    raw = random_bytes if random_bytes is not None else secrets.token_bytes(5)
    if len(raw) != 5:
        raise PairingCodeError(f"the code is derived from 5 bytes, got {len(raw)}")
    return encode_crockford(raw)[:PAIRING_CODE_LEN]


def validate_pairing_code(code: str) -> str:
    if len(code) != PAIRING_CODE_LEN:
        raise PairingCodeError(f"a pairing code is {PAIRING_CODE_LEN} characters")
    if any(char not in CROCKFORD_ALPHABET for char in code):
        raise PairingCodeError("pairing code contains characters outside the alphabet")
    return code


def derive_pairing_key(code: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 with WhatsApp's iteration count."""
    return pbkdf2_sha256(
        validate_pairing_code(code).encode("utf-8"), salt, PAIRING_KEY_ITERATIONS, 32
    )


def wrap_ephemeral_public(code: str, ephemeral_public: bytes, *, salt: bytes, iv: bytes) -> bytes:
    """salt ‖ iv ‖ AES-CTR(public key), the `wrapped_companion_ephemeral_pub` value."""
    if len(ephemeral_public) != 32:
        raise PairingCodeError("ephemeral public key must be 32 bytes")
    return salt + iv + aes_ctr(derive_pairing_key(code, salt), iv, ephemeral_public)


def unwrap_ephemeral_public(code: str, wrapped: bytes) -> bytes:
    if len(wrapped) != 32 + 16 + 32:
        raise PairingCodeError(f"unexpected wrapped key length: {len(wrapped)}")
    salt, iv, payload = wrapped[:32], wrapped[32:48], wrapped[48:]
    return aes_ctr(derive_pairing_key(code, salt), iv, payload)


def build_companion_hello(
    credentials: DeviceCredentials,
    phone_jid: str,
    code: str,
    message_id: str,
    *,
    salt: bytes,
    iv: bytes,
    platform_id: str = "1",
    platform_display: str = "Chrome (Mac OS)",
) -> Node:
    pairing_key = credentials.pairing_ephemeral_key
    if pairing_key is None:
        raise PairingCodeError("credentials carry no pairing ephemeral key")
    wrapped = wrap_ephemeral_public(code, pairing_key.public, salt=salt, iv=iv)
    return Node(
        tag="iq",
        attrs={"to": S_WHATSAPP_NET, "type": "set", "id": message_id, "xmlns": "md"},
        content=[
            Node(
                tag="link_code_companion_reg",
                attrs={
                    "jid": phone_jid,
                    "stage": "companion_hello",
                    "should_show_push_notification": "true",
                },
                content=[
                    Node(
                        tag="link_code_pairing_wrapped_companion_ephemeral_pub",
                        attrs={},
                        content=wrapped,
                    ),
                    Node(
                        tag="companion_server_auth_key_pub",
                        attrs={},
                        content=credentials.noise_public,
                    ),
                    Node(tag="companion_platform_id", attrs={}, content=platform_id.encode()),
                    Node(
                        tag="companion_platform_display",
                        attrs={},
                        content=platform_display.encode(),
                    ),
                    Node(tag="link_code_pairing_nonce", attrs={}, content=b"0"),
                ],
            )
        ],
    )


@dataclass(frozen=True, slots=True)
class CompanionFinishRequest:
    ref: bytes
    primary_identity_public: bytes
    wrapped_primary_ephemeral_public: bytes


def parse_companion_finish(node: Node) -> CompanionFinishRequest:
    """Read the server's `link_code_companion_reg` push."""
    registration = child(node, "link_code_companion_reg")
    if registration is None:
        raise PairingCodeError("node carries no link_code_companion_reg")
    # The server pushes this as a `notification` with no stage attribute, so the
    # presence of the pairing fields is the only reliable signal.
    stage = registration.attrs.get("stage")
    if stage is not None and stage != "companion_finish":
        raise PairingCodeError(f"unexpected stage: {stage!r}")

    def payload(tag: str) -> bytes:
        found = child(registration, tag)
        if found is None or not isinstance(found.content, bytes):
            raise PairingCodeError(f"missing {tag}")
        return found.content

    return CompanionFinishRequest(
        ref=payload("link_code_pairing_ref"),
        primary_identity_public=payload("primary_identity_pub"),
        wrapped_primary_ephemeral_public=payload("link_code_pairing_wrapped_primary_ephemeral_pub"),
    )


def build_companion_finish(
    credentials: DeviceCredentials,
    request: CompanionFinishRequest,
    code: str,
    phone_jid: str,
    message_id: str,
    *,
    random: bytes,
    link_code_salt: bytes,
    iv: bytes,
) -> tuple[Node, bytes]:
    """Return the `companion_finish` node and the advanced secret derived from it."""
    pairing_key = credentials.pairing_ephemeral_key
    if pairing_key is None:
        raise PairingCodeError("credentials carry no pairing ephemeral key")
    if len(random) != 32:
        raise PairingCodeError("the random block must be 32 bytes")

    primary_ephemeral = unwrap_ephemeral_public(code, request.wrapped_primary_ephemeral_public)
    companion_shared = dh(pairing_key.private, primary_ephemeral)

    bundle_key = hkdf(companion_shared, 32, KEY_BUNDLE_INFO, link_code_salt)
    payload = credentials.identity_public + request.primary_identity_public + random
    encrypted = link_code_salt + iv + aes_gcm_encrypt(bundle_key, iv, payload, b"")

    identity_shared = dh(credentials.identity_key.private, request.primary_identity_public)
    adv_secret = hkdf(companion_shared + identity_shared + random, 32, ADV_SECRET_INFO)

    node = Node(
        tag="iq",
        attrs={"to": S_WHATSAPP_NET, "type": "set", "id": message_id, "xmlns": "md"},
        content=[
            Node(
                tag="link_code_companion_reg",
                attrs={"jid": phone_jid, "stage": "companion_finish"},
                content=[
                    Node(
                        tag="link_code_pairing_wrapped_key_bundle",
                        attrs={},
                        content=encrypted,
                    ),
                    Node(
                        tag="companion_identity_public",
                        attrs={},
                        content=credentials.identity_public,
                    ),
                    Node(tag="link_code_pairing_ref", attrs={}, content=request.ref),
                ],
            )
        ],
    )
    return node, adv_secret


def decode_wrapped_bundle(
    wrapped: bytes, *, companion_shared: bytes, info: bytes = KEY_BUNDLE_INFO
) -> bytes:
    """Server-side view of the bundle, used by tests and by the reference check."""
    if len(wrapped) < 32 + 12 + 16:
        raise PairingCodeError("wrapped bundle is too short")
    salt, iv, payload = wrapped[:32], wrapped[32:44], wrapped[44:]
    key = hkdf(companion_shared, 32, info, salt)
    from wapy.crypto.primitives import aes_gcm_decrypt

    return aes_gcm_decrypt(key, iv, payload, b"")
