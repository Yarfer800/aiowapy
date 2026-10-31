"""Prekey publication: the key material other devices use to start a session.

WhatsApp keeps a pool of one-time prekeys per device. Without them, an incoming
message from a stranger cannot be decrypted, so the pool is uploaded right after
the connection is established and topped up when it runs low.

Wire format, mirroring the reference client:

    <iq xmlns="encrypt" type="set" to="s.whatsapp.net" id="...">
      <registration>{4-byte big-endian registration id}</registration>
      <type>{0x05}</type>
      <identity>{32-byte identity public key}</identity>
      <list>
        <key><id>{3-byte id}</id><value>{32-byte public}</value></key>
        ...
      </list>
      <skey>
        <id>{3-byte id}</id><value>{32-byte public}</value><signature>{64-byte}</signature>
      </skey>
    </iq>
"""

from __future__ import annotations

from collections.abc import Sequence

from wapy.creds import SIGNAL_KEY_PREFIX, DeviceCredentials, SignedPreKey
from wapy.errors import WapyError
from wapy.protocol.stream import child
from wapy.protocol.wabinary import Node

S_WHATSAPP_NET = "s.whatsapp.net"
INITIAL_PREKEY_COUNT = 812
MIN_PREKEY_COUNT = 5


class PreKeyError(WapyError):
    """Prekey material or a server response is inconsistent."""


def _big_endian(value: int, width: int) -> bytes:
    if not 0 <= value < 1 << (8 * width):
        raise PreKeyError(f"value {value} does not fit in {width} bytes")
    return value.to_bytes(width, "big")


def prekey_node(key_id: int, public: bytes) -> Node:
    if len(public) != 32:
        raise PreKeyError(f"prekey public must be 32 bytes, got {len(public)}")
    return Node(
        tag="key",
        attrs={},
        content=[
            Node(tag="id", attrs={}, content=_big_endian(key_id, 3)),
            Node(tag="value", attrs={}, content=public),
        ],
    )


def signed_prekey_node(signed: SignedPreKey) -> Node:
    return Node(
        tag="skey",
        attrs={},
        content=[
            Node(tag="id", attrs={}, content=_big_endian(signed.key_id, 3)),
            Node(tag="value", attrs={}, content=signed.key_pair.public),
            Node(tag="signature", attrs={}, content=signed.signature),
        ],
    )


def build_upload_node(
    credentials: DeviceCredentials,
    prekeys: Sequence[tuple[int, bytes]],
    message_id: str,
) -> Node:
    if not prekeys:
        raise PreKeyError("nothing to upload")
    return Node(
        tag="iq",
        attrs={"xmlns": "encrypt", "type": "set", "to": S_WHATSAPP_NET, "id": message_id},
        content=[
            Node(
                tag="registration",
                attrs={},
                content=_big_endian(credentials.registration_id, 4),
            ),
            Node(tag="type", attrs={}, content=SIGNAL_KEY_PREFIX),
            Node(tag="identity", attrs={}, content=credentials.identity_public),
            Node(
                tag="list",
                attrs={},
                content=[prekey_node(key_id, public) for key_id, public in prekeys],
            ),
            signed_prekey_node(credentials.signed_pre_key),
        ],
    )


def build_count_query(message_id: str) -> Node:
    return Node(
        tag="iq",
        attrs={"xmlns": "encrypt", "type": "get", "to": S_WHATSAPP_NET, "id": message_id},
        content=[Node(tag="count", attrs={})],
    )


def parse_count(node: Node) -> int:
    count = child(node, "count")
    if count is None or not isinstance(count.content, bytes):
        raise PreKeyError("response does not carry a count")
    try:
        return int(count.content.decode())
    except (UnicodeDecodeError, ValueError) as exc:
        raise PreKeyError("count is not a number") from exc


def pack_key_pair(private: bytes, public: bytes) -> bytes:
    """Store format: private followed by public, both 32 bytes."""
    if len(private) != 32 or len(public) != 32:
        raise PreKeyError("key pair halves must be 32 bytes each")
    return private + public


def unpack_public(blob: bytes) -> bytes:
    if len(blob) != 64:
        raise PreKeyError(f"stored key pair must be 64 bytes, got {len(blob)}")
    return blob[32:]


def prekeys_to_upload(
    pending: Sequence[tuple[int, bytes]], *, limit: int = INITIAL_PREKEY_COUNT
) -> list[tuple[int, bytes]]:
    """The wire carries public halves only; the record itself stays in the store."""
    return [(key_id, public) for key_id, public in pending][:limit]
