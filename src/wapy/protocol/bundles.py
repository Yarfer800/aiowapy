"""Prekey bundles: the key material needed to start a Signal session.

One request covers many devices:

    <iq xmlns="encrypt" type="get" to="@s.whatsapp.net">
      <key><user jid="..."/><user jid="..."/></key>
    </iq>

and the answer names, per device, the registration id, the identity key, the
signed prekey (with its signature) and, when the server still has one, a one-time
prekey. A device whose one-time prekeys ran out is still usable — the session then
starts from the signed prekey alone.
"""

from __future__ import annotations

from dataclasses import dataclass

from wapy.errors import WapyError
from wapy.protocol.stream import child, children
from wapy.protocol.wabinary import Node

S_WHATSAPP_NET = "@s.whatsapp.net"


class BundleError(WapyError):
    """A prekey bundle is malformed or missing required parts."""


@dataclass(frozen=True, slots=True)
class SignedKey:
    key_id: int
    public: bytes
    signature: bytes


@dataclass(frozen=True, slots=True)
class OneTimeKey:
    key_id: int
    public: bytes


@dataclass(frozen=True, slots=True)
class PreKeyBundle:
    jid: str
    registration_id: int
    identity_key: bytes
    signed_pre_key: SignedKey
    pre_key: OneTimeKey | None = None


def build_bundle_query(device_jids: list[str], message_id: str) -> Node:
    if not device_jids:
        raise BundleError("no devices requested")
    return Node(
        tag="iq",
        attrs={"to": S_WHATSAPP_NET, "type": "get", "xmlns": "encrypt", "id": message_id},
        content=[
            Node(
                tag="key",
                attrs={},
                content=[Node(tag="user", attrs={"jid": jid}) for jid in device_jids],
            )
        ],
    )


def _content(node: Node | None, tag: str) -> bytes | None:
    if node is None:
        return None
    found = child(node, tag)
    if found is None or not isinstance(found.content, bytes):
        return None
    return found.content


def _uint(node: Node | None, tag: str, width: int) -> int | None:
    raw = _content(node, tag)
    if raw is None or len(raw) != width:
        return None
    return int.from_bytes(raw, "big")


def _parse_signed_key(node: Node | None) -> SignedKey | None:
    if node is None:
        return None
    key_id = _uint(node, "id", 3)
    public = _content(node, "value")
    signature = _content(node, "signature")
    if key_id is None or public is None or signature is None:
        return None
    return SignedKey(key_id=key_id, public=public, signature=signature)


def _parse_one_time_key(node: Node | None) -> OneTimeKey | None:
    if node is None:
        return None
    key_id = _uint(node, "id", 3)
    public = _content(node, "value")
    if key_id is None or public is None:
        return None
    return OneTimeKey(key_id=key_id, public=public)


def parse_bundles(response: Node) -> list[PreKeyBundle]:
    listing = child(response, "list")
    if listing is None:
        return []
    bundles: list[PreKeyBundle] = []
    for user in children(listing, "user"):
        jid = user.attrs.get("jid")
        if not jid:
            continue
        if child(user, "error") is not None:
            continue  # device is gone or refused; not fatal for the whole send
        registration_id = _uint(user, "registration", 4)
        identity = _content(user, "identity")
        signed = _parse_signed_key(child(user, "skey"))
        if registration_id is None or identity is None or signed is None:
            raise BundleError(f"incomplete bundle for {jid}")
        bundles.append(
            PreKeyBundle(
                jid=jid,
                registration_id=registration_id,
                identity_key=identity,
                signed_pre_key=signed,
                pre_key=_parse_one_time_key(child(user, "key")),
            )
        )
    return bundles
