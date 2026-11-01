"""`usync` device discovery.

WhatsApp keeps a device list per account. The query asks for it; the answer names
each device (id, key index) but not its keys — keys come from a separate bundle
request. Device id 0 is the phone and may legitimately have no key index; every
other device must have one, otherwise the follow-up bundle request is rejected.
"""

from __future__ import annotations

from aiowapy.errors import WapyError
from aiowapy.protocol.stream import child, children
from aiowapy.protocol.wabinary import Node, jid_decode, jid_encode

S_WHATSAPP_NET = "@s.whatsapp.net"
DEVICE_PROTOCOL_VERSION = "2"


class UsyncError(WapyError):
    """The usync response cannot be understood."""


def build_device_query(jids: list[str], message_id: str, *, sid: str, mode: str = "query") -> Node:
    users = [
        Node(
            tag="user",
            attrs={"jid": jid},
            content=[Node(tag="devices", attrs={"version": DEVICE_PROTOCOL_VERSION})],
        )
        for jid in jids
    ]
    return Node(
        tag="iq",
        attrs={"to": S_WHATSAPP_NET, "type": "get", "xmlns": "usync", "id": message_id},
        content=[
            Node(
                tag="usync",
                attrs={
                    "context": "interactive",
                    "mode": mode,
                    "sid": sid,
                    "last": "true",
                    "index": "0",
                },
                content=[
                    Node(
                        tag="query",
                        attrs={},
                        content=[Node(tag="devices", attrs={"version": DEVICE_PROTOCOL_VERSION})],
                    ),
                    Node(tag="list", attrs={}, content=users),
                ],
            )
        ],
    )


def parse_device_jids(response: Node, *, exclude: set[str] | None = None) -> list[str]:
    """Device JIDs from a usync result, minus our own devices."""
    skip = exclude or set()
    usync = child(response, "usync")
    if usync is None:
        raise UsyncError("response carries no usync node")
    listing = child(usync, "list")
    if listing is None:
        return []

    result: list[str] = []
    for user in children(listing, "user"):
        user_jid = user.attrs.get("jid")
        if not user_jid:
            continue
        decoded = jid_decode(user_jid)
        if decoded is None:
            continue
        devices_node = child(user, "devices")
        device_list = child(devices_node, "device-list") if devices_node is not None else None
        if device_list is None:
            continue
        for device in children(device_list, "device"):
            try:
                device_id = int(device.attrs.get("id", "-1"))
            except ValueError:
                continue
            if device_id < 0:
                continue
            key_index = device.attrs.get("key-index")
            if device_id != 0 and not key_index:
                continue  # a non-zero device without a key index breaks the bundle query
            device_jid = jid_encode(decoded.user, decoded.server, device_id or None)
            if device_jid in skip:
                continue
            result.append(device_jid)
    return result
