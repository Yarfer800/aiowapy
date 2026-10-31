"""Receipts: acknowledgement, delivery, read and retry requests.

A receipt is a `<receipt>` node addressed back to the sender of a message:

    <receipt id="<message id>" to="<sender>" type="delivery"/>

`type="retry"` means "I could not decrypt this, please resend with a fresh
prekey". After the first attempt the receiver also includes its identity and a
one-time prekey, because the sender's session with us is clearly broken.
"""

from __future__ import annotations

from wapy.creds import SIGNAL_KEY_PREFIX, DeviceCredentials
from wapy.errors import WapyError
from wapy.protocol.prekeys import prekey_node, signed_prekey_node
from wapy.protocol.wabinary import Node

RECEIPT_DELIVERY = "delivery"
RECEIPT_READ = "read"
RECEIPT_RETRY = "retry"
MAX_RETRY_COUNT = 5


class ReceiptError(WapyError):
    """A receipt cannot be built from the given node."""


def base_receipt_attrs(node: Node) -> dict[str, str]:
    """`id` and `to` copied from the incoming message, plus group routing fields."""
    message_id = node.attrs.get("id")
    sender = node.attrs.get("from")
    if not message_id or not sender:
        raise ReceiptError("message node is missing id or from")
    attrs = {"id": message_id, "to": sender}
    for key in ("recipient", "participant"):
        value = node.attrs.get(key)
        if value:
            attrs[key] = value
    return attrs


def build_receipt(node: Node, *, receipt_type: str = RECEIPT_DELIVERY) -> Node:
    if receipt_type not in (RECEIPT_DELIVERY, RECEIPT_READ):
        raise ReceiptError(f"unsupported receipt type: {receipt_type!r}")
    attrs = base_receipt_attrs(node)
    attrs["type"] = receipt_type
    return Node(tag="receipt", attrs=attrs)


def build_retry_receipt(
    node: Node,
    credentials: DeviceCredentials,
    *,
    count: int = 1,
    one_time_prekey: tuple[int, bytes] | None = None,
) -> Node:
    """Ask the sender to resend.

    `count` is 1 for the first request; from the second one the payload must also
    carry our identity key and a one-time prekey, otherwise the sender keeps
    failing with the same broken session.
    """
    if count < 1:
        raise ReceiptError("retry count starts at 1")
    if count > MAX_RETRY_COUNT:
        raise ReceiptError(f"giving up after {MAX_RETRY_COUNT} retries")

    attrs = base_receipt_attrs(node)
    attrs["type"] = RECEIPT_RETRY
    content = [
        Node(
            tag="retry",
            attrs={
                "count": str(count),
                "id": node.attrs.get("id", ""),
                "t": node.attrs.get("t", ""),
                "v": "1",
            },
        ),
        Node(
            tag="registration",
            attrs={},
            content=credentials.registration_id.to_bytes(4, "big"),
        ),
    ]

    if count > 1:
        if one_time_prekey is None:
            raise ReceiptError("a retry after the first one must carry a one-time prekey")
        key_id, public = one_time_prekey
        content.append(
            Node(
                tag="keys",
                attrs={},
                content=[
                    Node(tag="type", attrs={}, content=SIGNAL_KEY_PREFIX),
                    Node(tag="identity", attrs={}, content=credentials.identity_public),
                    prekey_node(key_id, public),
                    signed_prekey_node(credentials.signed_pre_key),
                ],
            )
        )
    return Node(tag="receipt", attrs=attrs, content=content)
