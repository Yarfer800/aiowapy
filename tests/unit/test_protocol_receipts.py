from __future__ import annotations

import pytest

from wapy.creds import generate_credentials
from wapy.protocol.receipts import (
    MAX_RETRY_COUNT,
    RECEIPT_DELIVERY,
    RECEIPT_READ,
    RECEIPT_RETRY,
    ReceiptError,
    base_receipt_attrs,
    build_receipt,
    build_retry_receipt,
)
from wapy.protocol.stream import child
from wapy.protocol.wabinary import Node, decode_node, encode_node

INCOMING = Node(
    tag="message",
    attrs={"id": "ABC", "from": "491234567890@s.whatsapp.net", "t": "1793474837"},
)


def test_base_attrs_copy_id_and_sender() -> None:
    assert base_receipt_attrs(INCOMING) == {"id": "ABC", "to": "491234567890@s.whatsapp.net"}


def test_base_attrs_carry_group_routing() -> None:
    node = Node(
        tag="message",
        attrs={"id": "1", "from": "group@g.us", "participant": "member@s.whatsapp.net"},
    )
    attrs = base_receipt_attrs(node)
    assert attrs["participant"] == "member@s.whatsapp.net"


def test_base_attrs_require_id_and_sender() -> None:
    with pytest.raises(ReceiptError):
        base_receipt_attrs(Node(tag="message", attrs={"id": "1"}))


def test_delivery_and_read_receipts() -> None:
    delivery = build_receipt(INCOMING, receipt_type=RECEIPT_DELIVERY)
    read = build_receipt(INCOMING, receipt_type=RECEIPT_READ)
    assert delivery.tag == "receipt"
    assert delivery.attrs["type"] == "delivery"
    assert read.attrs["type"] == "read"
    assert delivery.content is None


def test_unsupported_receipt_type() -> None:
    with pytest.raises(ReceiptError):
        build_receipt(INCOMING, receipt_type="retry")


def test_first_retry_receipt_carries_no_keys() -> None:
    credentials = generate_credentials()
    receipt = build_retry_receipt(INCOMING, credentials)
    assert receipt.attrs["type"] == RECEIPT_RETRY
    retry = child(receipt, "retry")
    assert retry is not None
    assert retry.attrs == {"count": "1", "id": "ABC", "t": "1793474837", "v": "1"}
    registration = child(receipt, "registration")
    assert registration is not None
    assert int.from_bytes(registration.content, "big") == credentials.registration_id  # type: ignore[arg-type]
    assert child(receipt, "keys") is None


def test_second_retry_receipt_carries_keys() -> None:
    credentials = generate_credentials()
    receipt = build_retry_receipt(INCOMING, credentials, count=2, one_time_prekey=(3, b"\x01" * 32))
    keys = child(receipt, "keys")
    assert keys is not None and isinstance(keys.content, list)
    assert [item.tag for item in keys.content] == ["type", "identity", "key", "skey"]


def test_retry_limit_is_enforced() -> None:
    credentials = generate_credentials()
    with pytest.raises(ReceiptError):
        build_retry_receipt(INCOMING, credentials, count=MAX_RETRY_COUNT + 1)
    with pytest.raises(ReceiptError):
        build_retry_receipt(INCOMING, credentials, count=0)


def test_second_retry_requires_a_prekey() -> None:
    credentials = generate_credentials()
    with pytest.raises(ReceiptError):
        build_retry_receipt(INCOMING, credentials, count=2)


def test_receipt_roundtrips() -> None:
    credentials = generate_credentials()
    receipt = build_retry_receipt(INCOMING, credentials, count=2, one_time_prekey=(3, b"\x02" * 32))
    assert decode_node(encode_node(receipt)) == receipt
