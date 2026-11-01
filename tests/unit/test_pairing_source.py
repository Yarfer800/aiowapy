from __future__ import annotations

import pytest

from aiowapy.creds import generate_credentials
from aiowapy.pairing import (
    QR_FIRST_TTL,
    QR_NEXT_TTL,
    PairingQrError,
    PairingQrSource,
)


def test_first_qr_gets_the_long_ttl_and_the_rest_the_short_one() -> None:
    source = PairingQrSource(generate_credentials(), ["2@a", "2@b", "2@c"])
    ttls = [item.ttl for item in source]
    assert ttls == [QR_FIRST_TTL, QR_NEXT_TTL, QR_NEXT_TTL]


def test_ttls_are_configurable() -> None:
    source = PairingQrSource(generate_credentials(), ["2@a", "2@b"], first_ttl=90, next_ttl=5)
    assert [item.ttl for item in source] == [90, 5]


def test_each_qr_carries_its_own_ref() -> None:
    source = PairingQrSource(generate_credentials(), ["2@first", "2@second"])
    first = source.next()
    second = source.next()
    assert first is not None and second is not None
    assert "#2@first," in first.payload
    assert "#2@second," in second.payload


def test_keys_are_stable_across_rotations() -> None:
    credentials = generate_credentials()
    source = PairingQrSource(credentials, ["2@a", "2@b"])
    payloads = [item.payload for item in source]
    tail = payloads[0].split(",", 1)[1]
    assert payloads[1].split(",", 1)[1] == tail


def test_exhaustion_returns_none() -> None:
    source = PairingQrSource(generate_credentials(), ["2@a"])
    assert source.next() is not None
    assert source.next() is None
    assert source.next() is None


def test_remaining_counts_down() -> None:
    source = PairingQrSource(generate_credentials(), ["2@a", "2@b"])
    assert (len(source), source.remaining) == (2, 2)
    source.next()
    assert source.remaining == 1


def test_empty_ref_list_is_rejected() -> None:
    with pytest.raises(PairingQrError):
        PairingQrSource(generate_credentials(), [])


def test_qr_is_decodable_size_for_real_payload() -> None:
    source = PairingQrSource(generate_credentials(), ["2@" + "x" * 20])
    item = source.next()
    assert item is not None
    assert item.qr.version >= 5
    assert item.qr.size == 17 + 4 * item.qr.version
