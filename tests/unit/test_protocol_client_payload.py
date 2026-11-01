from __future__ import annotations

from pathlib import Path

from aiowapy.creds import DeviceCredentials, SignedPreKey
from aiowapy.crypto.primitives import KeyPair
from aiowapy.pb import first_bytes, first_int, parse_fields
from aiowapy.protocol.client_payload import (
    PLATFORM_WEB,
    build_login_payload,
    build_registration_payload,
)

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "protocol"
    / "client_payload_registration.hex"
)


def credentials() -> DeviceCredentials:
    return DeviceCredentials(
        noise_key=KeyPair(b"\x00" * 32, b"\x00" * 32),
        identity_key=KeyPair(b"\x11" * 32, b"\x22" * 32),
        signed_pre_key=SignedPreKey(7, KeyPair(b"\x33" * 32, b"\x44" * 32), b"\x55" * 64),
        registration_id=1234,
        adv_secret_key="AAAA",
    )


def test_registration_payload_matches_reference_byte_for_byte() -> None:
    """The fixture was produced by the reference client with the same inputs.

    WhatsApp treats any deviation as "client outdated" (405), so equality here is
    a functional requirement, not a formatting preference.
    """
    expected = bytes.fromhex(FIXTURE.read_text().strip())
    actual = build_registration_payload(
        credentials(),
        version=(2, 3000, 1043857760),
        platform=PLATFORM_WEB,
        device_platform=1,
    )
    assert actual == expected


def test_registration_payload_structure() -> None:
    payload = build_registration_payload(credentials(), version=(2, 3000, 1043857760))
    fields = parse_fields(payload)
    assert 3 in fields and first_int(fields, 3) == 0  # passive
    assert 33 in fields and first_int(fields, 33) == 0  # pull
    assert first_int(fields, 12) == 1  # connectType
    assert first_int(fields, 13) == 1  # connectReason

    pairing = parse_fields(first_bytes(fields, 19))
    assert len(first_bytes(pairing, 1)) == 4  # eRegid
    assert first_bytes(pairing, 2) == b"\x05"  # eKeytype
    assert len(first_bytes(pairing, 3)) == 32  # eIdent
    assert len(first_bytes(pairing, 4)) == 3  # eSkeyId
    assert len(first_bytes(pairing, 5)) == 32  # eSkeyVal
    assert len(first_bytes(pairing, 6)) == 64  # eSkeySig
    assert len(first_bytes(pairing, 7)) == 16  # buildHash (md5)


def test_registration_payload_carries_device_props() -> None:
    payload = build_registration_payload(credentials(), version=(2, 3000, 1043857760))
    pairing = parse_fields(first_bytes(parse_fields(payload), 19))
    device_props = parse_fields(first_bytes(pairing, 8))
    assert first_bytes(device_props, 1) == b"Mac OS"
    assert first_int(device_props, 3) == 1  # platformType
    assert 5 in device_props  # historySyncConfig


def test_build_hash_tracks_version() -> None:
    first = build_registration_payload(credentials(), version=(2, 3000, 1))
    second = build_registration_payload(credentials(), version=(2, 3000, 2))
    first_hash = first_bytes(parse_fields(first_bytes(parse_fields(first), 19)), 7)
    second_hash = first_bytes(parse_fields(first_bytes(parse_fields(second), 19)), 7)
    assert first_hash != second_hash


def test_login_payload_identifies_the_device() -> None:
    payload = build_login_payload("491234567890:3@s.whatsapp.net", version=(2, 3000, 42))
    fields = parse_fields(payload)
    assert first_int(fields, 1) == 491234567890
    assert first_int(fields, 18) == 3
    assert first_int(fields, 3) == 1  # passive
    assert first_int(fields, 33) == 1  # pull


def test_push_name_is_included_when_given() -> None:
    with_name = build_registration_payload(credentials(), version=(2, 3000, 1), push_name="bot")
    without = build_registration_payload(credentials(), version=(2, 3000, 1))
    assert first_bytes(parse_fields(with_name), 7) == b"bot"
    assert len(with_name) > len(without)


def test_login_payload_matches_reference_byte_for_byte() -> None:
    """Field order matters to WhatsApp: this fixture pins the reference layout."""
    fixture = (
        Path(__file__).resolve().parents[1] / "fixtures" / "protocol" / "client_payload_login.hex"
    )
    expected = bytes.fromhex(fixture.read_text().strip())
    actual = build_login_payload("79646669102:7@s.whatsapp.net", version=(2, 3000, 1043857760))
    assert actual == expected
