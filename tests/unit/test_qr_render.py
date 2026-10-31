from __future__ import annotations

import base64
import zlib

import pytest

from wapy.creds import generate_credentials
from wapy.pairing import (
    PAIRING_URL,
    PLATFORM_IDS,
    PairingQrError,
    build_pairing_payload,
    pairing_qr,
)
from wapy.qr.encoder import encode
from wapy.qr.render import render_ascii, render_png

NOISE_KEY = bytes(range(1, 33))
IDENTITY_KEY = bytes(range(33, 65))
ADV_SECRET = "advsecret0123456789=="


def test_payload_layout_matches_protocol() -> None:
    payload = build_pairing_payload("2@ref", NOISE_KEY, IDENTITY_KEY, ADV_SECRET, platform="chrome")
    assert payload == (
        PAIRING_URL
        + "2@ref,"
        + base64.b64encode(NOISE_KEY).decode()
        + ","
        + base64.b64encode(IDENTITY_KEY).decode()
        + ","
        + ADV_SECRET
        + ",1"
    )


def test_payload_ends_with_platform_id() -> None:
    for name, expected in (("chrome", 1), ("firefox", 3), ("electron", 7), ("other", 9)):
        payload = build_pairing_payload("ref", NOISE_KEY, IDENTITY_KEY, ADV_SECRET, platform=name)
        assert payload.endswith(f",{expected}")
        assert PLATFORM_IDS[name] == expected


def test_empty_ref_is_rejected() -> None:
    with pytest.raises(PairingQrError):
        build_pairing_payload("", NOISE_KEY, IDENTITY_KEY, ADV_SECRET)


def test_ref_with_comma_is_rejected() -> None:
    with pytest.raises(PairingQrError):
        build_pairing_payload("a,b", NOISE_KEY, IDENTITY_KEY, ADV_SECRET)


def test_unknown_platform_is_rejected() -> None:
    with pytest.raises(PairingQrError):
        build_pairing_payload("ref", NOISE_KEY, IDENTITY_KEY, ADV_SECRET, platform="netscape")


def test_wrong_key_length_is_rejected() -> None:
    with pytest.raises(PairingQrError):
        build_pairing_payload("ref", b"short", IDENTITY_KEY, ADV_SECRET)


def test_pairing_qr_returns_payload_and_symbol() -> None:
    credentials = generate_credentials()
    payload, qr = pairing_qr("2@ref", credentials)
    assert qr.version >= 5
    assert payload == build_pairing_payload(
        "2@ref",
        credentials.noise_public,
        credentials.identity_public,
        credentials.adv_secret_key,
    )


def test_ascii_render_has_border_and_double_width() -> None:
    qr = encode("hello", level="M")
    text = render_ascii(qr, border=2)
    lines = text.splitlines()
    assert len(lines) == qr.size + 4
    assert all(len(line) == (qr.size + 4) * 2 for line in lines)
    assert lines[0].strip() == ""
    assert lines[-1].strip() == ""


def test_ascii_render_inverted_swaps_colors() -> None:
    qr = encode("hello", level="M")
    normal = render_ascii(qr, border=0)
    inverted = render_ascii(qr, border=0, inverted=True)
    assert normal != inverted
    assert normal.replace("█", " ") != inverted.replace(" ", "█")


def test_png_structure() -> None:
    qr = encode("hello", level="M")
    data = render_png(qr, scale=3, border=4)
    assert data.startswith(b"\x89PNG\r\n\x1a\n")
    assert data.endswith(b"IEND\xaeB`\x82")

    side = (qr.size + 8) * 3
    header = data[16:29]
    width, height, depth, color = (
        int.from_bytes(header[0:4], "big"),
        int.from_bytes(header[4:8], "big"),
        header[8],
        header[9],
    )
    assert (width, height, depth, color) == (side, side, 8, 0)

    idat_start = data.index(b"IDAT") + 4
    idat_length = int.from_bytes(data[idat_start - 8 : idat_start - 4], "big")
    raw = zlib.decompress(data[idat_start : idat_start + idat_length])
    assert len(raw) == side * (side + 1)


def test_png_scale_must_be_positive() -> None:
    qr = encode("hello", level="M")
    with pytest.raises(ValueError):
        render_png(qr, scale=0)
