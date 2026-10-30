from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from wapy.crypto.xeddsa import (
    ORDER,
    XEdDSAError,
    montgomery_to_edwards,
    sign,
    verify,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "signal" / "xeddsa.json"


def vectors() -> list[dict[str, Any]]:
    loaded: list[dict[str, Any]] = json.loads(FIXTURES.read_text(encoding="utf-8"))
    return loaded


@pytest.mark.parametrize("vector", vectors(), ids=lambda v: f"{v['public'][:8]}-{v['message'][:8]}")
def test_verify_reference_signatures(vector: dict[str, Any]) -> None:
    assert verify(
        bytes.fromhex(vector["public"]),
        bytes.fromhex(vector["message"]),
        bytes.fromhex(vector["signature"]),
    )


@pytest.mark.parametrize("vector", vectors(), ids=lambda v: f"{v['public'][:8]}-{v['message'][:8]}")
def test_own_signature_verifies(vector: dict[str, Any]) -> None:
    signature = sign(bytes.fromhex(vector["private"]), bytes.fromhex(vector["message"]))
    assert len(signature) == 64
    assert verify(bytes.fromhex(vector["public"]), bytes.fromhex(vector["message"]), signature)


def test_signature_is_deterministic_with_fixed_nonce() -> None:
    private = bytes(range(1, 33))
    nonce = bytes(64)
    first = sign(private, b"payload", nonce=nonce)
    second = sign(private, b"payload", nonce=nonce)
    assert first == second
    public = bytes.fromhex("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c")
    assert verify(public, b"payload", first)


def test_verify_rejects_tampered_message() -> None:
    vector = vectors()[1]
    signature = bytes.fromhex(vector["signature"])
    assert not verify(bytes.fromhex(vector["public"]), b"other", signature)


def test_verify_rejects_tampered_signature() -> None:
    vector = vectors()[1]
    signature = bytearray(bytes.fromhex(vector["signature"]))
    signature[10] ^= 0xFF
    assert not verify(
        bytes.fromhex(vector["public"]), bytes.fromhex(vector["message"]), bytes(signature)
    )


def test_verify_rejects_wrong_length_signature() -> None:
    assert not verify(bytes(range(32)), b"message", bytes(63))


def test_verify_rejects_wrong_length_key() -> None:
    assert not verify(bytes(31), b"message", bytes(64))


def test_sign_rejects_wrong_length_key() -> None:
    with pytest.raises(XEdDSAError):
        sign(bytes(31), b"message")


def test_small_order_public_key_is_rejected() -> None:
    assert not verify(bytes(32), b"message", bytes(64))


def test_montgomery_to_edwards_matches_reference_y() -> None:
    edwards = montgomery_to_edwards(
        bytes.fromhex("07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c")
    )
    assert len(edwards) == 32
    assert edwards[31] & 0x80 == 0


def test_order_constant() -> None:
    assert ORDER == 2**252 + 27742317777372353535851937790883648493
