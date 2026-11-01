from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aiowapy.crypto.signal_proto import (
    PreKeyWhisperMessage,
    SignalProtoError,
    WhisperMessage,
    decode_prekey,
    decode_whisper,
    encode_prekey,
    encode_whisper,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "signal" / "protobuf.json"


def fixtures() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(FIXTURES.read_text(encoding="utf-8"))
    return loaded


def test_whisper_encode_matches_reference() -> None:
    fields = fixtures()["whisper"]["fields"]
    message = WhisperMessage(
        ephemeral_key=bytes.fromhex(fields["ephemeralKey"]),
        counter=fields["counter"],
        previous_counter=fields["previousCounter"],
        ciphertext=bytes.fromhex(fields["ciphertext"]),
    )
    assert encode_whisper(message).hex() == fixtures()["whisper"]["hex"]


def test_whisper_decode_matches_reference() -> None:
    decoded = decode_whisper(bytes.fromhex(fixtures()["whisper"]["hex"]))
    fields = fixtures()["whisper"]["fields"]
    assert decoded.ephemeral_key == bytes.fromhex(fields["ephemeralKey"])
    assert decoded.counter == fields["counter"]
    assert decoded.previous_counter == fields["previousCounter"]
    assert decoded.ciphertext == bytes.fromhex(fields["ciphertext"])


def test_prekey_encode_matches_reference() -> None:
    fields = fixtures()["prekey"]["fields"]
    message = PreKeyWhisperMessage(
        registration_id=fields["registrationId"],
        pre_key_id=fields["preKeyId"],
        signed_pre_key_id=fields["signedPreKeyId"],
        base_key=bytes.fromhex(fields["baseKey"]),
        identity_key=bytes.fromhex(fields["identityKey"]),
        message=bytes.fromhex(fields["message"]),
    )
    assert encode_prekey(message).hex() == fixtures()["prekey"]["hex"]


def test_prekey_decode_matches_reference() -> None:
    decoded = decode_prekey(bytes.fromhex(fixtures()["prekey"]["hex"]))
    fields = fixtures()["prekey"]["fields"]
    assert decoded.registration_id == fields["registrationId"]
    assert decoded.pre_key_id == fields["preKeyId"]
    assert decoded.signed_pre_key_id == fields["signedPreKeyId"]
    assert decoded.base_key == bytes.fromhex(fields["baseKey"])
    assert decoded.identity_key == bytes.fromhex(fields["identityKey"])
    assert decoded.message == bytes.fromhex(fields["message"])


def test_prekey_without_pre_key_id_omits_field() -> None:
    message = PreKeyWhisperMessage(
        registration_id=1,
        pre_key_id=None,
        signed_pre_key_id=2,
        base_key=b"\x05" * 33,
        identity_key=b"\x06" * 33,
        message=b"\x07" * 10,
    )
    encoded = encode_prekey(message)
    assert encoded[0] != 0x08
    assert decode_prekey(encoded).pre_key_id is None


def test_decode_skips_unknown_fields() -> None:
    encoded = encode_whisper(
        WhisperMessage(ephemeral_key=b"\x05" * 33, counter=1, previous_counter=0, ciphertext=b"x")
    )
    extended = encoded + b"\x50\x2a"  # field 10, varint 42: unknown
    assert decode_whisper(extended).counter == 1


def test_decode_rejects_truncated_varint() -> None:
    with pytest.raises(SignalProtoError):
        decode_whisper(b"\x10\xff")


def test_decode_rejects_wrong_wire_type() -> None:
    with pytest.raises(SignalProtoError):
        decode_whisper(b"\x0e\x00")  # field 1, wire type 6: invalid


def test_decode_whisper_of_empty_bytes_uses_defaults() -> None:
    decoded = decode_whisper(b"")
    assert decoded.ephemeral_key == b""
    assert decoded.counter == 0
    assert decoded.ciphertext == b""


def test_roundtrip_whisper() -> None:
    message = WhisperMessage(
        ephemeral_key=b"\x05" * 33, counter=2**31, previous_counter=7, ciphertext=b"payload"
    )
    assert decode_whisper(encode_whisper(message)) == message


def test_roundtrip_prekey() -> None:
    message = PreKeyWhisperMessage(
        registration_id=2**20,
        pre_key_id=2**20 - 1,
        signed_pre_key_id=1,
        base_key=b"\x05" * 33,
        identity_key=b"\x05" * 33,
        message=b"whisper",
    )
    assert decode_prekey(encode_prekey(message)) == message
