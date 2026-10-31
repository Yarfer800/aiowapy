"""Minimal protobuf codec for the two Signal messages.

Field numbers are fixed by the protocol:
WhisperMessage       - 1 ephemeralKey, 2 counter, 3 previousCounter, 4 ciphertext
PreKeyWhisperMessage - 1 preKeyId, 2 baseKey, 3 identityKey, 4 message,
                       5 registrationId, 6 signedPreKeyId
"""

from __future__ import annotations

from dataclasses import dataclass

from wapy.errors import WapyError

_WHISPER_VARINT_FIELDS = {2: "counter", 3: "previous_counter"}
_WHISPER_BYTES_FIELDS = {1: "ephemeral_key", 4: "ciphertext"}
_PREKEY_VARINT_FIELDS = {1: "pre_key_id", 5: "registration_id", 6: "signed_pre_key_id"}
_PREKEY_BYTES_FIELDS = {2: "base_key", 3: "identity_key", 4: "message"}

_WIRE_VARINT = 0
_WIRE_64BIT = 1
_WIRE_LEN = 2
_WIRE_32BIT = 5


class SignalProtoError(WapyError):
    """A Signal protobuf message is corrupted or does not match the schema."""


@dataclass(slots=True)
class WhisperMessage:
    ephemeral_key: bytes = b""
    counter: int = 0
    previous_counter: int = 0
    ciphertext: bytes = b""


@dataclass(slots=True)
class PreKeyWhisperMessage:
    registration_id: int = 0
    pre_key_id: int | None = None
    signed_pre_key_id: int = 0
    base_key: bytes = b""
    identity_key: bytes = b""
    message: bytes = b""


def _varint(value: int) -> bytes:
    if value < 0:
        raise SignalProtoError("negative values are not supported in protobuf")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _tag(field_number: int, wire_type: int) -> bytes:
    return _varint((field_number << 3) | wire_type)


def _bytes_field(field_number: int, value: bytes) -> bytes:
    return _tag(field_number, _WIRE_LEN) + _varint(len(value)) + value


def _varint_field(field_number: int, value: int) -> bytes:
    return _tag(field_number, _WIRE_VARINT) + _varint(value)


def _read_varint(data: bytes, position: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if position >= len(data):
            raise SignalProtoError("unexpected end of varint")
        byte = data[position]
        position += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, position
        shift += 7
        if shift > 63:
            raise SignalProtoError("varint is longer than 64 bits")


def _read_bytes(data: bytes, position: int) -> tuple[bytes, int]:
    length, position = _read_varint(data, position)
    if position + length > len(data):
        raise SignalProtoError("field length exceeds the message bounds")
    return data[position : position + length], position + length


def _skip(data: bytes, position: int, wire_type: int) -> int:
    if wire_type == _WIRE_VARINT:
        _, position = _read_varint(data, position)
        return position
    if wire_type == _WIRE_LEN:
        _, position = _read_bytes(data, position)
        return position
    if wire_type == _WIRE_64BIT:
        position += 8
    elif wire_type == _WIRE_32BIT:
        position += 4
    else:
        raise SignalProtoError(f"unsupported wire type: {wire_type}")
    if position > len(data):
        raise SignalProtoError("field exceeds the message bounds")
    return position


def _walk(
    data: bytes,
    varint_fields: dict[int, str],
    bytes_fields: dict[int, str],
) -> dict[str, object]:
    values: dict[str, object] = {}
    position = 0
    while position < len(data):
        tag, position = _read_varint(data, position)
        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number in varint_fields and wire_type == _WIRE_VARINT:
            value, position = _read_varint(data, position)
            values[varint_fields[field_number]] = value
        elif field_number in bytes_fields and wire_type == _WIRE_LEN:
            raw, position = _read_bytes(data, position)
            values[bytes_fields[field_number]] = raw
        else:
            position = _skip(data, position, wire_type)
    return values


def encode_whisper(message: WhisperMessage) -> bytes:
    out = bytearray()
    if message.ephemeral_key:
        out += _bytes_field(1, message.ephemeral_key)
    if message.counter:
        out += _varint_field(2, message.counter)
    if message.previous_counter:
        out += _varint_field(3, message.previous_counter)
    if message.ciphertext:
        out += _bytes_field(4, message.ciphertext)
    return bytes(out)


def decode_whisper(data: bytes) -> WhisperMessage:
    values = _walk(data, _WHISPER_VARINT_FIELDS, _WHISPER_BYTES_FIELDS)
    return WhisperMessage(
        ephemeral_key=_as_bytes(values.get("ephemeral_key")),
        counter=_as_int(values.get("counter")),
        previous_counter=_as_int(values.get("previous_counter")),
        ciphertext=_as_bytes(values.get("ciphertext")),
    )


def encode_prekey(message: PreKeyWhisperMessage) -> bytes:
    out = bytearray()
    if message.pre_key_id is not None:
        out += _varint_field(1, message.pre_key_id)
    if message.base_key:
        out += _bytes_field(2, message.base_key)
    if message.identity_key:
        out += _bytes_field(3, message.identity_key)
    if message.message:
        out += _bytes_field(4, message.message)
    if message.registration_id:
        out += _varint_field(5, message.registration_id)
    if message.signed_pre_key_id:
        out += _varint_field(6, message.signed_pre_key_id)
    return bytes(out)


def decode_prekey(data: bytes) -> PreKeyWhisperMessage:
    values = _walk(data, _PREKEY_VARINT_FIELDS, _PREKEY_BYTES_FIELDS)
    pre_key_id = values.get("pre_key_id")
    return PreKeyWhisperMessage(
        registration_id=_as_int(values.get("registration_id")),
        pre_key_id=None if pre_key_id is None else _as_int(pre_key_id),
        signed_pre_key_id=_as_int(values.get("signed_pre_key_id")),
        base_key=_as_bytes(values.get("base_key")),
        identity_key=_as_bytes(values.get("identity_key")),
        message=_as_bytes(values.get("message")),
    )


def _as_int(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return int.from_bytes(value, "big")
    return 0


def _as_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, int):
        return value.to_bytes((value.bit_length() + 7) // 8 or 0, "big")
    return b""
