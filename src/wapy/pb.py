"""Minimal protobuf helpers shared by protocol-level messages.

Only what WhatsApp's hand-rolled messages need: varints, length-delimited
fields and skipping of unknown fields. Kept deliberately small instead of pulling
in generated code for two message types.
"""

from __future__ import annotations

from wapy.errors import WapyError

WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LEN = 2
WIRE_32BIT = 5


class ProtobufError(WapyError):
    """Message bytes do not match the expected schema."""


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ProtobufError("negative values are not supported")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def read_varint(data: bytes, position: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if position >= len(data):
            raise ProtobufError("unexpected end of varint")
        byte = data[position]
        position += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, position
        shift += 7
        if shift > 63:
            raise ProtobufError("varint is longer than 64 bits")


def tag(field_number: int, wire_type: int) -> bytes:
    return encode_varint((field_number << 3) | wire_type)


def varint_field(field_number: int, value: int) -> bytes:
    if value == 0:
        return b""
    return tag(field_number, WIRE_VARINT) + encode_varint(value)


def bytes_field(field_number: int, value: bytes) -> bytes:
    if not value:
        return b""
    return tag(field_number, WIRE_LEN) + encode_varint(len(value)) + value


def message_field(field_number: int, payload: bytes) -> bytes:
    return tag(field_number, WIRE_LEN) + encode_varint(len(payload)) + payload


def read_bytes(data: bytes, position: int) -> tuple[bytes, int]:
    length, position = read_varint(data, position)
    if position + length > len(data):
        raise ProtobufError("field length exceeds the message bounds")
    return data[position : position + length], position + length


def skip(data: bytes, position: int, wire_type: int) -> int:
    if wire_type == WIRE_VARINT:
        _, position = read_varint(data, position)
        return position
    if wire_type == WIRE_LEN:
        _, position = read_bytes(data, position)
        return position
    if wire_type == WIRE_64BIT:
        position += 8
    elif wire_type == WIRE_32BIT:
        position += 4
    else:
        raise ProtobufError(f"unsupported wire type: {wire_type}")
    if position > len(data):
        raise ProtobufError("field exceeds the message bounds")
    return position


def parse_fields(data: bytes) -> dict[int, list[object]]:
    """Decode a message into {field_number: [values]} without a schema."""
    fields: dict[int, list[object]] = {}
    position = 0
    while position < len(data):
        header, position = read_varint(data, position)
        number = header >> 3
        wire_type = header & 0x07
        number_value: object
        if wire_type == WIRE_VARINT:
            integer, position = read_varint(data, position)
            number_value = integer
        elif wire_type == WIRE_LEN:
            blob, position = read_bytes(data, position)
            number_value = blob
        else:
            position = skip(data, position, wire_type)
            continue
        fields.setdefault(number, []).append(number_value)
    return fields


def first_bytes(fields: dict[int, list[object]], number: int) -> bytes:
    values = fields.get(number)
    if not values:
        return b""
    value = values[-1]
    if not isinstance(value, bytes):
        raise ProtobufError(f"field {number} is not length-delimited")
    return value


def first_int(fields: dict[int, list[object]], number: int) -> int:
    values = fields.get(number)
    if not values:
        return 0
    value = values[-1]
    if not isinstance(value, int):
        raise ProtobufError(f"field {number} is not a varint")
    return value
