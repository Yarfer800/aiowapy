"""Кодировщик узлов WABinary, байт-в-байт совместимый с эталоном."""

from __future__ import annotations

import zlib

from wapy.errors import WapyError
from wapy.protocol.wabinary import tokens
from wapy.protocol.wabinary.jid import FullJid, jid_decode
from wapy.protocol.wabinary.node import Node

_MAX_FRAME = 1 << 32


class EncodeError(WapyError):
    """Узел невозможно закодировать."""


def _push_byte(buffer: bytearray, value: int) -> None:
    buffer.append(value & 0xFF)


def _push_int(buffer: bytearray, value: int, width: int) -> None:
    for index in range(width):
        shift = width - 1 - index
        _push_byte(buffer, (value >> (shift * 8)) & 0xFF)


def _push_int20(buffer: bytearray, value: int) -> None:
    buffer.extend(((value >> 16) & 0x0F, (value >> 8) & 0xFF, value & 0xFF))


def _write_byte_length(buffer: bytearray, length: int) -> None:
    if length >= _MAX_FRAME:
        raise EncodeError(f"слишком длинное значение: {length}")
    if length >= 1 << 20:
        _push_byte(buffer, tokens.BINARY_32)
        _push_int(buffer, length, 4)
    elif length >= 256:
        _push_byte(buffer, tokens.BINARY_20)
        _push_int20(buffer, length)
    else:
        _push_byte(buffer, tokens.BINARY_8)
        _push_byte(buffer, length)


def _write_raw_string(buffer: bytearray, value: str) -> None:
    encoded = value.encode("utf-8")
    _write_byte_length(buffer, len(encoded))
    buffer.extend(encoded)


def _write_jid(buffer: bytearray, jid: FullJid) -> None:
    if jid.device is not None:
        _push_byte(buffer, tokens.AD_JID)
        _push_byte(buffer, jid.domain_type)
        _push_byte(buffer, jid.device)
        _write_string(buffer, jid.user)
    else:
        _push_byte(buffer, tokens.JID_PAIR)
        if jid.user:
            _write_string(buffer, jid.user)
        else:
            _push_byte(buffer, tokens.LIST_EMPTY)
        _write_string(buffer, jid.server)


def _nibble_value(char: str) -> int:
    if char == "-":
        return 10
    if char == ".":
        return 11
    if char == "\x00":
        return 15
    if "0" <= char <= "9":
        return ord(char) - ord("0")
    raise EncodeError(f'недопустимый символ для NIBBLE_8: "{char}"')


def _hex_value(char: str) -> int:
    if "0" <= char <= "9":
        return ord(char) - ord("0")
    if "A" <= char <= "F":
        return 10 + ord(char) - ord("A")
    if "a" <= char <= "f":
        return 10 + ord(char) - ord("a")
    raise EncodeError(f'недопустимый символ для HEX_8: "{char}"')


def _write_packed(buffer: bytearray, value: str, tag: int) -> None:
    if len(value) > tokens.PACKED_MAX:
        raise EncodeError("слишком длинное значение для упаковки")
    _push_byte(buffer, tag)
    packed_length = (len(value) + 1) // 2
    if len(value) % 2 != 0:
        packed_length |= 0x80
    _push_byte(buffer, packed_length)
    pack = _nibble_value if tag == tokens.NIBBLE_8 else _hex_value
    for index in range(0, len(value) - 1, 2):
        _push_byte(buffer, (pack(value[index]) << 4) | pack(value[index + 1]))
    if len(value) % 2 != 0:
        _push_byte(buffer, (pack(value[-1]) << 4) | 15)


def _is_nibble(value: str) -> bool:
    if not value or len(value) > tokens.PACKED_MAX:
        return False
    return all("0" <= char <= "9" or char in "-." for char in value)


def _is_hex(value: str) -> bool:
    if not value or len(value) > tokens.PACKED_MAX:
        return False
    return all("0" <= char <= "9" or "A" <= char <= "F" for char in value)


def _write_string(buffer: bytearray, value: str | None) -> None:
    if value is None:
        _push_byte(buffer, tokens.LIST_EMPTY)
        return
    if value == "":
        _write_raw_string(buffer, value)
        return
    token = tokens.TOKENS.get(value)
    if token is not None:
        if token.dictionary is not None:
            _push_byte(buffer, tokens.DICTIONARY_0 + token.dictionary)
        _push_byte(buffer, token.index)
        return
    if _is_nibble(value):
        _write_packed(buffer, value, tokens.NIBBLE_8)
        return
    if _is_hex(value):
        _write_packed(buffer, value, tokens.HEX_8)
        return
    jid = jid_decode(value)
    if jid is not None:
        _write_jid(buffer, jid)
        return
    _write_raw_string(buffer, value)


def _write_list_start(buffer: bytearray, size: int) -> None:
    if size == 0:
        _push_byte(buffer, tokens.LIST_EMPTY)
    elif size < 256:
        buffer.extend((tokens.LIST_8, size))
    else:
        _push_byte(buffer, tokens.LIST_16)
        _push_int(buffer, size, 2)


def _write_node(buffer: bytearray, node: Node) -> None:
    if not node.tag:
        raise EncodeError("у узла отсутствует тег")
    attrs = {key: value for key, value in node.attrs.items() if value is not None}
    _write_list_start(buffer, 2 * len(attrs) + 1 + (0 if node.content is None else 1))
    _write_string(buffer, node.tag)
    for key, value in attrs.items():
        _write_string(buffer, key)
        _write_string(buffer, value)
    if node.content is None:
        return
    if isinstance(node.content, str):
        _write_string(buffer, node.content)
    elif isinstance(node.content, (bytes, bytearray)):
        _write_byte_length(buffer, len(node.content))
        buffer.extend(node.content)
    elif isinstance(node.content, list):
        children = [child for child in node.content if child is not None]
        _write_list_start(buffer, len(children))
        for child in children:
            _write_node(buffer, child)
    else:
        raise EncodeError(f"неподдерживаемый тип содержимого: {type(node.content)!r}")


def encode_node(node: Node, *, compress: bool = False) -> bytes:
    """Кодирует узел в кадр с ведущим байтом флага сжатия."""
    payload = bytearray()
    _write_node(payload, node)
    if compress:
        return b"\x02" + zlib.compress(bytes(payload))
    return b"\x00" + bytes(payload)
