"""WABinary node decoder."""

from __future__ import annotations

import zlib

from wapy.errors import WapyError
from wapy.protocol.wabinary import tokens
from wapy.protocol.wabinary.jid import jid_encode, server_from_domain_type
from wapy.protocol.wabinary.node import Node


class DecodeError(WapyError):
    """Frame cannot be decoded."""


def _unpack(tag: int, value: int) -> str:
    if tag == tokens.NIBBLE_8:
        if 0 <= value <= 9:
            return chr(ord("0") + value)
        if value == 10:
            return "-"
        if value == 11:
            return "."
        if value == 15:
            return "\x00"
        raise DecodeError(f"invalid nibble: {value}")
    if tag == tokens.HEX_8:
        if 0 <= value <= 9:
            return chr(ord("0") + value)
        if 10 <= value <= 15:
            return chr(ord("A") + value - 10)
        raise DecodeError(f"invalid hex digit: {value}")
    raise DecodeError(f"invalid packing tag: {tag}")


def _double_token(dictionary: int, index: int) -> str:
    if dictionary >= len(tokens.DOUBLE_BYTE_TOKENS):
        raise DecodeError(f"invalid token dictionary: {dictionary}")
    entries = tokens.DOUBLE_BYTE_TOKENS[dictionary]
    if index >= len(entries):
        raise DecodeError(f"invalid token index: {index}")
    return entries[index]


class _Reader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self.index = 0

    def _check(self, length: int) -> None:
        if self.index + length > len(self._data):
            raise DecodeError("unexpected end of frame")

    def read_byte(self) -> int:
        self._check(1)
        value = self._data[self.index]
        self.index += 1
        return value

    def read_bytes(self, length: int) -> bytes:
        self._check(length)
        value = self._data[self.index : self.index + length]
        self.index += length
        return value

    def read_int(self, width: int) -> int:
        self._check(width)
        value = 0
        for _ in range(width):
            value = (value << 8) | self.read_byte()
        return value

    def read_int20(self) -> int:
        self._check(3)
        return ((self.read_byte() & 0x0F) << 16) | (self.read_byte() << 8) | self.read_byte()

    def read_packed(self, tag: int) -> str:
        start = self.read_byte()
        count = start & 0x7F
        if count > tokens.PACKED_MAX:
            raise DecodeError(f"invalid packed length: {count}")
        chars: list[str] = []
        for _ in range(count):
            value = self.read_byte()
            chars.append(_unpack(tag, (value & 0xF0) >> 4))
            chars.append(_unpack(tag, value & 0x0F))
        if start >> 7:
            chars.pop()
        return "".join(chars)

    def read_list_size(self, tag: int) -> int:
        if tag == tokens.LIST_EMPTY:
            return 0
        if tag == tokens.LIST_8:
            return self.read_byte()
        if tag == tokens.LIST_16:
            return self.read_int(2)
        raise DecodeError(f"invalid list size tag: {tag}")

    def read_string(self, tag: int) -> str:
        if 1 <= tag < len(tokens.SINGLE_BYTE_TOKENS):
            return tokens.SINGLE_BYTE_TOKENS[tag]
        if tokens.DICTIONARY_0 <= tag <= tokens.DICTIONARY_3:
            return _double_token(tag - tokens.DICTIONARY_0, self.read_byte())
        if tag == tokens.LIST_EMPTY:
            return ""
        if tag == tokens.BINARY_8:
            return self.read_bytes(self.read_byte()).decode("utf-8", errors="replace")
        if tag == tokens.BINARY_20:
            return self.read_bytes(self.read_int20()).decode("utf-8", errors="replace")
        if tag == tokens.BINARY_32:
            return self.read_bytes(self.read_int(4)).decode("utf-8", errors="replace")
        if tag == tokens.JID_PAIR:
            return self._read_jid_pair()
        if tag == tokens.AD_JID:
            return self._read_ad_jid()
        if tag == tokens.FB_JID:
            return self._read_fb_jid()
        if tag == tokens.INTEROP_JID:
            return self._read_interop_jid()
        if tag in (tokens.HEX_8, tokens.NIBBLE_8):
            return self.read_packed(tag)
        raise DecodeError(f"invalid string tag: {tag}")

    def _read_jid_pair(self) -> str:
        user = self.read_string(self.read_byte())
        server = self.read_string(self.read_byte())
        if not server:
            raise DecodeError("invalid JID pair")
        return f"{user}@{server}" if user else f"@{server}"

    def _read_ad_jid(self) -> str:
        domain_type = self.read_byte()
        device = self.read_byte()
        user = self.read_string(self.read_byte())
        server = server_from_domain_type("s.whatsapp.net", domain_type)
        return jid_encode(user, server, device)

    def _read_fb_jid(self) -> str:
        user = self.read_string(self.read_byte())
        device = self.read_int(2)
        server = self.read_string(self.read_byte())
        return f"{user}:{device}@{server}"

    def _read_interop_jid(self) -> str:
        user = self.read_string(self.read_byte())
        device = self.read_int(2)
        integrator = self.read_int(2)
        server = "interop"
        start = self.index
        try:
            server = self.read_string(self.read_byte())
        except DecodeError:
            self.index = start
        return f"{integrator}-{user}:{device}@{server}"

    def read_list(self, tag: int) -> list[Node]:
        size = self.read_list_size(tag)
        return [self.read_node() for _ in range(size)]

    def read_node(self) -> Node:
        list_size = self.read_list_size(self.read_byte())
        tag = self.read_string(self.read_byte())
        if list_size == 0 or not tag:
            raise DecodeError("empty node")
        attrs: dict[str, str] = {}
        for _ in range((list_size - 1) >> 1):
            key = self.read_string(self.read_byte())
            value = self.read_string(self.read_byte())
            attrs[key] = value
        content: bytes | str | list[Node] | None = None
        if list_size % 2 == 0:
            content_tag = self.read_byte()
            if content_tag in (tokens.LIST_EMPTY, tokens.LIST_8, tokens.LIST_16):
                content = self.read_list(content_tag)
            elif content_tag == tokens.BINARY_8:
                content = self.read_bytes(self.read_byte())
            elif content_tag == tokens.BINARY_20:
                content = self.read_bytes(self.read_int20())
            elif content_tag == tokens.BINARY_32:
                content = self.read_bytes(self.read_int(4))
            else:
                content = self.read_string(content_tag)
        return Node(tag=tag, attrs=attrs, content=content)


def decode_uncompressed(payload: bytes) -> Node:
    return _Reader(payload).read_node()


def decode_node(frame: bytes) -> Node:
    """Decode a frame: inflate zlib when flag 0x02 is set, otherwise strip the leading byte."""
    if not frame:
        raise DecodeError("empty frame")
    flag = frame[0]
    if flag & 0x02:
        try:
            payload = zlib.decompress(frame[1:])
        except zlib.error as exc:
            raise DecodeError(f"failed to inflate frame: {exc}") from exc
    else:
        payload = frame[1:]
    return decode_uncompressed(payload)
