"""Токен-словарь WABinary, вендоренный из эталонной реализации."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

_TOKENS_FILE: Final = Path(__file__).with_name("tokens.json")


@dataclass(frozen=True, slots=True)
class TokenRef:
    index: int
    dictionary: int | None = None


def _load() -> dict[str, Any]:
    raw: dict[str, Any] = json.loads(_TOKENS_FILE.read_text(encoding="utf-8"))
    return raw


_RAW = _load()
_TAGS: dict[str, int] = _RAW["tags"]

LIST_EMPTY: Final[int] = _TAGS["LIST_EMPTY"]
DICTIONARY_0: Final[int] = _TAGS["DICTIONARY_0"]
DICTIONARY_1: Final[int] = _TAGS["DICTIONARY_1"]
DICTIONARY_2: Final[int] = _TAGS["DICTIONARY_2"]
DICTIONARY_3: Final[int] = _TAGS["DICTIONARY_3"]
INTEROP_JID: Final[int] = _TAGS["INTEROP_JID"]
FB_JID: Final[int] = _TAGS["FB_JID"]
AD_JID: Final[int] = _TAGS["AD_JID"]
LIST_8: Final[int] = _TAGS["LIST_8"]
LIST_16: Final[int] = _TAGS["LIST_16"]
JID_PAIR: Final[int] = _TAGS["JID_PAIR"]
HEX_8: Final[int] = _TAGS["HEX_8"]
BINARY_8: Final[int] = _TAGS["BINARY_8"]
BINARY_20: Final[int] = _TAGS["BINARY_20"]
BINARY_32: Final[int] = _TAGS["BINARY_32"]
NIBBLE_8: Final[int] = _TAGS["NIBBLE_8"]
PACKED_MAX: Final[int] = _TAGS["PACKED_MAX"]

SINGLE_BYTE_TOKENS: Final[tuple[str, ...]] = tuple(_RAW["single"])
DOUBLE_BYTE_TOKENS: Final[tuple[tuple[str, ...], ...]] = tuple(
    tuple(entry) for entry in _RAW["double"]
)
DICTIONARIES: Final[tuple[tuple[str, ...], ...]] = DOUBLE_BYTE_TOKENS


def _build_token_map() -> dict[str, TokenRef]:
    mapping: dict[str, TokenRef] = {}
    for index, token in enumerate(SINGLE_BYTE_TOKENS):
        if token:
            mapping[token] = TokenRef(index=index)
    for dictionary_index, entries in enumerate(DOUBLE_BYTE_TOKENS):
        for index, token in enumerate(entries):
            mapping[token] = TokenRef(index=index, dictionary=dictionary_index)
    return mapping


TOKENS: Final[dict[str, TokenRef]] = _build_token_map()
