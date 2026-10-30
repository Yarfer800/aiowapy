from __future__ import annotations

from wapy.protocol.wabinary import tokens


def test_tag_values_match_reference() -> None:
    assert tokens.LIST_EMPTY == 0
    assert tokens.DICTIONARY_0 == 236
    assert tokens.DICTIONARY_3 == 239
    assert tokens.AD_JID == 247
    assert tokens.LIST_8 == 248
    assert tokens.LIST_16 == 249
    assert tokens.JID_PAIR == 250
    assert tokens.HEX_8 == 251
    assert tokens.BINARY_8 == 252
    assert tokens.BINARY_20 == 253
    assert tokens.BINARY_32 == 254
    assert tokens.NIBBLE_8 == 255
    assert tokens.PACKED_MAX == 127


def test_dictionary_shape() -> None:
    assert len(tokens.SINGLE_BYTE_TOKENS) == 236
    assert len(tokens.DOUBLE_BYTE_TOKENS) == 4
    assert all(len(entry) == 256 for entry in tokens.DOUBLE_BYTE_TOKENS)
    assert tokens.SINGLE_BYTE_TOKENS[0] == ""
    assert tokens.SINGLE_BYTE_TOKENS[3] == "s.whatsapp.net"


def test_anchor_tokens() -> None:
    assert tokens.SINGLE_BYTE_TOKENS.index("message") == 19
    assert tokens.SINGLE_BYTE_TOKENS.index("presence") == 31
    assert tokens.DOUBLE_BYTE_TOKENS[0][0] == "read-self"


def test_token_map_resolves_both_widths() -> None:
    assert tokens.TOKENS["message"] == tokens.TokenRef(index=19)
    assert tokens.TOKENS["read-self"] == tokens.TokenRef(index=0, dictionary=0)
    assert tokens.TOKENS["type"] == tokens.TokenRef(index=4)
