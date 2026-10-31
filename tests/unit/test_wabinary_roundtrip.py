"""Roundtrip decode(encode(node)) == node over random trees.

String content does not always come back as a string on the wire: only tokens,
JIDs and NIBBLE/HEX strings decode to `str`, everything else decodes to `bytes`
(the reference implementation behaves the same way). The general roundtrip test
therefore covers only `None | bytes | list[Node]`, while string content
is checked separately on tokens.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from wapy.protocol.wabinary import Node, decode_node, encode_node

# No '@': a string containing '@' is treated as a JID, and an invalid JID does not roundtrip.
TEXT = st.text(
    alphabet=st.characters(blacklist_categories=("Cc", "Cs"), blacklist_characters="@"),
    max_size=40,
)
TAG = st.text(alphabet="abcdefghijklmnopqrstuvwxyz.", min_size=1, max_size=20)
ATTR_KEY = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=20)
BINARY = st.binary(max_size=300)
TOKEN_TEXTS = st.sampled_from(["message", "presence", "iq", "type", "available", "read-self"])


def nodes(max_depth: int = 3) -> st.SearchStrategy[Node]:
    content: st.SearchStrategy[bytes | list[Node] | None]
    if max_depth <= 0:
        content = st.one_of(st.none(), BINARY)
    else:
        content = st.one_of(st.none(), BINARY, st.lists(nodes(max_depth - 1), max_size=4))
    return st.builds(
        Node,
        tag=TAG,
        attrs=st.dictionaries(ATTR_KEY, TEXT, max_size=4),
        content=content,
    )


@settings(max_examples=200, deadline=None)
@given(node=nodes())
def test_roundtrip_preserves_node(node: Node) -> None:
    assert decode_node(encode_node(node)) == node


@settings(max_examples=100, deadline=None)
@given(node=nodes())
def test_compressed_roundtrip_preserves_node(node: Node) -> None:
    assert decode_node(encode_node(node, compress=True)) == node


@given(value=TEXT)
def test_string_attributes_survive(value: str) -> None:
    node = Node(tag="iq", attrs={"v": value})
    assert decode_node(encode_node(node)).attrs["v"] == value


@given(value=TOKEN_TEXTS)
def test_token_content_stays_string(value: str) -> None:
    node = Node(tag="iq", content=value)
    assert decode_node(encode_node(node)).content == value


@given(value=st.text(alphabet="0123456789-.", min_size=1, max_size=127))
def test_nibble_strings_survive(value: str) -> None:
    node = Node(tag="iq", attrs={"v": value})
    assert decode_node(encode_node(node)).attrs["v"] == value


@given(value=st.text(alphabet="0123456789ABCDEF", min_size=1, max_size=127))
def test_hex_strings_survive(value: str) -> None:
    node = Node(tag="iq", attrs={"v": value})
    assert decode_node(encode_node(node)).attrs["v"] == value


@settings(max_examples=50, deadline=None)
@given(size=st.integers(min_value=0, max_value=700))
def test_binary_length_classes_survive(size: int) -> None:
    node = Node(tag="enc", content=bytes(size))
    assert decode_node(encode_node(node)).content == bytes(size)


@settings(max_examples=30, deadline=None)
@given(count=st.integers(min_value=0, max_value=400))
def test_list_length_classes_survive(count: int) -> None:
    children = [Node(tag="item", attrs={"n": str(index)}) for index in range(count)]
    node = Node(tag="iq", content=children)
    assert decode_node(encode_node(node)).content == node.content


@given(user=st.text(alphabet="0123456789", min_size=1, max_size=15))
def test_jid_attribute_survives(user: str) -> None:
    jid = f"{user}@s.whatsapp.net"
    node = Node(tag="message", attrs={"to": jid})
    assert decode_node(encode_node(node)).attrs["to"] == jid


@given(user=st.text(alphabet="0123456789", min_size=1, max_size=15))
def test_jid_with_device_attribute_survives(user: str) -> None:
    jid = f"{user}:3@s.whatsapp.net"
    node = Node(tag="message", attrs={"to": jid})
    assert decode_node(encode_node(node)).attrs["to"] == jid
