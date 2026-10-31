from __future__ import annotations

from wapy.pb import parse_fields
from wapy.protocol.messages import (
    QuoteRef,
    encode_edit,
    encode_reaction,
    encode_revoke,
    encode_text,
    parse_message,
)

CHAT = "491234567890@s.whatsapp.net"
GROUP = "120363000000000001@g.us"
MSG = "3EB0ABCDEF"


def test_reaction_roundtrip() -> None:
    parsed = parse_message(encode_reaction(CHAT, MSG, "\U0001f44d", timestamp_ms=1_700_000_000_000))
    assert parsed.reaction is not None
    assert parsed.reaction.message_id == MSG
    assert parsed.reaction.text == "\U0001f44d"
    assert parsed.reaction.sender_jid is None


def test_group_reaction_carries_the_participant() -> None:
    parsed = parse_message(encode_reaction(GROUP, MSG, "\u2764", sender_jid=CHAT))
    assert parsed.reaction is not None
    assert parsed.reaction.sender_jid == CHAT


def test_empty_reaction_is_a_retraction() -> None:
    parsed = parse_message(encode_reaction(CHAT, MSG, ""))
    assert parsed.reaction is not None
    assert parsed.reaction.text == ""


def test_edit_roundtrip() -> None:
    parsed = parse_message(encode_edit(CHAT, MSG, "new text"))
    assert parsed.protocol is not None
    assert parsed.protocol.kind == "edit"
    assert parsed.protocol.message_id == MSG
    assert parsed.protocol.text == "new text"


def test_revoke_roundtrip() -> None:
    parsed = parse_message(encode_revoke(CHAT, MSG))
    assert parsed.protocol is not None
    assert parsed.protocol.kind == "revoke"
    assert parsed.protocol.message_id == MSG
    assert parsed.protocol.text is None


def test_quote_is_attached_to_extended_text() -> None:
    quote = QuoteRef(chat_jid=CHAT, message_id=MSG, sender_jid=CHAT, text="original")
    payload = encode_text("answer", quote=quote)
    fields = parse_fields(payload)
    assert 6 in fields  # extendedTextMessage
    parsed = parse_message(payload)
    assert parsed.text == "answer"
    assert parsed.quote is not None
    assert parsed.quote.message_id == MSG
    assert parsed.quote.sender_jid == CHAT
    assert parsed.quote.text == "original"


def test_plain_text_has_no_quote() -> None:
    assert parse_message(encode_text("plain")).quote is None


def test_long_text_with_quote_still_parses() -> None:
    quote = QuoteRef(chat_jid=CHAT, message_id=MSG, sender_jid=CHAT, text="x")
    text = "y" * 400
    parsed = parse_message(encode_text(text, quote=quote))
    assert parsed.text == text
    assert parsed.quote is not None


def test_unknown_protocol_message_is_ignored() -> None:
    from wapy.pb import bytes_field, message_field, varint_field_explicit

    payload = bytes_field(12, bytes_field(1, bytes_field(3, b"ID")) + varint_field_explicit(2, 9))
    assert parse_message(payload).protocol is None
    assert parse_message(message_field(12, b"")).protocol is None
