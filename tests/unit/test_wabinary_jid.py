from __future__ import annotations

import pytest

from wapy.protocol.wabinary.jid import (
    WA_DOMAIN_HOSTED,
    WA_DOMAIN_HOSTED_LID,
    WA_DOMAIN_LID,
    FullJid,
    jid_decode,
    jid_encode,
    server_from_domain_type,
)


def test_decode_plain_jid() -> None:
    decoded = jid_decode("491234567890@s.whatsapp.net")
    assert decoded == FullJid(user="491234567890", server="s.whatsapp.net", domain_type=0)


def test_decode_jid_with_device() -> None:
    decoded = jid_decode("491234567890:3@s.whatsapp.net")
    assert decoded is not None
    assert decoded.user == "491234567890"
    assert decoded.server == "s.whatsapp.net"
    assert decoded.device == 3


def test_decode_lid_jid_sets_domain_type() -> None:
    decoded = jid_decode("123456789@lid")
    assert decoded is not None
    assert decoded.domain_type == WA_DOMAIN_LID


def test_decode_hosted_variants() -> None:
    hosted = jid_decode("123@hosted")
    hosted_lid = jid_decode("123@hosted.lid")
    assert hosted is not None and hosted.domain_type == WA_DOMAIN_HOSTED
    assert hosted_lid is not None and hosted_lid.domain_type == WA_DOMAIN_HOSTED_LID


def test_decode_agent_sets_domain_type() -> None:
    decoded = jid_decode("123_5@s.whatsapp.net")
    assert decoded is not None
    assert decoded.agent == 5
    assert decoded.domain_type == 5


def test_decode_without_at_returns_none() -> None:
    assert jid_decode("plainstring") is None
    assert jid_decode("") is None
    assert jid_decode(None) is None


@pytest.mark.parametrize(
    ("user", "server", "device", "agent", "expected"),
    [
        ("491234567890", "s.whatsapp.net", None, None, "491234567890@s.whatsapp.net"),
        ("491234567890", "s.whatsapp.net", 3, None, "491234567890:3@s.whatsapp.net"),
        ("491234567890", "s.whatsapp.net", None, 2, "491234567890_2@s.whatsapp.net"),
        (None, "status@broadcast", None, None, "@status@broadcast"),
    ],
)
def test_encode(
    user: str | None, server: str, device: int | None, agent: int | None, expected: str
) -> None:
    assert jid_encode(user, server, device, agent) == expected


def test_encode_zero_device_is_dropped_like_reference() -> None:
    assert jid_encode("491234567890", "s.whatsapp.net", 0) == "491234567890@s.whatsapp.net"


def test_server_from_domain_type() -> None:
    assert server_from_domain_type("s.whatsapp.net", 0) == "s.whatsapp.net"
    assert server_from_domain_type("s.whatsapp.net", WA_DOMAIN_LID) == "lid"
    assert server_from_domain_type("s.whatsapp.net", WA_DOMAIN_HOSTED) == "hosted"
    assert server_from_domain_type("s.whatsapp.net", WA_DOMAIN_HOSTED_LID) == "hosted.lid"


def test_decode_encode_roundtrip_for_device_and_lid() -> None:
    for original in ("491234567890:3@s.whatsapp.net", "123456789@lid", "42@g.us"):
        decoded = jid_decode(original)
        assert decoded is not None
        rebuilt = jid_encode(decoded.user, decoded.server, decoded.device, decoded.agent)
        assert rebuilt == original
