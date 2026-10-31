from __future__ import annotations

import asyncio
import base64
from pathlib import Path

import pytest

from wapy.creds import DeviceCredentials, generate_credentials
from wapy.crypto.primitives import generate_keypair, hmac_sha256
from wapy.crypto.xeddsa import sign
from wapy.pb import bytes_field, first_int, parse_fields, varint_field
from wapy.protocol.pairing import ACCOUNT_SIG_PREFIX
from wapy.protocol.wabinary import Node, decode_node, encode_node
from wapy.session import ClientSession, SessionError, parse_stream_error
from wapy.store import SessionStore


def stream_error_node(code: int, text: str = "") -> Node:
    return Node(
        tag="stream:error",
        attrs={},
        content=[
            Node(tag="code", attrs={}, content=str(code).encode()),
            Node(tag="text", attrs={}, content=text.encode()),
        ],
    )


def pair_device_node(refs: list[str], node_id: str = "pd-1") -> Node:
    return Node(
        tag="iq",
        attrs={"id": node_id, "type": "set", "xmlns": "md"},
        content=[
            Node(
                tag="pair-device",
                attrs={},
                content=[Node(tag="ref", attrs={}, content=r.encode()) for r in refs],
            )
        ],
    )


def pair_success_node(credentials: DeviceCredentials, node_id: str = "ps-1") -> Node:
    account = generate_keypair()
    details = varint_field(1, 1) + varint_field(2, 1_700_000_000) + varint_field(3, 0)
    account_signature = sign(
        account.private, ACCOUNT_SIG_PREFIX + details + credentials.identity_public
    )
    signed = (
        bytes_field(1, details) + bytes_field(2, account.public) + bytes_field(3, account_signature)
    )
    secret = base64.b64decode(credentials.adv_secret_key)
    payload = bytes_field(1, signed) + bytes_field(2, hmac_sha256(secret, signed))
    return Node(
        tag="iq",
        attrs={"id": node_id, "type": "set"},
        content=[
            Node(
                tag="pair-success",
                attrs={},
                content=[
                    Node(tag="device-identity", attrs={}, content=payload),
                    Node(
                        tag="device",
                        attrs={"jid": "491234567890:3@s.whatsapp.net", "lid": "9:3@lid"},
                    ),
                    Node(tag="platform", attrs={"name": "android"}),
                ],
            )
        ],
    )


class ScriptedTransport:
    """Hands out the frames of one scripted connection, then closes."""

    scripts: list[list[Node]] = []
    handshakes: list[bytes] = []
    gap: float = 0.0

    def __init__(self) -> None:
        self._frames = list(self.scripts.pop(0)) if self.scripts else []
        self.sent: list[Node] = []

    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def handshake(self, key_pair=None, client_payload: bytes = b"", **kwargs) -> object:
        ScriptedTransport.handshakes.append(client_payload)
        return object()

    async def send_encrypted(self, payload: bytes) -> None:
        node = decode_node(payload)
        self.sent.append(node)
        # Answer prekey uploads automatically so queries do not hang.
        if node.attrs.get("xmlns") == "encrypt" and node.attrs.get("type") == "set":
            self._frames.append(Node(tag="iq", attrs={"id": node.attrs["id"], "type": "result"}))

    async def recv_encrypted(self) -> bytes:
        if not self._frames:
            raise ConnectionError("scripted connection closed")
        if self.gap:
            await asyncio.sleep(self.gap)
        return encode_node(self._frames.pop(0))


@pytest.fixture
def session_path(tmp_path: Path) -> Path:
    return tmp_path / "bot.session"


async def test_parse_stream_error_recognises_restart() -> None:
    error = parse_stream_error(stream_error_node(515, "restart"))
    assert error is not None and error.code == 515 and error.text == "restart"


def test_parse_stream_error_ignores_other_nodes() -> None:
    assert parse_stream_error(Node(tag="success")) is None
    assert parse_stream_error(Node(tag="stream:error", content=[])) is None


async def test_pairing_then_restart_then_login(session_path: Path) -> None:
    credentials = generate_credentials()
    async with SessionStore(session_path) as store:
        await store.save_creds(credentials.to_dict())

    ScriptedTransport.scripts = [
        [pair_device_node(["2@a", "2@b"]), pair_success_node(credentials), stream_error_node(515)],
        [Node(tag="success", attrs={"lid": "9:3"})],
    ]
    ScriptedTransport.handshakes = []
    shown = []

    session = ClientSession(
        session_path,
        transport_factory=ScriptedTransport,
        qr_callback=shown.append,
    )
    state = await asyncio.wait_for(session.run(), timeout=20)

    assert state.paired is True
    assert state.jid == "491234567890:3@s.whatsapp.net"
    assert len(shown) == 1 and shown[0].payload.startswith("https://wa.me/")

    # first connection used the registration payload, the second the login payload
    registration, login = ScriptedTransport.handshakes
    assert 19 in parse_fields(registration)  # devicePairingData
    login_fields = parse_fields(login)
    assert first_int(login_fields, 1) == 491234567890
    assert first_int(login_fields, 3) == 1  # passive

    async with SessionStore(session_path) as store:
        stored = await store.load_creds()
    assert stored is not None and stored["me"]["id"] == state.jid


async def test_logged_out_session_raises(session_path: Path) -> None:
    credentials = generate_credentials()
    async with SessionStore(session_path) as store:
        await store.save_creds({**credentials.to_dict(), "me": {"id": "1:2@s.whatsapp.net"}})

    ScriptedTransport.scripts = [[stream_error_node(401, "logged out")]]
    ScriptedTransport.handshakes = []
    session = ClientSession(session_path, transport_factory=ScriptedTransport)
    with pytest.raises(SessionError):
        await asyncio.wait_for(session.run(), timeout=10)


async def test_fresh_session_generates_and_persists_credentials(session_path: Path) -> None:
    ScriptedTransport.scripts = [[stream_error_node(515)]]
    ScriptedTransport.handshakes = []
    session = ClientSession(session_path, transport_factory=ScriptedTransport)
    await asyncio.wait_for(session.run(), timeout=10)

    async with SessionStore(session_path) as store:
        stored = await store.load_creds()
    assert stored is not None
    assert "noise_public" in stored
    assert DeviceCredentials.from_dict(stored).verify()


async def test_qr_rotation_uses_next_ref(
    session_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    credentials = generate_credentials()
    async with SessionStore(session_path) as store:
        await store.save_creds(credentials.to_dict())

    monkeypatch.setattr("wapy.session.QR_FIRST_TTL", 0.05)
    monkeypatch.setattr("wapy.session.QR_NEXT_TTL", 0.05)
    monkeypatch.setattr(ScriptedTransport, "gap", 0.2)
    ScriptedTransport.scripts = [
        [pair_device_node(["2@first", "2@second"]), stream_error_node(515)]
    ]
    ScriptedTransport.handshakes = []
    shown = []
    session = ClientSession(
        session_path,
        transport_factory=ScriptedTransport,
        qr_callback=shown.append,
    )
    await asyncio.wait_for(session.run(), timeout=10)
    assert "2@first" in shown[0].payload
    assert any("2@second" in item.payload for item in shown)


async def test_prekeys_are_uploaded_after_connect(session_path: Path) -> None:
    credentials = generate_credentials()
    async with SessionStore(session_path) as store:
        await store.save_creds({**credentials.to_dict(), "me": {"id": "1:2@s.whatsapp.net"}})

    ScriptedTransport.scripts = [[Node(tag="success", attrs={})]]
    ScriptedTransport.handshakes = []
    session = ClientSession(session_path, transport_factory=ScriptedTransport)
    await asyncio.wait_for(session.run(), timeout=20)

    async with SessionStore(session_path) as store:
        available = await store.count_available_prekeys()
        pending = await store.pending_prekeys()
    assert available > 0
    assert pending == []
