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
from wapy.protocol.stream import child
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
    instances: list[ScriptedTransport] = []

    def __init__(self) -> None:
        ScriptedTransport.instances.append(self)
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


async def test_logged_out_session_falls_back_to_pairing(session_path: Path) -> None:
    credentials = generate_credentials()
    async with SessionStore(session_path) as store:
        await store.save_creds({**credentials.to_dict(), "me": {"id": "1:2@s.whatsapp.net"}})

    ScriptedTransport.scripts = [
        [stream_error_node(401, "logged out")],
        [pair_device_node(["2@a"]), stream_error_node(515)],
    ]
    ScriptedTransport.handshakes = []
    shown = []
    session = ClientSession(
        session_path, transport_factory=ScriptedTransport, qr_callback=shown.append
    )
    await asyncio.wait_for(session.run(), timeout=20)

    # first attempt used the login payload, the retry went back to registration
    assert 1 in parse_fields(ScriptedTransport.handshakes[0])
    assert 19 in parse_fields(ScriptedTransport.handshakes[1])
    assert shown  # a QR was offered again

    async with SessionStore(session_path) as store:
        stored = await store.load_creds()
    assert stored is not None and "me" not in stored


async def test_unpaired_401_is_terminal(session_path: Path) -> None:
    ScriptedTransport.scripts = [[stream_error_node(401, "no account")]]
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


async def test_restart_after_pairing_persists_the_account(session_path: Path) -> None:
    credentials = generate_credentials()
    async with SessionStore(session_path) as store:
        await store.save_creds(credentials.to_dict())

    ScriptedTransport.scripts = [
        [pair_device_node(["2@a"]), pair_success_node(credentials), stream_error_node(515)],
        [stream_error_node(515)],
    ]
    ScriptedTransport.handshakes = []
    session = ClientSession(
        session_path, transport_factory=ScriptedTransport, qr_callback=lambda item: None
    )
    await asyncio.wait_for(session.run(), timeout=20)

    async with SessionStore(session_path) as store:
        stored = await store.load_creds()
    assert stored is not None and stored["me"]["id"].endswith("@s.whatsapp.net")
    assert 1 in parse_fields(ScriptedTransport.handshakes[1])  # login payload


def test_parse_stream_error_from_attribute() -> None:
    error = parse_stream_error(Node(tag="stream:error", attrs={"code": "515"}))
    assert error is not None and error.code == 515


def test_parse_stream_error_prefers_child_code() -> None:
    node = Node(
        tag="stream:error",
        attrs={"code": "401"},
        content=[Node(tag="code", attrs={}, content=b"515")],
    )
    error = parse_stream_error(node)
    assert error is not None and error.code == 515


def test_unified_session_id_is_within_a_week() -> None:
    from wapy.session import unified_session_id

    value = int(unified_session_id(1_700_000_000.0))
    assert 0 <= value < 604_800_000


async def test_pairing_reply_is_addressed_to_the_whatsapp_server(session_path: Path) -> None:
    credentials = generate_credentials()
    async with SessionStore(session_path) as store:
        await store.save_creds(credentials.to_dict())

    ScriptedTransport.scripts = [
        [pair_device_node(["2@a"]), pair_success_node(credentials), stream_error_node(515)]
    ]
    ScriptedTransport.handshakes = []
    ScriptedTransport.instances = []
    session = ClientSession(
        session_path, transport_factory=ScriptedTransport, qr_callback=lambda item: None
    )
    await asyncio.wait_for(session.run(), timeout=20)

    transport = ScriptedTransport.instances[0]
    replies = [
        node for node in transport.sent if node.tag == "iq" and node.attrs.get("type") == "result"
    ]
    assert any(node.attrs["to"] == "@s.whatsapp.net" for node in replies)
    assert any(node.tag == "ib" for node in transport.sent)


async def test_failure_401_on_paired_session_is_reported(session_path: Path) -> None:
    credentials = generate_credentials()
    async with SessionStore(session_path) as store:
        await store.save_creds({**credentials.to_dict(), "me": {"id": "1:2@s.whatsapp.net"}})

    ScriptedTransport.scripts = [[Node(tag="failure", attrs={"reason": "401"})]]
    ScriptedTransport.handshakes = []
    ScriptedTransport.instances = []
    session = ClientSession(
        session_path, transport_factory=ScriptedTransport, qr_callback=lambda item: None
    )
    with pytest.raises(SessionError):
        await asyncio.wait_for(session.run(), timeout=10)

    # exactly one attempt: no QR storm after a failed activation
    assert len(ScriptedTransport.handshakes) == 1
    async with SessionStore(session_path) as store:
        stored = await store.load_creds()
    assert stored is not None and "me" not in stored


def _pairing_ref_node(ref: bytes = b"ref") -> Node:
    return Node(
        tag="iq",
        attrs={"type": "result", "id": "hello"},
        content=[
            Node(
                tag="link_code_companion_reg",
                attrs={"stage": "primary_hello"},
                content=[Node(tag="link_code_pairing_ref", attrs={}, content=ref)],
            )
        ],
    )


def _companion_finish_node(
    server_ephemeral_public: bytes, primary_identity_public: bytes, code: str
) -> Node:
    from wapy.protocol.pairing_code import wrap_ephemeral_public

    wrapped = wrap_ephemeral_public(code, server_ephemeral_public, salt=bytes(32), iv=bytes(16))
    return Node(
        tag="iq",
        attrs={"type": "set", "xmlns": "md"},
        content=[
            Node(
                tag="link_code_companion_reg",
                attrs={"stage": "companion_finish"},
                content=[
                    Node(tag="link_code_pairing_ref", attrs={}, content=b"ref"),
                    Node(tag="primary_identity_pub", attrs={}, content=primary_identity_public),
                    Node(
                        tag="link_code_pairing_wrapped_primary_ephemeral_pub",
                        attrs={},
                        content=wrapped,
                    ),
                ],
            )
        ],
    )


async def test_pairing_by_phone_number_completes(
    session_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from wapy.crypto.primitives import generate_keypair

    monkeypatch.setattr(ScriptedTransport, "gap", 0.0)
    credentials = generate_credentials()
    async with SessionStore(session_path) as store:
        await store.save_creds(credentials.to_dict())

    code = "ABCD1234"
    server_ephemeral = generate_keypair()
    primary_identity = generate_keypair()
    ScriptedTransport.scripts = [
        [
            _pairing_ref_node(),
            _companion_finish_node(server_ephemeral.public, primary_identity.public, code),
            Node(tag="success", attrs={}),
        ]
    ]
    ScriptedTransport.handshakes = []
    ScriptedTransport.instances = []

    session = ClientSession(session_path, transport_factory=ScriptedTransport)
    state = await asyncio.wait_for(
        session.pair_with_phone_number("+79 646 669 102", code), timeout=20
    )

    assert state.jid == "+79646669102@s.whatsapp.net"
    transport = ScriptedTransport.instances[0]
    stages = [
        child(node, "link_code_companion_reg").attrs["stage"]
        for node in transport.sent
        if child(node, "link_code_companion_reg") is not None
    ]
    assert stages == ["companion_hello", "companion_finish"]

    async with SessionStore(session_path) as store:
        stored = await store.load_creds()
        available = await store.count_available_prekeys()
    assert stored is not None
    assert stored["me"]["id"] == "+79646669102@s.whatsapp.net"
    assert stored["adv_secret_key"] != credentials.adv_secret_key
    assert available > 0


async def test_phone_pairing_rejects_a_failure(session_path: Path) -> None:
    from wapy.crypto.primitives import generate_keypair

    credentials = generate_credentials()
    async with SessionStore(session_path) as store:
        await store.save_creds(credentials.to_dict())

    ScriptedTransport.scripts = [
        [
            _pairing_ref_node(),
            _companion_finish_node(
                generate_keypair().public, generate_keypair().public, "ABCD1234"
            ),
            Node(tag="failure", attrs={"reason": "401"}),
        ]
    ]
    ScriptedTransport.handshakes = []
    ScriptedTransport.instances = []
    session = ClientSession(session_path, transport_factory=ScriptedTransport)
    with pytest.raises(SessionError):
        await asyncio.wait_for(
            session.pair_with_phone_number("79646669102", "ABCD1234"), timeout=20
        )


async def test_phone_pairing_acknowledges_server_requests(session_path: Path) -> None:
    from wapy.crypto.primitives import generate_keypair

    credentials = generate_credentials()
    async with SessionStore(session_path) as store:
        await store.save_creds(credentials.to_dict())

    server_request = Node(tag="iq", attrs={"type": "set", "id": "srv-1", "xmlns": "md"})
    ScriptedTransport.scripts = [
        [
            _pairing_ref_node(),
            server_request,
            _companion_finish_node(
                generate_keypair().public, generate_keypair().public, "ABCD1234"
            ),
            Node(tag="success", attrs={}),
        ]
    ]
    ScriptedTransport.handshakes = []
    ScriptedTransport.instances = []
    session = ClientSession(session_path, transport_factory=ScriptedTransport)
    await asyncio.wait_for(session.pair_with_phone_number("79646669102", "ABCD1234"), timeout=20)

    sent = ScriptedTransport.instances[0].sent
    acks = [
        n
        for n in sent
        if n.tag == "iq" and n.attrs.get("type") == "result" and n.attrs.get("id") == "srv-1"
    ]
    assert acks and acks[0].attrs["to"] == "@s.whatsapp.net"


def test_phone_jid_keeps_the_leading_plus() -> None:
    from wapy.session import phone_jid

    assert phone_jid("+79 646 669 102") == "+79646669102@s.whatsapp.net"
    assert phone_jid("79646669102") == "+79646669102@s.whatsapp.net"
    with pytest.raises(SessionError):
        phone_jid("+ - ")
