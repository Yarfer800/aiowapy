"""Noise handshake tests.

There is no server implementation to test against offline, so the tests carry a
responder that mirrors the exact operation order WhatsApp's server follows. That
is what proves the client sequence (hash mixing, key schedule, counters) is
self-consistent; interoperability is checked against the live server separately.
"""

from __future__ import annotations

import pytest

from wapy.crypto.primitives import (
    CryptoError,
    KeyPair,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    dh,
    generate_keypair,
    hkdf,
    sha256,
)
from wapy.crypto.xeddsa import sign
from wapy.pb import bytes_field, message_field, varint_field
from wapy.protocol.handshake import HandshakeMessage, ServerHello, decode, encode
from wapy.protocol.noise import (
    INTRO_MAGIC,
    PROTOCOL_NAME,
    NoiseError,
    NoiseHandshake,
    NoiseTransport,
    counter_iv,
    parse_cert_chain,
    parse_certificate_details,
)


def make_details(key: bytes, serial: int = 0, issuer_serial: int = 0) -> bytes:
    return (
        varint_field(1, serial)
        + varint_field(2, issuer_serial)
        + bytes_field(3, key)
        + varint_field(4, 1_600_000_000)
        + varint_field(5, 1_700_000_000)
    )


def make_cert_chain() -> tuple[bytes, KeyPair]:
    intermediate = generate_keypair()
    leaf = generate_keypair()
    leaf_details = make_details(leaf.public, serial=1, issuer_serial=0)
    intermediate_details = make_details(intermediate.public, serial=0)
    chain = message_field(
        1, bytes_field(1, leaf_details) + bytes_field(2, sign(intermediate.private, leaf_details))
    ) + message_field(
        2,
        bytes_field(1, intermediate_details)
        + bytes_field(2, sign(intermediate.private, intermediate_details)),
    )
    return chain, intermediate


class Responder:
    """Mirror of the server's side of the handshake, for tests only."""

    def __init__(
        self,
        static_key: KeyPair,
        client_static_public: bytes,
        *,
        prologue: bytes = INTRO_MAGIC,
        cert_chain: bytes | None = None,
    ) -> None:
        self._static = static_key
        self._ephemeral = generate_keypair()
        self._cert_chain = cert_chain if cert_chain is not None else make_cert_chain()[0]
        self._hash = PROTOCOL_NAME
        self._salt = self._hash
        self._enc_key = self._hash
        self._dec_key = self._hash
        self._counter = 0
        self._authenticate(prologue)
        self._authenticate(client_static_public)

    def _authenticate(self, data: bytes) -> None:
        self._hash = sha256(self._hash + data)

    def _mix(self, secret: bytes) -> None:
        expanded = hkdf(secret, 64, b"", self._salt)
        self._salt = expanded[:32]
        self._enc_key = expanded[32:]
        self._dec_key = expanded[32:]
        self._counter = 0

    def _encrypt(self, data: bytes) -> bytes:
        ciphertext = aes_gcm_encrypt(self._enc_key, counter_iv(self._counter), data, self._hash)
        self._counter += 1
        self._authenticate(ciphertext)
        return ciphertext

    def _decrypt(self, data: bytes) -> bytes:
        plaintext = aes_gcm_decrypt(self._dec_key, counter_iv(self._counter), data, self._hash)
        self._counter += 1
        self._authenticate(data)
        return plaintext

    def answer(self, client_hello: bytes) -> bytes:
        message = decode(client_hello)
        assert message.client_hello is not None
        client_key = message.client_hello.ephemeral
        # Only the server's ephemeral is mixed in here: the client's key was mixed
        # during construction, and the client never mixes its own ephemeral.
        self._authenticate(self._ephemeral.public)
        self._mix(dh(self._ephemeral.private, client_key))
        encrypted_static = self._encrypt(self._static.public)
        # The server already knows the client's key from the hello, so it can run the
        # second DH and encrypt the payload with the resulting key.
        self._mix(dh(self._static.private, client_key))
        encrypted_payload = self._encrypt(self._cert_chain)
        hello = ServerHello(
            ephemeral=self._ephemeral.public,
            static=encrypted_static,
            payload=encrypted_payload,
        )
        return encode(HandshakeMessage(server_hello=hello))

    def accept(self, client_finish: bytes) -> bytes:
        message = decode(client_finish)
        assert message.client_finish is not None
        client_key = self._decrypt(message.client_finish.static)
        self._mix(dh(self._ephemeral.private, client_key))
        return self._decrypt(message.client_finish.payload)

    def finish(self) -> NoiseTransport:
        expanded = hkdf(b"", 64, b"", self._salt)
        return NoiseTransport(write_key=expanded[32:], read_key=expanded[:32])


def test_full_handshake_both_sides_agree() -> None:
    client_key = generate_keypair()
    server_static = generate_keypair()

    client = NoiseHandshake(client_key)
    responder = Responder(server_static, client_key.public)

    server_hello = responder.answer(client.client_hello())
    encrypted_static = client.process_server_hello(server_hello)
    client_finish = client.client_finish(b"client-payload", encrypted_static)
    assert responder.accept(client_finish) == b"client-payload"

    client_transport = client.finish()
    server_transport = responder.finish()

    ping = client_transport.encrypt(b"ping")
    assert ping != b"ping"
    assert server_transport.decrypt(ping) == b"ping"
    pong = server_transport.encrypt(b"pong")
    assert client_transport.decrypt(pong) == b"pong"


def test_initial_hash_mixes_prologue_and_own_key() -> None:
    key_pair = generate_keypair()
    client = NoiseHandshake(key_pair)
    expected = sha256(sha256(PROTOCOL_NAME + INTRO_MAGIC) + key_pair.public)
    assert client.hash == expected


def test_tampered_server_static_is_rejected() -> None:
    client_key = generate_keypair()
    server_static = generate_keypair()
    client = NoiseHandshake(client_key)
    responder = Responder(server_static, client_key.public)

    server_hello = bytearray(responder.answer(client.client_hello()))
    server_hello[-1] ^= 0xFF
    with pytest.raises(NoiseError):
        client.process_server_hello(bytes(server_hello))


def test_invalid_certificate_signature_is_rejected() -> None:
    client_key = generate_keypair()
    server_static = generate_keypair()
    intermediate = generate_keypair()
    leaf_details = make_details(generate_keypair().public)
    forged_chain = message_field(
        1,
        bytes_field(1, leaf_details)
        + bytes_field(2, sign(generate_keypair().private, leaf_details)),
    ) + message_field(
        2,
        bytes_field(1, make_details(intermediate.public))
        + bytes_field(2, sign(intermediate.private, make_details(intermediate.public))),
    )
    client = NoiseHandshake(client_key)
    responder = Responder(server_static, client_key.public, cert_chain=forged_chain)
    with pytest.raises(NoiseError):
        client.process_server_hello(responder.answer(client.client_hello()))


def test_cert_chain_parsing() -> None:
    chain_payload, intermediate = make_cert_chain()
    chain = parse_cert_chain(chain_payload)
    details = parse_certificate_details(chain.intermediate)
    assert details.key == intermediate.public
    assert details.serial == 0
    assert details.not_after == 1_700_000_000


def test_transport_rejects_replayed_frame() -> None:
    sender = NoiseTransport(write_key=b"\x01" * 32, read_key=b"\x02" * 32)
    receiver = NoiseTransport(write_key=b"\x02" * 32, read_key=b"\x01" * 32)
    frame = sender.encrypt(b"hello")
    assert receiver.decrypt(frame) == b"hello"
    with pytest.raises(CryptoError):
        receiver.decrypt(frame)


def test_counter_iv_layout() -> None:
    assert counter_iv(0) == bytes(12)
    assert counter_iv(1) == bytes(11) + b"\x01"
    assert counter_iv(0x01020304) == bytes(8) + b"\x01\x02\x03\x04"


def test_transport_counters_are_independent() -> None:
    write_key = b"\x03" * 32
    read_key = b"\x04" * 32
    transport = NoiseTransport(write_key=write_key, read_key=read_key)
    first = transport.encrypt(b"a")
    second = transport.encrypt(b"b")
    assert first[:12] != second[:12] or first != second
    peer = NoiseTransport(write_key=read_key, read_key=write_key)
    assert peer.decrypt(first) == b"a"
    assert peer.decrypt(second) == b"b"
