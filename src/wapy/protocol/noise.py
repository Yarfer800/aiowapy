"""Noise handshake used by WhatsApp Web and the transport mode that follows it.

The pattern is the published `Noise_XX_25519_AESGCM_SHA256` with WhatsApp's
concrete choices: the prologue and the static key are mixed into the handshake
hash before the first message, handshake AEAD uses the running hash as AAD, and
the transport phase uses a 12-byte counter nonce with empty AAD.
"""

from __future__ import annotations

from dataclasses import dataclass

from wapy.crypto.primitives import (
    CryptoError,
    KeyPair,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    dh,
    hkdf,
    sha256,
)
from wapy.crypto.xeddsa import verify
from wapy.errors import WapyError
from wapy.pb import first_bytes, first_int, parse_fields
from wapy.protocol.handshake import (
    ClientFinish,
    ClientHello,
    HandshakeMessage,
    decode,
    encode,
)

PROTOCOL_NAME = b"Noise_XX_25519_AESGCM_SHA256" + b"\x00" * 4
INTRO_MAGIC = b"WA\x06\x03"
TRANSPORT_IV_LEN = 12


class NoiseError(WapyError):
    """Handshake failed or a handshake message could not be verified."""


def counter_iv(counter: int) -> bytes:
    """12-byte IV with the counter in the last four bytes, big-endian."""
    return bytes(8) + counter.to_bytes(4, "big")


class NoiseTransport:
    """Post-handshake state: independent write/read keys and counters."""

    def __init__(self, write_key: bytes, read_key: bytes) -> None:
        self._write_key = write_key
        self._read_key = read_key
        self._write_counter = 0
        self._read_counter = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = counter_iv(self._write_counter)
        self._write_counter += 1
        return aes_gcm_encrypt(self._write_key, iv, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        iv = counter_iv(self._read_counter)
        self._read_counter += 1
        return aes_gcm_decrypt(self._read_key, iv, ciphertext)


@dataclass(frozen=True, slots=True)
class NoiseCertificate:
    serial: int
    issuer_serial: int
    key: bytes
    not_before: int
    not_after: int


@dataclass(frozen=True, slots=True)
class CertChain:
    leaf: bytes
    leaf_signature: bytes
    intermediate: bytes
    intermediate_signature: bytes


def parse_cert_chain(payload: bytes) -> CertChain:
    fields = parse_fields(payload)
    leaf = parse_fields(first_bytes(fields, 1))
    intermediate = parse_fields(first_bytes(fields, 2))
    chain = CertChain(
        leaf=first_bytes(leaf, 1),
        leaf_signature=first_bytes(leaf, 2),
        intermediate=first_bytes(intermediate, 1),
        intermediate_signature=first_bytes(intermediate, 2),
    )
    if not chain.leaf or not chain.intermediate:
        raise NoiseError("incomplete certificate chain")
    return chain


def parse_certificate_details(details: bytes) -> NoiseCertificate:
    fields = parse_fields(details)
    return NoiseCertificate(
        serial=first_int(fields, 1),
        issuer_serial=first_int(fields, 2),
        key=first_bytes(fields, 3),
        not_before=first_int(fields, 4),
        not_after=first_int(fields, 5),
    )


class NoiseHandshake:
    """Client side of the WhatsApp noise handshake."""

    def __init__(
        self,
        key_pair: KeyPair,
        *,
        prologue: bytes = INTRO_MAGIC,
        trusted_root_key: bytes | None = None,
    ) -> None:
        # WhatsApp derives a fresh key pair per connection; the long-lived noise key
        # published in the pairing QR is a different key and is not used here.
        self._key_pair = key_pair
        self._prologue = prologue
        self._trusted_root_key = trusted_root_key
        self._hash = PROTOCOL_NAME
        self._salt = self._hash
        self._enc_key = self._hash
        self._dec_key = self._hash
        self._counter = 0
        self._finish_secret: bytes | None = None
        self._authenticate(prologue)
        self._authenticate(key_pair.public)

    @property
    def hash(self) -> bytes:
        return self._hash

    def _authenticate(self, data: bytes) -> None:
        self._hash = sha256(self._hash + data)

    def _mix_into_key(self, secret: bytes) -> None:
        expanded = hkdf(secret, 64, b"", self._salt)
        self._salt = expanded[:32]
        self._enc_key = expanded[32:]
        self._dec_key = expanded[32:]
        self._counter = 0

    def _encrypt(self, plaintext: bytes) -> bytes:
        ciphertext = aes_gcm_encrypt(
            self._enc_key, counter_iv(self._counter), plaintext, self._hash
        )
        self._counter += 1
        self._authenticate(ciphertext)
        return ciphertext

    def _decrypt(self, ciphertext: bytes) -> bytes:
        plaintext = aes_gcm_decrypt(
            self._dec_key, counter_iv(self._counter), ciphertext, self._hash
        )
        self._counter += 1
        self._authenticate(ciphertext)
        return plaintext

    def client_hello(self) -> bytes:
        return encode(HandshakeMessage(client_hello=ClientHello(ephemeral=self._key_pair.public)))

    def process_server_hello(self, data: bytes) -> bytes:
        """Consume `serverHello` and return the encrypted static key for `clientFinish`."""
        message = decode(data)
        if message.server_hello is None:
            raise NoiseError("expected a serverHello")
        hello = message.server_hello
        if len(hello.ephemeral) != 32:
            raise NoiseError("server ephemeral key must be 32 bytes")

        self._authenticate(hello.ephemeral)
        self._mix_into_key(dh(self._key_pair.private, hello.ephemeral))

        try:
            server_static = self._decrypt(hello.static)
        except CryptoError as exc:
            raise NoiseError("cannot decrypt the server static key") from exc
        if len(server_static) != 32:
            raise NoiseError("server static key must be 32 bytes")
        self._mix_into_key(dh(self._key_pair.private, server_static))

        try:
            certificate = self._decrypt(hello.payload)
        except CryptoError as exc:
            raise NoiseError("cannot decrypt the server certificate") from exc
        self._verify_certificate_chain(certificate)

        encrypted_static = self._encrypt(self._key_pair.public)
        self._mix_into_key(dh(self._key_pair.private, hello.ephemeral))
        return encrypted_static

    def _verify_certificate_chain(self, payload: bytes) -> None:
        chain = parse_cert_chain(payload)
        leaf = parse_certificate_details(chain.leaf)
        intermediate = parse_certificate_details(chain.intermediate)
        if not leaf.key or not intermediate.key:
            raise NoiseError("certificate keys are missing")
        if leaf.issuer_serial != intermediate.serial:
            raise NoiseError("certificate chain does not link leaf to intermediate")
        if not verify(intermediate.key, chain.leaf, chain.leaf_signature):
            raise NoiseError("leaf certificate signature is invalid")
        if self._trusted_root_key is not None and not verify(
            self._trusted_root_key, chain.intermediate, chain.intermediate_signature
        ):
            raise NoiseError("intermediate certificate signature is invalid")

    def client_finish(self, payload: bytes, encrypted_static: bytes) -> bytes:
        message = HandshakeMessage(
            client_finish=ClientFinish(static=encrypted_static, payload=self._encrypt(payload))
        )
        return encode(message)

    def finish(self) -> NoiseTransport:
        expanded = hkdf(b"", 64, b"", self._salt)
        return NoiseTransport(write_key=expanded[:32], read_key=expanded[32:])
