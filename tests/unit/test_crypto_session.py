from __future__ import annotations

import pytest

from wapy.crypto.primitives import generate_keypair
from wapy.crypto.session import (
    MAX_SKIP,
    SessionError,
    decrypt,
    deserialize,
    encrypt,
    initiator_session,
    responder_session,
    serialize,
    signal_key,
)


class Pair:
    """Both ends of a session, built the way a real client would."""

    def __init__(self) -> None:
        self.alice_identity = generate_keypair()
        self.bob_identity = generate_keypair()
        self.bob_signed = generate_keypair()
        self.bob_one_time = generate_keypair()

        self.alice = initiator_session(
            self.alice_identity,
            signal_key(self.bob_identity.public),
            signal_key(self.bob_signed.public),
            signal_key(self.bob_one_time.public),
            signed_pre_key_id=1,
            pre_key_id=2,
        )
        state = self.alice
        assert state.pending_pre_key is not None
        self.bob = responder_session(
            self.bob_identity,
            self.bob_signed,
            signed_pre_key_id=1,
            their_identity=signal_key(self.alice_identity.public),
            their_base_key=state.pending_pre_key.base_key,
            our_one_time_pre_key=self.bob_one_time,
        )


def test_first_message_from_initiator() -> None:
    p = Pair()
    message = encrypt(p.alice, b"hello")
    assert decrypt(p.bob, message) == b"hello"


def test_bidirectional_conversation() -> None:
    p = Pair()
    assert decrypt(p.bob, encrypt(p.alice, b"one")) == b"one"
    assert decrypt(p.alice, encrypt(p.bob, b"two")) == b"two"
    assert decrypt(p.bob, encrypt(p.alice, b"three")) == b"three"
    assert decrypt(p.alice, encrypt(p.bob, b"four")) == b"four"


def test_many_messages_in_one_direction() -> None:
    p = Pair()
    assert decrypt(p.bob, encrypt(p.alice, b"0")) == b"0"
    for index in range(1, 12):
        payload = f"message-{index}".encode()
        assert decrypt(p.bob, encrypt(p.alice, payload)) == payload


def test_out_of_order_delivery_uses_stored_keys() -> None:
    p = Pair()
    first = encrypt(p.alice, b"first")
    second = encrypt(p.alice, b"second")
    third = encrypt(p.alice, b"third")
    assert decrypt(p.bob, third) == b"third"
    assert decrypt(p.bob, first) == b"first"
    assert decrypt(p.bob, second) == b"second"


def test_replayed_message_is_rejected() -> None:
    p = Pair()
    message = encrypt(p.alice, b"once")
    assert decrypt(p.bob, message) == b"once"
    with pytest.raises(SessionError):
        decrypt(p.bob, message)


def test_tampered_ciphertext_is_rejected() -> None:
    p = Pair()
    message = bytearray(encrypt(p.alice, b"secret"))
    message[-9] ^= 0xFF
    with pytest.raises(SessionError):
        decrypt(p.bob, bytes(message))


def test_tampered_mac_is_rejected() -> None:
    p = Pair()
    message = bytearray(encrypt(p.alice, b"secret"))
    message[-1] ^= 0xFF
    with pytest.raises(SessionError):
        decrypt(p.bob, bytes(message))


def test_unknown_version_is_rejected() -> None:
    p = Pair()
    message = bytearray(encrypt(p.alice, b"x"))
    message[0] = 0x44
    with pytest.raises(SessionError):
        decrypt(p.bob, bytes(message))


def test_state_survives_serialization() -> None:
    p = Pair()
    restored = deserialize(serialize(p.bob))
    assert decrypt(restored, encrypt(p.alice, b"after-restart")) == b"after-restart"


def test_serialized_state_carries_no_plaintext() -> None:
    p = Pair()
    encrypt(p.alice, b"super-secret-plaintext")
    assert b"super-secret-plaintext" not in serialize(p.bob)


def test_responder_needs_no_sending_chain_before_first_message() -> None:
    p = Pair()
    with pytest.raises(SessionError):
        encrypt(p.bob, b"too-early")


def test_skip_limit_is_enforced() -> None:
    p = Pair()
    message = encrypt(p.alice, b"first")
    assert decrypt(p.bob, message) == b"first"
    for _ in range(MAX_SKIP + 5):
        encrypt(p.alice, b"filler")
    with pytest.raises(SessionError):
        decrypt(p.bob, encrypt(p.alice, b"too-far"))


def test_signal_key_normalises_prefix() -> None:
    key = generate_keypair().public
    assert signal_key(key) == b"\x05" + key
    assert signal_key(b"\x05" + key) == b"\x05" + key
    with pytest.raises(SessionError):
        signal_key(b"\x01" * 31)
