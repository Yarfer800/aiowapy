from __future__ import annotations

import pytest

from wapy.crypto.sender_key import (
    SenderKeyError,
    SenderKeyState,
    decrypt,
    deserialize_state,
    distribution_message,
    encrypt,
    from_distribution,
    pad,
    serialize_state,
    unpad,
    validate_state,
)


def pair() -> tuple[SenderKeyState, SenderKeyState]:
    sender = SenderKeyState.create(key_id=17)
    receiver = from_distribution(distribution_message(sender))
    return sender, receiver


def test_distribution_message_sets_up_the_receiver() -> None:
    sender, receiver = pair()
    assert receiver.key_id == sender.key_id
    assert receiver.chain_key == sender.chain_key
    assert receiver.signing_public == sender.signing_public
    assert receiver.signing_private is None


def test_roundtrip() -> None:
    sender, receiver = pair()
    ciphertext = encrypt(sender, b"hello group")
    assert decrypt(receiver, ciphertext) == b"hello group"


def test_iterations_advance_and_stay_in_sync() -> None:
    sender, receiver = pair()
    first = encrypt(sender, b"one")
    second = encrypt(sender, b"two")
    third = encrypt(sender, b"three")
    assert decrypt(receiver, first) == b"one"
    assert decrypt(receiver, second) == b"two"
    assert decrypt(receiver, third) == b"three"


def test_out_of_order_delivery_uses_stored_keys() -> None:
    sender, receiver = pair()
    first = encrypt(sender, b"one")
    second = encrypt(sender, b"two")
    assert decrypt(receiver, second) == b"two"
    assert decrypt(receiver, first) == b"one"


def test_replaying_an_old_message_is_rejected() -> None:
    sender, receiver = pair()
    first = encrypt(sender, b"one")
    assert decrypt(receiver, first) == b"one"
    with pytest.raises(SenderKeyError):
        decrypt(receiver, first)


def test_wrong_signing_key_is_rejected() -> None:
    sender, _receiver = pair()
    stranger = SenderKeyState.create(key_id=sender.key_id)
    forged = encrypt(stranger, b"not mine")
    receiver = from_distribution(distribution_message(sender))
    with pytest.raises(SenderKeyError, match="signature"):
        decrypt(receiver, forged)


def test_key_id_mismatch_is_rejected() -> None:
    sender = SenderKeyState.create(key_id=1)
    receiver = from_distribution(distribution_message(sender))
    receiver.key_id = 2
    with pytest.raises(SenderKeyError, match="key 1"):
        decrypt(receiver, encrypt(sender, b"x"))


def test_truncated_message_is_rejected() -> None:
    _sender, receiver = pair()
    with pytest.raises(SenderKeyError):
        decrypt(receiver, b"\x33\x00")


def test_unsupported_version_is_rejected() -> None:
    sender, _receiver = pair()
    message = bytearray(encrypt(sender, b"x"))
    message[0] = 0x22
    with pytest.raises(SenderKeyError, match="version"):
        decrypt(from_distribution(distribution_message(sender)), bytes(message))


def test_far_future_iteration_is_rejected() -> None:
    sender, receiver = pair()
    receiver.iteration = 0
    with pytest.raises(SenderKeyError, match="future"):
        receiver.next_message_key(5000)


def test_padding_roundtrip_and_validation() -> None:
    assert unpad(pad(b"abc")) == b"abc"
    with pytest.raises(SenderKeyError):
        unpad(b"")
    with pytest.raises(SenderKeyError):
        unpad(b"abc\x00")


def test_state_survives_serialization() -> None:
    sender, _receiver = pair()
    encrypt(sender, b"one")
    restored = deserialize_state(serialize_state(sender))
    assert restored.key_id == sender.key_id
    assert restored.iteration == sender.iteration
    assert restored.chain_key == sender.chain_key
    assert restored.signing_private == sender.signing_private
    assert restored.message_keys == sender.message_keys
    validate_state(restored)


def test_receiver_state_survives_serialization() -> None:
    _sender, receiver = pair()
    restored = deserialize_state(serialize_state(receiver))
    assert restored.signing_private is None
    validate_state(restored)


def test_encrypt_without_signing_key_fails() -> None:
    _sender, receiver = pair()
    with pytest.raises(SenderKeyError):
        encrypt(receiver, b"x")


def test_create_generates_distinct_keys() -> None:
    first = SenderKeyState.create()
    second = SenderKeyState.create()
    assert first.chain_key != second.chain_key
    assert first.signing_public != second.signing_public
