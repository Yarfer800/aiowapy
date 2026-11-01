"""Signal sessions: X3DH establishment and the Double Ratchet.

Implemented from the published specifications, with WhatsApp's concrete choices
(which the reference client implements): a 32-byte 0xFF prefix on the X3DH
secret, HKDF with the `WhisperText` / `WhisperRatchet` / `WhisperMessageKeys`
info strings, AES-CBC with a derived IV, and an 8-byte truncated HMAC over the
version byte, both identity keys and the message body.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

from aiowapy.crypto.primitives import (
    KeyPair,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    dh,
    generate_keypair,
    hkdf,
    hmac_sha256,
)
from aiowapy.crypto.signal_proto import (
    PreKeyWhisperMessage,
    WhisperMessage,
    decode_whisper,
    encode_prekey,
    encode_whisper,
)
from aiowapy.errors import WapyError

SIGNAL_KEY_PREFIX = b"\x05"
X3DH_PREFIX = b"\xff" * 32
PROTOCOL_VERSION = 3
VERSION_BYTE = (PROTOCOL_VERSION << 4) | PROTOCOL_VERSION
MESSAGE_VERSION = bytes([VERSION_BYTE])
MAC_LEN = 8
MAX_SKIP = 2000
ZERO_SALT = bytes(32)

ROOT_INFO = b"WhisperText"
RATCHET_INFO = b"WhisperRatchet"
MESSAGE_KEYS_INFO = b"WhisperMessageKeys"

CHAIN_SEED_BYTE = b"\x01"
CHAIN_STEP_BYTE = b"\x02"


class SessionError(WapyError):
    """The session cannot be established or the message does not verify."""


def signal_key(public: bytes) -> bytes:
    """Normalise a key to the 33-byte `0x05`-prefixed wire form."""
    if len(public) == 33 and public[:1] == SIGNAL_KEY_PREFIX:
        return public
    if len(public) != 32:
        raise SessionError(f"key must be 32 or 33 bytes, got {len(public)}")
    return SIGNAL_KEY_PREFIX + public


def _raw(key: bytes) -> bytes:
    if len(key) == 33 and key[:1] == SIGNAL_KEY_PREFIX:
        return key[1:]
    if len(key) != 32:
        raise SessionError(f"key must be 32 bytes, got {len(key)}")
    return key


@dataclass(slots=True)
class Chain:
    key: bytes | None
    counter: int = -1
    sending: bool = False
    message_keys: dict[int, bytes] = field(default_factory=dict)

    def next_seed(self) -> bytes:
        if self.key is None:
            raise SessionError("chain is closed")
        seed = hmac_sha256(self.key, CHAIN_SEED_BYTE)
        self.key = hmac_sha256(self.key, CHAIN_STEP_BYTE)
        return seed

    def fill(self, counter: int) -> None:
        if self.counter >= counter:
            return
        if counter - self.counter > MAX_SKIP:
            raise SessionError(f"message is too far in the future ({counter - self.counter})")
        while self.counter < counter:
            seed = self.next_seed()
            self.counter += 1
            self.message_keys[self.counter] = seed


@dataclass(slots=True)
class PendingPreKey:
    base_key: bytes
    signed_pre_key_id: int
    pre_key_id: int | None = None


@dataclass(slots=True)
class SessionState:
    local_identity: bytes
    remote_identity: bytes
    root_key: bytes
    our_ephemeral: KeyPair
    remote_ephemeral: bytes | None = None
    previous_counter: int = 0
    chains: dict[bytes, Chain] = field(default_factory=dict)
    pending_pre_key: PendingPreKey | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "local_identity": base64.b64encode(self.local_identity).decode(),
            "remote_identity": base64.b64encode(self.remote_identity).decode(),
            "root_key": base64.b64encode(self.root_key).decode(),
            "our_ephemeral_private": base64.b64encode(self.our_ephemeral.private).decode(),
            "our_ephemeral_public": base64.b64encode(self.our_ephemeral.public).decode(),
            "remote_ephemeral": base64.b64encode(self.remote_ephemeral).decode()
            if self.remote_ephemeral
            else None,
            "previous_counter": self.previous_counter,
            "chains": {
                base64.b64encode(base).decode("ascii"): {
                    "key": base64.b64encode(chain.key).decode() if chain.key else None,
                    "counter": chain.counter,
                    "sending": chain.sending,
                    "message_keys": {
                        str(counter): base64.b64encode(seed).decode()
                        for counter, seed in chain.message_keys.items()
                    },
                }
                for base, chain in self.chains.items()
            },
            "pending_pre_key": None
            if self.pending_pre_key is None
            else {
                "base_key": base64.b64encode(self.pending_pre_key.base_key).decode(),
                "signed_pre_key_id": self.pending_pre_key.signed_pre_key_id,
                "pre_key_id": self.pending_pre_key.pre_key_id,
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SessionState:
        def blob(value: str) -> bytes:
            return base64.b64decode(value)

        raw_pending = data.get("pending_pre_key")
        pending = (
            None
            if not raw_pending
            else PendingPreKey(
                base_key=blob(raw_pending["base_key"]),
                signed_pre_key_id=int(raw_pending["signed_pre_key_id"]),
                pre_key_id=raw_pending.get("pre_key_id"),
            )
        )
        chains: dict[bytes, Chain] = {}
        for base, chain in data.get("chains", {}).items():
            chains[blob(base)] = Chain(
                key=blob(chain["key"]) if chain.get("key") else None,
                counter=int(chain.get("counter", -1)),
                sending=bool(chain.get("sending", False)),
                message_keys={
                    int(counter): blob(seed)
                    for counter, seed in chain.get("message_keys", {}).items()
                },
            )
        remote = data.get("remote_ephemeral")
        return cls(
            local_identity=blob(data["local_identity"]),
            remote_identity=blob(data["remote_identity"]),
            root_key=blob(data["root_key"]),
            our_ephemeral=KeyPair(
                private=blob(data["our_ephemeral_private"]),
                public=blob(data["our_ephemeral_public"]),
            ),
            remote_ephemeral=blob(remote) if remote else None,
            previous_counter=int(data.get("previous_counter", 0)),
            chains=chains,
            pending_pre_key=pending,
        )


def _derive_message_keys(seed: bytes) -> tuple[bytes, bytes, bytes]:
    expanded = hkdf(seed, 80, MESSAGE_KEYS_INFO, ZERO_SALT)
    return expanded[:32], expanded[32:64], expanded[64:80]


def _ratchet(root_key: bytes, secret: bytes) -> tuple[bytes, bytes]:
    expanded = hkdf(secret, 64, RATCHET_INFO, root_key)
    return expanded[:32], expanded[32:]


def _x3dh_secret(*parts: bytes) -> bytes:
    return X3DH_PREFIX + b"".join(parts)


def initiator_session(
    local_identity: KeyPair,
    remote_identity: bytes,
    remote_signed_pre_key: bytes,
    remote_one_time_pre_key: bytes | None = None,
    *,
    signed_pre_key_id: int = 0,
    pre_key_id: int | None = None,
) -> SessionState:
    """Establish a session towards a device, from its prekey bundle."""
    base = generate_keypair()
    parts = [
        dh(local_identity.private, _raw(remote_signed_pre_key)),
        dh(base.private, _raw(remote_identity)),
        dh(base.private, _raw(remote_signed_pre_key)),
    ]
    if remote_one_time_pre_key is not None:
        parts.append(dh(base.private, _raw(remote_one_time_pre_key)))

    expanded = hkdf(_x3dh_secret(*parts), 64, ROOT_INFO, ZERO_SALT)
    root_key = expanded[:32]

    ratchet_ephemeral = generate_keypair()
    state = SessionState(
        local_identity=signal_key(local_identity.public),
        remote_identity=signal_key(remote_identity),
        root_key=root_key,
        our_ephemeral=ratchet_ephemeral,
        remote_ephemeral=_raw(remote_signed_pre_key),
        pending_pre_key=PendingPreKey(
            base_key=base.public,
            signed_pre_key_id=signed_pre_key_id,
            pre_key_id=pre_key_id,
        ),
    )
    new_root, chain_key = _ratchet(
        root_key, dh(ratchet_ephemeral.private, _raw(remote_signed_pre_key))
    )
    state.root_key = new_root
    state.chains[ratchet_ephemeral.public] = Chain(key=chain_key, sending=True)
    return state


def responder_session(
    local_identity: KeyPair,
    our_signed_pre_key: KeyPair,
    *,
    signed_pre_key_id: int,
    their_identity: bytes,
    their_base_key: bytes,
    our_one_time_pre_key: KeyPair | None = None,
) -> SessionState:
    """Establish the same session from the receiving side."""
    parts = [
        dh(our_signed_pre_key.private, _raw(their_identity)),
        dh(local_identity.private, _raw(their_base_key)),
        dh(our_signed_pre_key.private, _raw(their_base_key)),
    ]
    if our_one_time_pre_key is not None:
        parts.append(dh(our_one_time_pre_key.private, _raw(their_base_key)))

    expanded = hkdf(_x3dh_secret(*parts), 64, ROOT_INFO, ZERO_SALT)
    return SessionState(
        local_identity=signal_key(local_identity.public),
        remote_identity=signal_key(their_identity),
        root_key=expanded[:32],
        our_ephemeral=our_signed_pre_key,
        remote_ephemeral=_raw(their_base_key),
        chains={},
    )


def _mac_with_key(state: SessionState, mac_key: bytes, body: bytes, *, incoming: bool) -> bytes:
    first = state.remote_identity if incoming else state.local_identity
    second = state.local_identity if incoming else state.remote_identity
    return hmac_sha256(mac_key, first + second + MESSAGE_VERSION + body)[:MAC_LEN]


def encrypt(state: SessionState, plaintext: bytes) -> bytes:
    """Encrypt one message on the sending chain."""
    chain = state.chains.get(state.our_ephemeral.public)
    if chain is None or not chain.sending:
        raise SessionError("no sending chain")
    seed = chain.next_seed()
    chain.counter += 1
    cipher_key, mac_key, iv = _derive_message_keys(seed)

    body = encode_whisper(
        WhisperMessage(
            ephemeral_key=state.our_ephemeral.public,
            counter=chain.counter,
            previous_counter=state.previous_counter,
            ciphertext=aes_cbc_encrypt(cipher_key, iv, plaintext),
        )
    )
    mac = _mac_with_key(state, mac_key, body, incoming=False)
    message = MESSAGE_VERSION + body + mac
    return message


def decrypt(state: SessionState, message: bytes) -> bytes:
    """Decrypt one incoming message, stepping the ratchet when needed."""
    if len(message) < 1 + MAC_LEN:
        raise SessionError("message is too short")
    if message[0] != VERSION_BYTE:
        raise SessionError(f"unsupported message version: {message[0]:#x}")
    body = message[1:-MAC_LEN]
    mac = message[-MAC_LEN:]
    parsed = decode_whisper(body)

    _maybe_step_ratchet(state, parsed.ephemeral_key, parsed.previous_counter)
    chain = state.chains.get(parsed.ephemeral_key)
    if chain is None:
        raise SessionError("no chain for this message")
    if chain.sending:
        raise SessionError("cannot decrypt on a sending chain")

    chain.fill(parsed.counter)
    seed = chain.message_keys.pop(parsed.counter, None)
    if seed is None:
        raise SessionError("message key already used or never derived")

    cipher_key, mac_key, iv = _derive_message_keys(seed)
    expected = _mac_with_key(state, mac_key, body, incoming=True)
    if not _constant_time_equals(expected, mac):
        raise SessionError("message authentication failed")
    return aes_cbc_decrypt(cipher_key, iv, parsed.ciphertext)


def _constant_time_equals(left: bytes, right: bytes) -> bool:
    import hmac as stdlib_hmac

    return stdlib_hmac.compare_digest(left, right)


def _maybe_step_ratchet(state: SessionState, remote_key: bytes, previous_counter: int) -> None:
    if remote_key in state.chains:
        return

    previous = state.chains.get(state.remote_ephemeral or b"")
    if previous is not None:
        previous.fill(previous_counter)
        previous.key = None  # close the chain

    _calculate_ratchet(state, remote_key, sending=False)

    ours = state.chains.get(state.our_ephemeral.public)
    if ours is not None:
        state.previous_counter = ours.counter
        del state.chains[state.our_ephemeral.public]

    state.our_ephemeral = generate_keypair()
    _calculate_ratchet(state, remote_key, sending=True)
    state.remote_ephemeral = remote_key


def _calculate_ratchet(state: SessionState, remote_key: bytes, *, sending: bool) -> None:
    shared = dh(state.our_ephemeral.private, _raw(remote_key))
    new_root, chain_key = _ratchet(state.root_key, shared)
    base = state.our_ephemeral.public if sending else remote_key
    state.chains[base] = Chain(key=chain_key, sending=sending)
    state.root_key = new_root


def serialize(state: SessionState) -> bytes:
    return json.dumps(state.to_dict(), separators=(",", ":")).encode("utf-8")


def deserialize(blob: bytes) -> SessionState:
    return SessionState.from_dict(json.loads(blob.decode("utf-8")))


def prekey_message(state: SessionState, message: bytes, *, registration_id: int = 0) -> bytes:
    """Wrap a first message in a PreKeyWhisperMessage for the recipient."""
    if state.pending_pre_key is None:
        raise SessionError("session has no pending prekey data")
    return MESSAGE_VERSION + encode_prekey(
        PreKeyWhisperMessage(
            registration_id=registration_id,
            pre_key_id=state.pending_pre_key.pre_key_id,
            signed_pre_key_id=state.pending_pre_key.signed_pre_key_id,
            base_key=signal_key(state.pending_pre_key.base_key),
            identity_key=state.local_identity,
            message=message,
        )
    )
