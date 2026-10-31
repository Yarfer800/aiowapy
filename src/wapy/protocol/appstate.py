from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field

from wapy.crypto.primitives import aes_cbc_decrypt, aes_cbc_encrypt, hkdf, hmac_sha256
from wapy.errors import WapyError
from wapy.pb import (
    ProtobufError,
    bytes_field,
    first_bytes,
    first_int,
    message_field,
    parse_fields,
    varint_field,
    varint_field_explicit,
)
from wapy.protocol.stream import child, children
from wapy.protocol.wabinary import Node

S_WHATSAPP_NET = "@s.whatsapp.net"

CRITICAL_BLOCK = "critical_block"
CRITICAL_UNBLOCK_LOW = "critical_unblock_low"
REGULAR = "regular"
REGULAR_HIGH = "regular_high"
REGULAR_LOW = "regular_low"
ALL_COLLECTIONS = (
    CRITICAL_BLOCK,
    CRITICAL_UNBLOCK_LOW,
    REGULAR_HIGH,
    REGULAR,
    REGULAR_LOW,
)

INDEX_CONTACT = "contact"
INDEX_LID_CONTACT = "lid_contact"
INDEX_MUTE = "mute"
INDEX_PIN = "pin_v1"
INDEX_ARCHIVE = "archive"
INDEX_MARK_READ = "markChatAsRead"
INDEX_PUSH_NAME = "setting_pushName"
INDEX_LOCALE = "setting_locale"
INDEX_UNARCHIVE_CHATS = "setting_unarchiveChats"
INDEX_STAR = "star"
INDEX_DELETE_CHAT = "deleteChat"

MUTATION_SET = "set"
MUTATION_REMOVE = "remove"
OPERATION_CODES = {MUTATION_SET: 0, MUTATION_REMOVE: 1}

EXPAND_INFO = b"WhatsApp Mutation Keys"
LTHASH_INFO = b"WhatsApp Patch Integrity"
LTHASH_SIZE = 128
VALUE_MAC_LEN = 32

_FIELD_SYNC_VERSION = 1
_FIELD_PATCH_MUTATIONS = 2
_FIELD_PATCH_EXTERNAL = 3
_FIELD_PATCH_SNAPSHOT_MAC = 4
_FIELD_PATCH_MAC = 5
_FIELD_PATCH_KEY_ID = 6
_FIELD_MUTATION_OPERATION = 1
_FIELD_MUTATION_RECORD = 2
_FIELD_RECORD_INDEX = 1
_FIELD_RECORD_VALUE = 2
_FIELD_RECORD_KEY_ID = 3
_FIELD_BLOB = 1
_FIELD_KEY_ID_INNER = 1
_FIELD_ACTION_INDEX = 1
_FIELD_ACTION_VALUE = 2
_FIELD_ACTION_VERSION = 4
_FIELD_SNAPSHOT_RECORDS = 2
_FIELD_SNAPSHOT_MAC = 3


class AppStateError(WapyError):
    """App state data is malformed or fails verification."""


@dataclass(frozen=True, slots=True)
class AppStateKeys:
    index: bytes
    value_encryption: bytes
    value_mac: bytes
    snapshot_mac: bytes
    patch_mac: bytes


def expand_keys(key_data: bytes) -> AppStateKeys:
    if len(key_data) != 32:
        raise AppStateError(f"app state key must be 32 bytes, got {len(key_data)}")
    expanded = hkdf(key_data, 160, EXPAND_INFO, bytes(32))
    return AppStateKeys(
        index=expanded[0:32],
        value_encryption=expanded[32:64],
        value_mac=expanded[64:96],
        snapshot_mac=expanded[96:128],
        patch_mac=expanded[128:160],
    )


def content_mac(operation: str, content: bytes, key_id: bytes, key: bytes) -> bytes:
    """Value MAC: SHA-512 HMAC over the operation, key id and ciphertext."""
    if operation not in OPERATION_CODES:
        raise AppStateError(f"unknown mutation operation: {operation!r}")
    data = (
        bytes((OPERATION_CODES[operation] + 1,)) + key_id + content + len(key_id).to_bytes(8, "big")
    )
    digest = hmac.new(key, data, hashlib.sha512).digest()
    return digest[:VALUE_MAC_LEN]


def index_mac(index: tuple[str, ...], key: bytes) -> bytes:
    payload = _index_json(index)
    return hmac_sha256(key, payload)


def patch_mac(
    snapshot_mac: bytes, value_macs: list[bytes], version: int, name: str, key: bytes
) -> bytes:
    data = snapshot_mac + b"".join(value_macs) + version.to_bytes(8, "big") + name.encode()
    return hmac_sha256(key, data)


def snapshot_mac(digest: bytes, version: int, name: str, key: bytes) -> bytes:
    data = digest + version.to_bytes(8, "big") + name.encode()
    return hmac_sha256(key, data)


def lthash_subtract_then_add(
    base: bytes, *, subtract: list[bytes] | None = None, add: list[bytes] | None = None
) -> bytes:
    """WhatsApp's additive integrity hash: 128 bytes of little-endian 16-bit words."""
    if len(base) != LTHASH_SIZE:
        raise AppStateError(f"integrity hash must be {LTHASH_SIZE} bytes")
    state = bytearray(base)
    for item in subtract or []:
        _pointwise(state, hkdf(item, LTHASH_SIZE, LTHASH_INFO, bytes(32)), subtract=True)
    for item in add or []:
        _pointwise(state, hkdf(item, LTHASH_SIZE, LTHASH_INFO, bytes(32)), subtract=False)
    return bytes(state)


def _pointwise(base: bytearray, value: bytes, *, subtract: bool) -> None:
    for offset in range(0, LTHASH_SIZE, 2):
        current = int.from_bytes(base[offset : offset + 2], "little")
        delta = int.from_bytes(value[offset : offset + 2], "little")
        result = (current - delta if subtract else current + delta) & 0xFFFF
        base[offset : offset + 2] = result.to_bytes(2, "little")


def _index_json(index: tuple[str, ...]) -> bytes:
    if not index:
        raise AppStateError("a mutation needs at least one index entry")
    return json.dumps(list(index), separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True, slots=True)
class RawMutation:
    """A mutation as it sits in a patch: MACs and ciphertext, nothing readable."""

    operation: str
    index_mac: bytes
    blob: bytes
    key_id: bytes

    @property
    def value_mac(self) -> bytes:
        return self.blob[-VALUE_MAC_LEN:]


@dataclass(frozen=True, slots=True)
class DecodedMutation:
    operation: str
    index: tuple[str, ...]
    value: bytes
    key_id: bytes
    index_mac: bytes
    value_mac: bytes
    version: int = 0

    @property
    def is_remove(self) -> bool:
        return self.operation == MUTATION_REMOVE

    @property
    def timestamp(self) -> int:
        if not self.value:
            return 0
        try:
            return first_int(parse_fields(self.value), 1)
        except ProtobufError:
            return 0


def parse_mutation(raw: bytes) -> RawMutation:
    fields = parse_fields(raw)
    operation_code = first_int(fields, _FIELD_MUTATION_OPERATION)
    operation = MUTATION_REMOVE if operation_code == 1 else MUTATION_SET
    record = parse_fields(first_bytes(fields, _FIELD_MUTATION_RECORD))
    index = parse_fields(first_bytes(record, _FIELD_RECORD_INDEX))
    value = parse_fields(first_bytes(record, _FIELD_RECORD_VALUE))
    key_id = parse_fields(first_bytes(record, _FIELD_RECORD_KEY_ID))
    blob = first_bytes(value, _FIELD_BLOB)
    return RawMutation(
        operation=operation,
        index_mac=first_bytes(index, _FIELD_BLOB),
        blob=blob,
        key_id=first_bytes(key_id, _FIELD_KEY_ID_INNER),
    )


def decode_mutation(
    raw: RawMutation, keys: AppStateKeys, *, verify: bool = True
) -> DecodedMutation:
    if len(raw.blob) <= 16 + VALUE_MAC_LEN:
        raise AppStateError("mutation value is too short")
    content = raw.blob[:-VALUE_MAC_LEN]
    received_mac = raw.blob[-VALUE_MAC_LEN:]
    if verify:
        expected = content_mac(raw.operation, content, raw.key_id, keys.value_mac)
        if not hmac.compare_digest(expected, received_mac):
            raise AppStateError("mutation value MAC does not match")
    iv, ciphertext = content[:16], content[16:]
    try:
        action = parse_fields(aes_cbc_decrypt(keys.value_encryption, iv, ciphertext))
    except Exception as exc:
        raise AppStateError("mutation content cannot be decrypted") from exc
    index_bytes = first_bytes(action, _FIELD_ACTION_INDEX)
    if verify and not hmac.compare_digest(hmac_sha256(keys.index, index_bytes), raw.index_mac):
        raise AppStateError("mutation index MAC does not match")
    try:
        index = tuple(str(part) for part in json.loads(index_bytes.decode("utf-8")))
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise AppStateError("mutation index is not valid JSON") from exc
    return DecodedMutation(
        operation=raw.operation,
        index=index,
        value=first_bytes(action, _FIELD_ACTION_VALUE),
        key_id=raw.key_id,
        index_mac=raw.index_mac,
        value_mac=received_mac,
        version=first_int(action, _FIELD_ACTION_VERSION),
    )


def encode_mutation(
    operation: str,
    index: tuple[str, ...],
    key_id: bytes,
    keys: AppStateKeys,
    *,
    value: bytes = b"",
    version: int = 0,
) -> bytes:
    index_bytes = _index_json(index)
    payload = bytes_field(_FIELD_ACTION_INDEX, index_bytes)
    if value:
        payload += bytes_field(_FIELD_ACTION_VALUE, value)
    payload += varint_field_explicit(_FIELD_ACTION_VERSION, version)
    iv = secrets.token_bytes(16)
    content = iv + aes_cbc_encrypt(keys.value_encryption, iv, payload)
    mac = content_mac(operation, content, key_id, keys.value_mac)
    record = message_field(
        _FIELD_RECORD_INDEX, bytes_field(_FIELD_BLOB, hmac_sha256(keys.index, index_bytes))
    )
    record += message_field(_FIELD_RECORD_VALUE, bytes_field(_FIELD_BLOB, content + mac))
    record += message_field(_FIELD_RECORD_KEY_ID, bytes_field(_FIELD_KEY_ID_INNER, key_id))
    mutation = varint_field(_FIELD_MUTATION_OPERATION, OPERATION_CODES[operation])
    return mutation + message_field(_FIELD_MUTATION_RECORD, record)


@dataclass(frozen=True, slots=True)
class ParsedPatch:
    version: int
    mutations: list[RawMutation] = field(default_factory=list)
    snapshot_mac: bytes = b""
    patch_mac: bytes = b""
    key_id: bytes = b""
    external: bytes = b""

    @property
    def value_macs(self) -> list[bytes]:
        return [
            mutation.value_mac for mutation in self.mutations if mutation.operation == MUTATION_SET
        ]


@dataclass(frozen=True, slots=True)
class PatchList:
    name: str
    version: int
    patches: list[ParsedPatch] = field(default_factory=list)
    has_more_patches: bool = False


def parse_patch(raw: bytes) -> ParsedPatch:
    fields = parse_fields(raw)
    version = parse_fields(first_bytes(fields, _FIELD_SYNC_VERSION))
    key_id = parse_fields(first_bytes(fields, _FIELD_PATCH_KEY_ID))
    mutations: list[RawMutation] = []
    for item in _all_bytes(fields, _FIELD_PATCH_MUTATIONS):
        mutations.append(parse_mutation(item))
    return ParsedPatch(
        version=first_int(version, _FIELD_SYNC_VERSION),
        mutations=mutations,
        snapshot_mac=first_bytes(fields, _FIELD_PATCH_SNAPSHOT_MAC),
        patch_mac=first_bytes(fields, _FIELD_PATCH_MAC),
        key_id=first_bytes(key_id, _FIELD_KEY_ID_INNER),
        external=first_bytes(fields, _FIELD_PATCH_EXTERNAL),
    )


def build_patch(
    mutations: list[bytes],
    *,
    snapshot_mac_value: bytes,
    key_id: bytes,
    patch_mac_value: bytes,
    version: int = 0,
) -> bytes:
    body = message_field(_FIELD_SYNC_VERSION, varint_field(_FIELD_SYNC_VERSION, version))
    body += b"".join(message_field(_FIELD_PATCH_MUTATIONS, item) for item in mutations)
    body += bytes_field(_FIELD_PATCH_SNAPSHOT_MAC, snapshot_mac_value)
    body += bytes_field(_FIELD_PATCH_MAC, patch_mac_value)
    body += message_field(_FIELD_PATCH_KEY_ID, bytes_field(_FIELD_KEY_ID_INNER, key_id))
    return body


def parse_patch_list(node: Node) -> PatchList:
    """Decode the `<sync><collection>` answer."""
    collection = child(node, "sync")
    collection = child(collection, "collection") if collection is not None else None
    if collection is None:
        raise AppStateError("response carries no collection node")
    name = collection.attrs.get("name", "")
    try:
        version = int(collection.attrs.get("version", "0"))
    except ValueError:
        version = 0
    patches: list[ParsedPatch] = []
    patches_node = child(collection, "patches")
    if patches_node is not None:
        for item in children(patches_node, "patch"):
            if isinstance(item.content, bytes):
                patches.append(parse_patch(item.content))
    has_more = collection.attrs.get("has_more_patches") == "true"
    return PatchList(name=name, version=version, patches=patches, has_more_patches=has_more)


def build_sync_request(name: str, *, version: int | None = None, snapshot: bool = False) -> Node:
    attrs = {"name": name, "return_snapshot": "true" if snapshot else "false"}
    if not snapshot and version is not None:
        attrs["version"] = str(version)
    return Node(
        tag="iq",
        attrs={"to": S_WHATSAPP_NET, "type": "set", "xmlns": "w:sync:app:state"},
        content=[Node(tag="sync", attrs={}, content=[Node(tag="collection", attrs=attrs)])],
    )


def build_patch_push(name: str, version: int, encoded_patch: bytes) -> Node:
    return Node(
        tag="iq",
        attrs={"to": S_WHATSAPP_NET, "type": "set", "xmlns": "w:sync:app:state"},
        content=[
            Node(
                tag="sync",
                attrs={},
                content=[
                    Node(
                        tag="collection",
                        attrs={
                            "name": name,
                            "version": str(version),
                            "return_snapshot": "false",
                        },
                        content=[Node(tag="patch", attrs={}, content=encoded_patch)],
                    )
                ],
            )
        ],
    )


def _all_bytes(fields: dict[int, list[object]], number: int) -> list[bytes]:
    return [item for item in fields.get(number, []) if isinstance(item, bytes)]


# --- SyncActionValue builders and parser ------------------------------------

_FIELD_STAR = 2
_FIELD_CONTACT = 3
_FIELD_MUTE = 4
_FIELD_PIN = 5
_FIELD_PUSH_NAME = 7
_FIELD_LOCALE = 16
_FIELD_ARCHIVE = 17
_FIELD_MARK_READ = 20
_FIELD_UNARCHIVE_CHATS = 23


@dataclass(frozen=True, slots=True)
class SyncAction:
    """One entry of `SyncActionValue`: the field number plus that field's body."""

    field: int
    body: bytes

    def encode(self, timestamp_ms: int) -> bytes:
        payload = varint_field(1, timestamp_ms) + bytes_field(self.field, self.body)
        return payload


def mute_action(muted: bool, *, until_ms: int | None = None) -> SyncAction:
    end = until_ms if until_ms is not None else (-1 if muted else None)
    body = varint_field_explicit(1, 1 if muted else 0) + _int64_field(2, end)
    return SyncAction(_FIELD_MUTE, body)


def pin_action(pinned: bool) -> SyncAction:
    return SyncAction(_FIELD_PIN, varint_field_explicit(1, 1 if pinned else 0))


def push_name_action(name: str) -> SyncAction:
    return SyncAction(_FIELD_PUSH_NAME, bytes_field(1, name.encode("utf-8")))


def contact_action(*, full_name: str | None = None, first_name: str | None = None) -> SyncAction:
    body = b""
    if full_name:
        body += bytes_field(1, full_name.encode("utf-8"))
    if first_name:
        body += bytes_field(2, first_name.encode("utf-8"))
    return SyncAction(_FIELD_CONTACT, body)


def archive_action(archived: bool, *, last_message_ts: int | None = None) -> SyncAction:
    body = varint_field_explicit(1, 1 if archived else 0)
    if last_message_ts is not None:
        body += message_field(2, _message_range(last_message_ts))
    return SyncAction(_FIELD_ARCHIVE, body)


def read_action(read: bool, *, last_message_ts: int | None = None) -> SyncAction:
    body = varint_field_explicit(1, 1 if read else 0)
    if last_message_ts is not None:
        body += message_field(2, _message_range(last_message_ts))
    return SyncAction(_FIELD_MARK_READ, body)


def unarchive_chats_action(unarchive: bool) -> SyncAction:
    return SyncAction(_FIELD_UNARCHIVE_CHATS, varint_field_explicit(1, 1 if unarchive else 0))


def locale_action(locale: str) -> SyncAction:
    return SyncAction(_FIELD_LOCALE, bytes_field(1, locale.encode("utf-8")))


def _message_range(timestamp: int) -> bytes:
    return varint_field(1, timestamp)


def _int64_field(number: int, value: int | None) -> bytes:
    if value is None:
        return b""
    encoded = value if value >= 0 else value + (1 << 64)
    return varint_field_explicit(number, encoded)


@dataclass(frozen=True, slots=True)
class ActionValue:
    """What we understand of a `SyncActionValue`; unknown fields are ignored."""

    timestamp: int = 0
    mute: tuple[bool, int | None] | None = None
    pin: bool | None = None
    push_name: str | None = None
    contact: tuple[str | None, str | None] | None = None
    archive: bool | None = None
    mark_read: bool | None = None
    unarchive_chats: bool | None = None
    locale: str | None = None


def parse_action_value(raw: bytes) -> ActionValue:
    fields = parse_fields(raw)

    def nested(number: int) -> dict[int, list[object]] | None:
        blob = first_bytes(fields, number)
        return parse_fields(blob) if blob else None

    mute = nested(4)
    pin = nested(5)
    push = nested(7)
    contact = nested(3)
    archive = nested(17)
    mark_read = nested(20)
    unarchive = nested(23)
    locale = nested(16)
    try:
        timestamp = first_int(fields, 1)
    except ProtobufError:
        timestamp = 0
    return ActionValue(
        timestamp=timestamp,
        mute=(bool(first_int(mute, 1)), _optional_int(mute, 2)) if mute else None,
        pin=bool(first_int(pin, 1)) if pin else None,
        push_name=_text(push, 1) if push else None,
        contact=(_text(contact, 1), _text(contact, 2)) if contact else None,
        archive=bool(first_int(archive, 1)) if archive else None,
        mark_read=bool(first_int(mark_read, 1)) if mark_read else None,
        unarchive_chats=bool(first_int(unarchive, 1)) if unarchive else None,
        locale=_text(locale, 1) if locale else None,
    )


def _optional_int(fields: dict[int, list[object]] | None, number: int) -> int | None:
    if fields is None or number not in fields:
        return None
    return _signed(first_int(fields, number))


def _signed(value: int) -> int:
    """int64 fields are varints on the wire; negative values arrive as 2^64 - n."""
    return value - (1 << 64) if value >= 1 << 63 else value


def _text(fields: dict[int, list[object]] | None, number: int) -> str | None:
    if fields is None:
        return None
    blob = first_bytes(fields, number)
    return blob.decode("utf-8", errors="replace") if blob else None


def collection_name(node: Node) -> str:
    sync = child(node, "sync")
    collection = child(sync, "collection") if sync is not None else None
    return collection.attrs.get("name", "") if collection is not None else ""
