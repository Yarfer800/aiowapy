"""ClientPayload: what a companion device declares when it connects.

Field numbers, field order and even the explicit zero values follow the reference
client byte for byte; WhatsApp's server is stricter about this than a protobuf
spec requires, and deviations surface as "client outdated" (405).

Two variants: registration (first connection, carries the device pairing data)
and login (returning device, identifies itself by user JID).
"""

from __future__ import annotations

import hashlib

from wapy.creds import SIGNAL_KEY_PREFIX, DeviceCredentials
from wapy.pb import bytes_field, message_field, varint_field_explicit

PLATFORM_WEB = 14
PLATFORM_BLUE_WEB = 32
CONNECT_TYPE_WIFI_UNKNOWN = 1
CONNECT_REASON_USER_ACTIVATED = 1
DEFAULT_APP_VERSION = (2, 3000, 0)
DEFAULT_COMPANION_VERSION = (10, 15, 7)


def _app_version(version: tuple[int, int, int]) -> bytes:
    primary, secondary, tertiary = version
    return (
        varint_field_explicit(1, primary)
        + varint_field_explicit(2, secondary)
        + varint_field_explicit(3, tertiary)
    )


def encode_user_agent(
    version: tuple[int, int, int] = DEFAULT_APP_VERSION,
    *,
    platform: int = PLATFORM_WEB,
    country: str = "US",
) -> bytes:
    return b"".join(
        (
            varint_field_explicit(1, platform),
            message_field(2, _app_version(version)),
            bytes_field(3, b"000"),
            bytes_field(4, b"000"),
            bytes_field(5, b"0.1"),
            bytes_field(7, b"Desktop"),
            bytes_field(8, b"0.1"),
            varint_field_explicit(10, 0),  # releaseChannel = RELEASE
            bytes_field(11, b"en"),
            bytes_field(12, country.encode()[:2]),
        )
    )


def encode_web_info() -> bytes:
    return varint_field_explicit(4, 0)  # webSubPlatform = WEB_BROWSER


def encode_history_sync_config() -> bytes:
    return b"".join(
        (
            varint_field_explicit(3, 10240),
            varint_field_explicit(4, 1),
            varint_field_explicit(6, 0),
            varint_field_explicit(7, 1),
            varint_field_explicit(8, 1),
            varint_field_explicit(9, 1),
            varint_field_explicit(10, 1),
            varint_field_explicit(11, 1),
            varint_field_explicit(12, 1),
            varint_field_explicit(14, 1),
            varint_field_explicit(15, 0),
        )
    )


def encode_device_props(
    version: tuple[int, int, int] = DEFAULT_COMPANION_VERSION,
    *,
    os_name: str = "Mac OS",
    platform_type: int = 1,
    require_full_sync: bool = False,
) -> bytes:
    return b"".join(
        (
            bytes_field(1, os_name.encode()),
            message_field(2, _app_version(version)),
            varint_field_explicit(3, platform_type),
            varint_field_explicit(4, 1 if require_full_sync else 0),
            message_field(5, encode_history_sync_config()),
        )
    )


def _big_endian(value: int, width: int) -> bytes:
    return value.to_bytes(width, "big")


def encode_pairing_data(
    credentials: DeviceCredentials,
    *,
    version: tuple[int, int, int] = DEFAULT_APP_VERSION,
    os_name: str = "Mac OS",
    device_platform: int = 1,
) -> bytes:
    signed = credentials.signed_pre_key
    build_hash = hashlib.md5(".".join(str(part) for part in version).encode()).digest()
    return b"".join(
        (
            bytes_field(1, _big_endian(credentials.registration_id, 4)),
            bytes_field(2, SIGNAL_KEY_PREFIX),
            bytes_field(3, credentials.identity_public),
            bytes_field(4, _big_endian(signed.key_id, 3)),
            bytes_field(5, signed.key_pair.public),
            bytes_field(6, signed.signature),
            bytes_field(7, build_hash),
            bytes_field(8, encode_device_props(os_name=os_name, platform_type=device_platform)),
        )
    )


def build_registration_payload(
    credentials: DeviceCredentials,
    *,
    version: tuple[int, int, int] = DEFAULT_APP_VERSION,
    country: str = "US",
    os_name: str = "Mac OS",
    platform: int = PLATFORM_WEB,
    device_platform: int = 1,
    push_name: str | None = None,
) -> bytes:
    """Payload for the first connection: declares the device to the server."""
    fields = [
        varint_field_explicit(3, 0),  # passive = false
        message_field(5, encode_user_agent(version, platform=platform, country=country)),
        message_field(6, encode_web_info()),
        varint_field_explicit(12, CONNECT_TYPE_WIFI_UNKNOWN),
        varint_field_explicit(13, CONNECT_REASON_USER_ACTIVATED),
    ]
    if push_name:
        fields.append(bytes_field(7, push_name.encode("utf-8")))
    fields.append(
        message_field(
            19,
            encode_pairing_data(
                credentials, version=version, os_name=os_name, device_platform=device_platform
            ),
        )
    )
    fields.append(varint_field_explicit(33, 0))  # pull = false
    return b"".join(fields)


def build_login_payload(
    user_jid: str,
    *,
    version: tuple[int, int, int] = DEFAULT_APP_VERSION,
    country: str = "US",
    platform: int = PLATFORM_WEB,
    push_name: str | None = None,
) -> bytes:
    """Payload for a returning device: identifies it by user JID."""
    user, _, rest = user_jid.partition("@")
    account, _, device_part = user.partition(":")
    device = int(device_part) if device_part else 0
    fields = [
        varint_field_explicit(1, int(account)),
        varint_field_explicit(3, 1),  # passive = true
        message_field(5, encode_user_agent(version, platform=platform, country=country)),
        message_field(6, encode_web_info()),
        varint_field_explicit(12, CONNECT_TYPE_WIFI_UNKNOWN),
        varint_field_explicit(13, CONNECT_REASON_USER_ACTIVATED),
        varint_field_explicit(18, device),
        varint_field_explicit(24, 1),  # lc: the reference client sets this when unset
        varint_field_explicit(41, 1),  # lidDbMigrated
    ]
    if push_name:
        fields.append(bytes_field(7, push_name.encode("utf-8")))
    fields.append(varint_field_explicit(33, 1))  # pull = true
    return b"".join(fields)
