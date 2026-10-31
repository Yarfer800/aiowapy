from __future__ import annotations

import base64

from wapy.errors import WapyError
from wapy.models import (
    MEDIA_AUDIO,
    MEDIA_DOCUMENT,
    MEDIA_IMAGE,
    MEDIA_PTT,
    MEDIA_STICKER,
    MEDIA_VIDEO,
    MediaConnection,
    MediaInfo,
)
from wapy.protocol.stream import child, children
from wapy.protocol.wabinary import Node

S_WHATSAPP_NET = "@s.whatsapp.net"

__all__ = [
    "MEDIA_AUDIO",
    "MEDIA_DOCUMENT",
    "MEDIA_IMAGE",
    "MEDIA_PTT",
    "MEDIA_STICKER",
    "MEDIA_VIDEO",
    "MMS_TYPES",
    "MESSAGE_FIELDS",
    "MediaConnection",
    "MediaError",
    "MediaInfo",
    "build_media_conn_query",
    "download_url",
    "parse_media_conn",
    "upload_path",
    "upload_url",
]

# The `mms-type` used in upload and download paths.
MMS_TYPES: dict[str, str] = {
    MEDIA_IMAGE: "image",
    MEDIA_VIDEO: "video",
    MEDIA_AUDIO: "audio",
    MEDIA_PTT: "audio",
    MEDIA_DOCUMENT: "document",
    MEDIA_STICKER: "sticker",
}

# Message protobuf field that carries each attachment type.
MESSAGE_FIELDS: dict[str, int] = {
    MEDIA_IMAGE: 3,
    MEDIA_PTT: 8,
    MEDIA_DOCUMENT: 7,
    MEDIA_AUDIO: 8,
    MEDIA_VIDEO: 9,
    MEDIA_STICKER: 26,
}


class MediaError(WapyError):
    """Media metadata is incomplete or a media host answered with an error."""


def build_media_conn_query(message_id: str) -> Node:
    return Node(
        tag="iq",
        attrs={"to": S_WHATSAPP_NET, "type": "set", "xmlns": "w:m", "id": message_id},
        content=[Node(tag="media_conn", attrs={})],
    )


def parse_media_conn(node: Node) -> MediaConnection:
    conn = child(node, "media_conn")
    if conn is None:
        raise MediaError("response carries no media_conn node")
    auth = conn.attrs.get("auth")
    if not auth:
        raise MediaError("media_conn carries no auth token")
    hosts = tuple(
        host.attrs["hostname"] for host in children(conn, "host") if host.attrs.get("hostname")
    )
    if not hosts:
        raise MediaError("media_conn carries no hosts")
    try:
        ttl = int(conn.attrs.get("ttl", "0"))
    except ValueError:
        ttl = 0
    return MediaConnection(auth=auth, hosts=hosts, ttl=ttl)


def upload_path(info: MediaInfo) -> str:
    mms_type = MMS_TYPES.get(info.media_type)
    if mms_type is None:
        raise MediaError(f"unknown media type: {info.media_type!r}")
    token = base64.urlsafe_b64encode(info.file_enc_sha256).decode("ascii")
    return f"/mms/{mms_type}/{token}"


def upload_url(connection: MediaConnection, info: MediaInfo) -> str:
    token = base64.urlsafe_b64encode(info.file_enc_sha256).decode("ascii")
    return (
        f"https://{connection.upload_host}{upload_path(info)}?auth={connection.auth}&token={token}"
    )


def download_url(host: str, info: MediaInfo) -> str:
    mms_type = MMS_TYPES.get(info.media_type)
    if mms_type is None:
        raise MediaError(f"unknown media type: {info.media_type!r}")
    if not info.direct_path.startswith("/"):
        raise MediaError(f"direct path must start with a slash: {info.direct_path!r}")
    token = base64.urlsafe_b64encode(info.file_enc_sha256).decode("ascii")
    return f"https://{host}{info.direct_path}&hash={token}&mms-type={mms_type}&__wa-mms="
