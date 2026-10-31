from __future__ import annotations

import base64
from dataclasses import dataclass

from wapy.errors import WapyError
from wapy.protocol.stream import child, children
from wapy.protocol.wabinary import Node

S_WHATSAPP_NET = "@s.whatsapp.net"

MEDIA_IMAGE = "image"
MEDIA_VIDEO = "video"
MEDIA_AUDIO = "audio"
MEDIA_PTT = "ptt"
MEDIA_DOCUMENT = "document"
MEDIA_STICKER = "sticker"

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
    MEDIA_DOCUMENT: 7,
    MEDIA_AUDIO: 8,
    MEDIA_VIDEO: 9,
    MEDIA_STICKER: 26,
}


class MediaError(WapyError):
    """Media metadata is incomplete or a media host answered with an error."""


@dataclass(frozen=True, slots=True)
class MediaInfo:
    media_type: str
    mime_type: str
    url: str
    direct_path: str
    media_key: bytes
    file_sha256: bytes
    file_enc_sha256: bytes
    file_length: int
    caption: str | None = None
    file_name: str | None = None
    seconds: int | None = None
    width: int | None = None
    height: int | None = None
    is_ptt: bool = False
    media_key_timestamp: int | None = None


@dataclass(frozen=True, slots=True)
class MediaConnection:
    auth: str
    hosts: tuple[str, ...]
    ttl: int

    @property
    def upload_host(self) -> str:
        if not self.hosts:
            raise MediaError("the server returned no media hosts")
        return self.hosts[0]


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
