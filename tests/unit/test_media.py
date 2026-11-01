from __future__ import annotations

import base64
import hashlib
import json

import pytest

from aiowapy.crypto.media import decrypt_media, encrypt_media
from aiowapy.messaging.media import MediaStorage, MediaTransferError
from aiowapy.protocol.media import (
    MEDIA_DOCUMENT,
    MEDIA_IMAGE,
    MediaConnection,
    MediaError,
    MediaInfo,
    build_media_conn_query,
    download_url,
    parse_media_conn,
    upload_path,
    upload_url,
)
from aiowapy.protocol.messages import encode_media, parse_message
from aiowapy.protocol.wabinary import Node


def media_conn_node() -> Node:
    return Node(
        tag="iq",
        attrs={"type": "result"},
        content=[
            Node(
                tag="media_conn",
                attrs={"auth": "token", "ttl": "3600"},
                content=[
                    Node(tag="host", attrs={"hostname": "media1.example"}),
                    Node(tag="host", attrs={"hostname": "media2.example"}),
                ],
            )
        ],
    )


def test_media_conn_query_shape() -> None:
    node = build_media_conn_query("id-1")
    assert node.attrs == {
        "to": "@s.whatsapp.net",
        "type": "set",
        "xmlns": "w:m",
        "id": "id-1",
    }
    assert node.content[0].tag == "media_conn"  # type: ignore[index]


def test_parse_media_conn() -> None:
    connection = parse_media_conn(media_conn_node())
    assert connection.auth == "token"
    assert connection.hosts == ("media1.example", "media2.example")
    assert connection.ttl == 3600
    assert connection.upload_host == "media1.example"


def test_parse_media_conn_requires_auth_and_hosts() -> None:
    with pytest.raises(MediaError):
        parse_media_conn(Node(tag="iq"))
    with pytest.raises(MediaError):
        parse_media_conn(Node(tag="iq", content=[Node(tag="media_conn", attrs={"auth": "x"})]))


def sample_info(**kwargs: object) -> MediaInfo:
    defaults = dict(
        media_type=MEDIA_IMAGE,
        mime_type="image/jpeg",
        url="https://mmg.example/x",
        direct_path="/v/t62/x?ccb=1",
        media_key=b"k" * 32,
        file_sha256=b"a" * 32,
        file_enc_sha256=b"b" * 32,
        file_length=10,
    )
    defaults.update(kwargs)
    return MediaInfo(**defaults)  # type: ignore[arg-type]


def test_upload_url_shape() -> None:
    connection = MediaConnection(auth="auth", hosts=("h1",), ttl=60)
    info = sample_info()
    token = base64.urlsafe_b64encode(info.file_enc_sha256).decode()
    assert upload_path(info) == f"/mms/image/{token}"
    url = upload_url(connection, info)
    assert url.startswith(f"https://h1/mms/image/{token}?auth=auth&token={token}")


def test_download_url_shape() -> None:
    info = sample_info()
    token = base64.urlsafe_b64encode(info.file_enc_sha256).decode()
    url = download_url("h1", info)
    assert url == f"https://h1{info.direct_path}&hash={token}&mms-type=image&__wa-mms="


def test_download_url_requires_absolute_path() -> None:
    with pytest.raises(MediaError):
        download_url("h1", sample_info(direct_path="relative"))


def test_image_message_roundtrip() -> None:
    info = sample_info(caption="look", width=100, height=50, media_key_timestamp=1700000000)
    parsed = parse_message(encode_media(info))
    assert parsed.media is not None
    media = parsed.media
    assert media.media_type == "image"
    assert media.url == info.url
    assert media.mime_type == "image/jpeg"
    assert media.caption == "look"
    assert media.width == 100 and media.height == 50
    assert media.media_key == info.media_key
    assert media.file_sha256 == info.file_sha256
    assert media.direct_path == info.direct_path


def test_document_message_roundtrip() -> None:
    info = sample_info(
        media_type=MEDIA_DOCUMENT,
        mime_type="application/pdf",
        file_name="report.pdf",
        caption="q3",
    )
    parsed = parse_message(encode_media(info))
    assert parsed.media is not None
    assert parsed.media.file_name == "report.pdf"
    assert parsed.media.caption == "q3"
    assert parsed.media.media_type == "document"


def test_audio_message_marks_voice_notes() -> None:
    info = sample_info(media_type="ptt", mime_type="audio/ogg", seconds=4, is_ptt=True)
    parsed = parse_message(encode_media(info))
    assert parsed.media is not None
    assert parsed.media.media_type == "ptt"
    assert parsed.media.is_ptt is True
    assert parsed.media.seconds == 4


class FakeTransport:
    def __init__(self) -> None:
        self.posts: list[tuple[str, bytes, dict[str, str]]] = []
        self.gets: list[str] = []
        self.download_payload = b""
        self.upload_response = json.dumps(
            {"url": "https://mmg.example/blob", "direct_path": "/v/t62/blob"}
        ).encode()

    async def post(self, url: str, data: bytes, headers: dict[str, str]) -> bytes:
        self.posts.append((url, data, headers))
        return self.upload_response

    async def get(self, url: str) -> bytes:
        self.gets.append(url)
        return self.download_payload


class FakeQuerier:
    def __init__(self) -> None:
        self.queries: list[Node] = []

    async def query(self, node: Node, *, timeout: float | None = None) -> Node:
        self.queries.append(node)
        return media_conn_node()


async def test_upload_encrypts_and_returns_location() -> None:
    transport = FakeTransport()
    querier = FakeQuerier()
    storage = MediaStorage(querier, transport, id_factory=lambda: "id")

    plaintext = b"\x89PNG" + b"x" * 100
    info = await storage.upload(plaintext, MEDIA_IMAGE, caption="hi", mime_type="image/png")

    assert info.url == "https://mmg.example/blob"
    assert info.direct_path == "/v/t62/blob"
    assert info.file_length == len(plaintext)
    assert info.caption == "hi"

    url, data, headers = transport.posts[0]
    assert headers["Origin"] == "https://web.whatsapp.com"
    assert base64.urlsafe_b64encode(info.file_enc_sha256).decode() in url
    assert decrypt_media(info.media_key, MEDIA_IMAGE, data) == plaintext
    assert hashlib.sha256(data).digest() == info.file_enc_sha256
    assert len(querier.queries) == 1


async def test_upload_reuses_the_media_connection() -> None:
    transport = FakeTransport()
    querier = FakeQuerier()
    storage = MediaStorage(querier, transport, id_factory=lambda: "id")
    await storage.upload(b"one", MEDIA_IMAGE)
    await storage.upload(b"two", MEDIA_IMAGE)
    assert len(querier.queries) == 1


async def test_upload_rejects_empty_files() -> None:
    storage = MediaStorage(FakeQuerier(), FakeTransport())
    with pytest.raises(MediaTransferError):
        await storage.upload(b"", MEDIA_IMAGE)


async def test_download_verifies_and_decrypts() -> None:
    transport = FakeTransport()
    storage = MediaStorage(FakeQuerier(), transport)
    plaintext = b"hello media"
    media_key = b"\x01" * 32
    encrypted = encrypt_media(media_key, MEDIA_IMAGE, plaintext)
    transport.download_payload = encrypted.payload

    info = MediaInfo(
        media_type=MEDIA_IMAGE,
        mime_type="image/png",
        url="https://mmg.example/blob",
        direct_path="/v/t62/blob",
        media_key=media_key,
        file_sha256=encrypted.file_sha256,
        file_enc_sha256=encrypted.file_enc_sha256,
        file_length=len(plaintext),
    )
    assert await storage.download(info) == plaintext
    assert transport.gets and "mms-type=image" in transport.gets[0]


async def test_download_rejects_a_hash_mismatch() -> None:
    transport = FakeTransport()
    storage = MediaStorage(FakeQuerier(), transport)
    media_key = b"\x02" * 32
    encrypted = encrypt_media(media_key, MEDIA_IMAGE, b"data")
    transport.download_payload = encrypted.payload
    info = MediaInfo(
        media_type=MEDIA_IMAGE,
        mime_type="image/png",
        url="",
        direct_path="/v/t64/blob",
        media_key=media_key,
        file_sha256=b"\x00" * 32,
        file_enc_sha256=encrypted.file_enc_sha256,
        file_length=4,
    )
    with pytest.raises(MediaTransferError, match="file_sha256"):
        await storage.download(info)


async def test_download_requires_key_material() -> None:
    storage = MediaStorage(FakeQuerier(), FakeTransport())
    with pytest.raises(MediaTransferError):
        await storage.download(sample_info(media_key=b"", file_enc_sha256=b""))
