from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import time
import urllib.request
from collections.abc import Callable
from dataclasses import replace
from typing import Protocol

from wapy.crypto.media import decrypt_media, encrypt_media
from wapy.errors import WapyError
from wapy.messaging.real import NodeQuerier
from wapy.protocol.media import (
    MediaConnection,
    MediaInfo,
    build_media_conn_query,
    download_url,
    parse_media_conn,
    upload_url,
)

MEDIA_CONN_TTL = 300.0
DEFAULT_TIMEOUT = 60.0
ORIGIN = "https://web.whatsapp.com"


class MediaTransferError(WapyError):
    """An upload or download could not be completed."""


class MediaTransport(Protocol):
    """The HTTP half: separated so tests never touch the network."""

    async def post(self, url: str, data: bytes, headers: dict[str, str]) -> bytes: ...

    async def get(self, url: str) -> bytes: ...


class UrllibMediaTransport:
    """Blocking urllib calls pushed into a thread; no extra dependency needed."""

    def __init__(self, *, timeout: float = DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout

    async def post(self, url: str, data: bytes, headers: dict[str, str]) -> bytes:
        return await asyncio.to_thread(self._post, url, data, headers)

    async def get(self, url: str) -> bytes:
        return await asyncio.to_thread(self._get, url)

    def _post(self, url: str, data: bytes, headers: dict[str, str]) -> bytes:
        request = urllib.request.Request(url, data=data, method="POST", headers=headers)
        return self._read(request)

    def _get(self, url: str) -> bytes:
        request = urllib.request.Request(url, headers={"Origin": ORIGIN}, method="GET")
        return self._read(request)

    def _read(self, request: urllib.request.Request) -> bytes:
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                payload: bytes = response.read()
                return payload
        except Exception as exc:  # urllib raises a wide family of errors
            raise MediaTransferError(f"media host rejected the request: {exc}") from exc


class MediaStorage:
    """Uploads and downloads attachments, caching the media host list."""

    def __init__(
        self,
        querier: NodeQuerier,
        transport: MediaTransport,
        *,
        clock: Callable[[], float] = time.monotonic,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._querier = querier
        self._transport = transport
        self._clock = clock
        self._new_id = id_factory or (lambda: secrets.token_hex(4))
        self._connection: MediaConnection | None = None
        self._expires_at = 0.0

    async def connection(self, *, refresh: bool = False) -> MediaConnection:
        if not refresh and self._connection is not None and self._clock() < self._expires_at:
            return self._connection
        response = await self._querier.query(build_media_conn_query(self._new_id()))
        connection = parse_media_conn(response)
        self._connection = connection
        self._expires_at = self._clock() + (connection.ttl or MEDIA_CONN_TTL)
        return connection

    async def upload(
        self,
        plaintext: bytes,
        media_type: str,
        *,
        caption: str | None = None,
        file_name: str | None = None,
        mime_type: str = "application/octet-stream",
        seconds: int | None = None,
        width: int | None = None,
        height: int | None = None,
    ) -> MediaInfo:
        if not plaintext:
            raise MediaTransferError("refusing to upload an empty file")
        media_key = secrets.token_bytes(32)
        encrypted = encrypt_media(media_key, media_type, plaintext)
        info = MediaInfo(
            media_type=media_type,
            mime_type=mime_type,
            url="",
            direct_path="",
            media_key=media_key,
            file_sha256=encrypted.file_sha256,
            file_enc_sha256=encrypted.file_enc_sha256,
            file_length=len(plaintext),
            caption=caption,
            file_name=file_name,
            seconds=seconds,
            width=width,
            height=height,
            is_ptt=media_type == "ptt",
        )
        connection = await self.connection()
        body = await self._transport.post(
            upload_url(connection, info),
            encrypted.payload,
            {"Origin": ORIGIN, "Referer": ORIGIN + "/"},
        )
        url, direct_path = _parse_upload_response(body)
        return replace(info, url=url, direct_path=direct_path)

    async def download(self, info: MediaInfo) -> bytes:
        if not info.media_key or not info.file_enc_sha256:
            raise MediaTransferError("the media description carries no key material")
        connection = await self.connection()
        url = download_url(connection.upload_host, info)
        payload = await self._transport.get(url)
        plaintext = decrypt_media(info.media_key, info.media_type, payload)
        if info.file_sha256 and hashlib.sha256(plaintext).digest() != info.file_sha256:
            raise MediaTransferError("downloaded file does not match file_sha256")
        return plaintext


def _parse_upload_response(body: bytes) -> tuple[str, str]:
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise MediaTransferError("upload response is not valid JSON") from exc
    if not isinstance(data, dict):
        raise MediaTransferError("upload response is not an object")
    url = data.get("url")
    direct_path = data.get("direct_path")
    if not isinstance(url, str) or not isinstance(direct_path, str):
        raise MediaTransferError("upload response has no url or direct_path")
    return url, direct_path
