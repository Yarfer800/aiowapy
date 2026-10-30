from __future__ import annotations

from pathlib import Path

import pytest

from wapy import WapyError
from wapy.errors import StoreError
from wapy.store import SessionStore


async def test_load_creds_returns_none_when_empty(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        assert await store.load_creds() is None
    finally:
        await store.close()


async def test_creds_roundtrip(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        creds = {
            "registration_id": 1234,
            "me": {"id": "491234567890:3@s.whatsapp.net"},
            "noise_key": "base64+payload",
            "signal_identities": {"491234567890": {"key": "abc", "trusted": True}},
        }
        await store.save_creds(creds)
        assert await store.load_creds() == creds
    finally:
        await store.close()


async def test_save_creds_replaces_previous_value(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        await store.save_creds({"registration_id": 1})
        await store.save_creds({"registration_id": 2})
        assert await store.load_creds() == {"registration_id": 2}
    finally:
        await store.close()


async def test_save_creds_rejects_non_json_value(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        with pytest.raises(TypeError):
            await store.save_creds({"noise_key": b"\x00\x01"})
        assert await store.load_creds() is None
    finally:
        await store.close()


async def test_clear_creds(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "bot.session")
    await store.open()
    try:
        await store.save_creds({"registration_id": 7})
        await store.clear_creds()
        assert await store.load_creds() is None
    finally:
        await store.close()


def test_store_error_is_wapy_error() -> None:
    assert issubclass(StoreError, WapyError)
