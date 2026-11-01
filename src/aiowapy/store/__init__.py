"""Session state storage."""

from __future__ import annotations

from aiowapy.store.sqlite import SCHEMA_VERSION, SessionStore

__all__ = ["SCHEMA_VERSION", "SessionStore"]
