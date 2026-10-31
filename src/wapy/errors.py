"""Exception hierarchy for wapy."""

from __future__ import annotations


class WapyError(Exception):
    """Base class for all library errors."""


class StoreError(WapyError):
    """Session store error."""


class StoreNotOpenError(StoreError):
    """Store is used before open() or after close()."""
