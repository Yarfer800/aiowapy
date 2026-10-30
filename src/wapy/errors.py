"""Иерархия исключений wapy."""

from __future__ import annotations


class WapyError(Exception):
    """База для всех ошибок библиотеки."""


class StoreError(WapyError):
    """Ошибка хранилища сессии."""


class StoreNotOpenError(StoreError):
    """Хранилище используется до open() или после close()."""
