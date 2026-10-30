"""Узел протокола WABinary."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Node:
    """Узел: тег, атрибуты и содержимое (дети, текст или бинарные данные)."""

    tag: str
    attrs: dict[str, str] = field(default_factory=dict)
    content: bytes | str | list[Node] | None = None
