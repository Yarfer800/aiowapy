"""A WABinary protocol node."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Node:
    """Node with a tag, attributes and content (children, text or binary data)."""

    tag: str
    attrs: dict[str, str] = field(default_factory=dict)
    content: bytes | str | list[Node] | None = None
