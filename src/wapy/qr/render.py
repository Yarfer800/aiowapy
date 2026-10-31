"""Rendering a QR matrix as terminal text or PNG bytes.

No image library is involved: PNG is a small, well-defined container, and a
grayscale image needs three chunks.
"""

from __future__ import annotations

import struct
import zlib

from wapy.qr.encoder import QrCode

_LIGHT = 255
_DARK = 0


def _pixel_is_dark(qr: QrCode, x: int, y: int, scale: int, border: int) -> bool:
    module_x = x // scale - border
    module_y = y // scale - border
    if 0 <= module_x < qr.size and 0 <= module_y < qr.size:
        return qr.modules[module_y][module_x]
    return False


def render_ascii(qr: QrCode, *, border: int = 2, inverted: bool = False) -> str:
    """Two-character blocks keep the symbol square in monospace terminals."""
    dark, light = ("██", "  ") if not inverted else ("  ", "██")
    rows: list[str] = []
    for y in range(-border, qr.size + border):
        cells: list[str] = []
        for x in range(-border, qr.size + border):
            inside = 0 <= y < qr.size and 0 <= x < qr.size
            cells.append(dark if inside and qr.modules[y][x] else light)
        rows.append("".join(cells))
    return "\n".join(rows)


def _chunk(tag: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + tag
        + payload
        + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
    )


def render_png(qr: QrCode, *, scale: int = 8, border: int = 4) -> bytes:
    """8-bit grayscale PNG, one pixel per module scaled up by `scale`."""
    if scale < 1:
        raise ValueError("scale must be positive")
    side = (qr.size + 2 * border) * scale
    raw = bytearray()
    for y in range(side):
        raw.append(0)  # filter type: none
        for x in range(side):
            raw.append(_DARK if _pixel_is_dark(qr, x, y, scale, border) else _LIGHT)

    header = struct.pack(">IIBBBBB", side, side, 8, 0, 0, 0, 0)
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            _chunk(b"IHDR", header),
            _chunk(b"IDAT", zlib.compress(bytes(raw), 9)),
            _chunk(b"IEND", b""),
        )
    )
