"""QR code encoder: byte mode, versions 1-40, error correction L/M/Q/H.

Implemented from ISO/IEC 18004. The Reed-Solomon block layout and alignment
positions are vendored data (see `scripts/sync_qr_tables.py`); everything else is
computed, including BCH-protected format and version information and mask
selection by the standard penalty rules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from aiowapy.errors import WapyError

_TABLES: Final = json.loads(Path(__file__).with_name("tables.json").read_text(encoding="utf-8"))

ALIGNMENT: Final[tuple[tuple[int, ...], ...]] = tuple(tuple(row) for row in _TABLES["alignment"])
BLOCKS: Final[dict[str, dict[str, tuple[tuple[int, int], ...]]]] = {
    version: {
        level: tuple((total, data) for total, data in entries) for level, entries in levels.items()
    }
    for version, levels in _TABLES["blocks"].items()
}

LEVEL_BITS: Final[dict[str, int]] = {"L": 0b01, "M": 0b00, "Q": 0b11, "H": 0b10}
LEVELS: Final[tuple[str, ...]] = ("L", "M", "Q", "H")

_FORMAT_MASK = 0x5412
_FORMAT_GENERATOR = 0x537
_VERSION_GENERATOR = 0x1F25


class QrError(WapyError):
    """Payload cannot be encoded as a QR code."""


@dataclass(frozen=True, slots=True)
class QrCode:
    """A finished QR symbol. `modules[row][col]` is True for a dark module."""

    version: int
    level: str
    mask: int
    size: int
    modules: tuple[tuple[bool, ...], ...]


def _raw_data_modules(version: int) -> int:
    return (16 * version + 128) * version + 64


def _total_codewords(version: int) -> int:
    return _raw_data_modules(version) // 8


def _data_codewords(version: int, level: str) -> int:
    return sum(data for _total, data in BLOCKS[str(version)][level])


def _char_count_bits(version: int) -> int:
    return 8 if version < 10 else 16


def _append(bits: list[int], value: int, width: int) -> None:
    for shift in range(width - 1, -1, -1):
        bits.append((value >> shift) & 1)


def _to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for index in range(0, len(bits), 8):
        byte = 0
        for bit in bits[index : index + 8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def _choose_version(length: int, level: str) -> int:
    for version in range(1, 41):
        needed = 4 + _char_count_bits(version) + 8 * length
        if needed <= _data_codewords(version, level) * 8:
            return version
    raise QrError(f"payload of {length} bytes does not fit in any QR version at level {level}")


def _encode_codewords(data: bytes, version: int, level: str) -> bytes:
    capacity_bits = _data_codewords(version, level) * 8
    bits: list[int] = []
    _append(bits, 0b0100, 4)
    _append(bits, len(data), _char_count_bits(version))
    for byte in data:
        _append(bits, byte, 8)
    if len(bits) > capacity_bits:
        raise QrError("payload does not fit")
    _append(bits, 0, min(4, capacity_bits - len(bits)))
    while len(bits) % 8:
        bits.append(0)
    codewords = bytearray(_to_bytes(bits))
    pad = (0xEC, 0x11)
    index = 0
    while len(codewords) < _data_codewords(version, level):
        codewords.append(pad[index % 2])
        index += 1
    return bytes(codewords)


def _galois_tables() -> tuple[list[int], list[int]]:
    exp = [0] * 512
    log = [0] * 256
    value = 1
    for power in range(255):
        exp[power] = value
        log[value] = power
        value <<= 1
        if value & 0x100:
            value ^= 0x11D
    for power in range(255, 512):
        exp[power] = exp[power - 255]
    return exp, log


_EXP, _LOG = _galois_tables()


def _multiply(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _generator(degree: int) -> list[int]:
    polynomial = [1]
    for power in range(degree):
        factor = _EXP[power]
        shifted = polynomial + [0]
        for index in range(len(polynomial)):
            shifted[index + 1] ^= _multiply(polynomial[index], factor)
        polynomial = shifted
    return polynomial


def _reed_solomon(data: bytes, degree: int) -> bytes:
    generator = _generator(degree)
    remainder = [0] * degree
    for byte in data:
        factor = byte ^ remainder[0]
        remainder = remainder[1:] + [0]
        if factor:
            for index in range(degree):
                remainder[index] ^= _multiply(generator[index + 1], factor)
    return bytes(remainder)


def _interleave(data: bytes, version: int, level: str) -> bytes:
    spec = BLOCKS[str(version)][level]
    ec_count = spec[0][0] - spec[0][1]
    blocks: list[tuple[bytes, bytes]] = []
    offset = 0
    for _total, data_count in spec:
        chunk = data[offset : offset + data_count]
        offset += data_count
        blocks.append((chunk, _reed_solomon(chunk, ec_count)))
    out = bytearray()
    longest = max(len(chunk) for chunk, _ecc in blocks)
    for index in range(longest):
        for chunk, _ecc in blocks:
            if index < len(chunk):
                out.append(chunk[index])
    for index in range(ec_count):
        for _chunk, ecc in blocks:
            out.append(ecc[index])
    return bytes(out)


class _Grid:
    def __init__(self, size: int) -> None:
        self.size = size
        self.modules = [[False] * size for _ in range(size)]
        self.fixed = [[False] * size for _ in range(size)]

    def place(self, row: int, col: int, dark: bool) -> None:
        self.modules[row][col] = dark
        self.fixed[row][col] = True


def _draw_finder(grid: _Grid, top: int, left: int) -> None:
    for dr in range(-1, 8):
        for dc in range(-1, 8):
            row, col = top + dr, left + dc
            if not (0 <= row < grid.size and 0 <= col < grid.size):
                continue
            inside = 0 <= dr <= 6 and 0 <= dc <= 6
            ring = inside and (dr in (0, 6) or dc in (0, 6))
            core = 2 <= dr <= 4 and 2 <= dc <= 4
            grid.place(row, col, ring or core)


def _draw_alignment(grid: _Grid, version: int) -> None:
    positions = ALIGNMENT[version - 1]
    if not positions:
        return
    last = grid.size - 7
    skip = {(6, 6), (6, last), (last, 6)}
    for row in positions:
        for col in positions:
            if (row, col) in skip:
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    dark = max(abs(dr), abs(dc)) != 1
                    grid.place(row + dr, col + dc, dark)


def _draw_timing(grid: _Grid) -> None:
    for index in range(8, grid.size - 8):
        dark = index % 2 == 0
        grid.place(6, index, dark)
        grid.place(index, 6, dark)


def _bch(data: int, generator: int, degree: int) -> int:
    value = data << degree
    while value.bit_length() - 1 >= degree:
        value ^= generator << (value.bit_length() - 1 - degree)
    return (data << degree) | value


def _draw_format(grid: _Grid, level: str, mask: int) -> None:
    bits = _bch((LEVEL_BITS[level] << 3) | mask, _FORMAT_GENERATOR, 10) ^ _FORMAT_MASK
    size = grid.size
    for index in range(6):
        grid.place(index, 8, (bits >> index) & 1 != 0)
    grid.place(7, 8, (bits >> 6) & 1 != 0)
    grid.place(8, 8, (bits >> 7) & 1 != 0)
    grid.place(8, 7, (bits >> 8) & 1 != 0)
    for index in range(9, 15):
        grid.place(8, 14 - index, (bits >> index) & 1 != 0)
    for index in range(8):
        grid.place(8, size - 1 - index, (bits >> index) & 1 != 0)
    for index in range(8, 15):
        grid.place(size - 15 + index, 8, (bits >> index) & 1 != 0)
    grid.place(size - 8, 8, True)


def _draw_version(grid: _Grid, version: int) -> None:
    if version < 7:
        return
    bits = _bch(version, _VERSION_GENERATOR, 12)
    size = grid.size
    for index in range(18):
        dark = (bits >> index) & 1 != 0
        col = size - 11 + index % 3
        row = index // 3
        grid.place(row, col, dark)
        grid.place(col, row, dark)


def _draw_data(grid: _Grid, codewords: bytes) -> None:
    bits = [(byte >> shift) & 1 for byte in codewords for shift in range(7, -1, -1)]
    index = 0
    column = grid.size - 1
    upward = True
    while column > 0:
        if column == 6:
            column -= 1
        for step in range(grid.size):
            row = grid.size - 1 - step if upward else step
            for offset in (0, 1):
                col = column - offset
                if grid.fixed[row][col]:
                    continue
                grid.modules[row][col] = index < len(bits) and bits[index] == 1
                index += 1
        upward = not upward
        column -= 2


def _mask_bit(mask: int, row: int, col: int) -> bool:
    if mask == 0:
        return (row + col) % 2 == 0
    if mask == 1:
        return row % 2 == 0
    if mask == 2:
        return col % 3 == 0
    if mask == 3:
        return (row + col) % 3 == 0
    if mask == 4:
        return (row // 2 + col // 3) % 2 == 0
    if mask == 5:
        return (row * col) % 2 + (row * col) % 3 == 0
    if mask == 6:
        return ((row * col) % 2 + (row * col) % 3) % 2 == 0
    if mask == 7:
        return ((row + col) % 2 + (row * col) % 3) % 2 == 0
    raise QrError(f"unknown mask: {mask}")


def _apply_mask(grid: _Grid, mask: int) -> _Grid:
    masked = _Grid(grid.size)
    masked.fixed = [row[:] for row in grid.fixed]
    for row in range(grid.size):
        for col in range(grid.size):
            dark = grid.modules[row][col]
            if not grid.fixed[row][col] and _mask_bit(mask, row, col):
                dark = not dark
            masked.modules[row][col] = dark
    return masked


def _penalty(grid: _Grid) -> int:
    size = grid.size
    score = 0
    for row in range(size):
        run = 1
        for col in range(1, size):
            if grid.modules[row][col] == grid.modules[row][col - 1]:
                run += 1
            else:
                if run >= 5:
                    score += 3 + run - 5
                run = 1
        if run >= 5:
            score += 3 + run - 5
    for col in range(size):
        run = 1
        for row in range(1, size):
            if grid.modules[row][col] == grid.modules[row - 1][col]:
                run += 1
            else:
                if run >= 5:
                    score += 3 + run - 5
                run = 1
        if run >= 5:
            score += 3 + run - 5
    for row in range(size - 1):
        for col in range(size - 1):
            value = grid.modules[row][col]
            if (
                grid.modules[row][col + 1] == value
                and grid.modules[row + 1][col] == value
                and grid.modules[row + 1][col + 1] == value
            ):
                score += 3
    patterns = (
        (True, False, True, True, True, False, True, False, False, False, False),
        (False, False, False, False, True, False, True, True, True, False, True),
    )
    for row in range(size):
        for col in range(size - 10):
            for pattern in patterns:
                if all(grid.modules[row][col + offset] == pattern[offset] for offset in range(11)):
                    score += 40
    for col in range(size):
        for row in range(size - 10):
            for pattern in patterns:
                if all(grid.modules[row + offset][col] == pattern[offset] for offset in range(11)):
                    score += 40
    dark = sum(1 for row in grid.modules for cell in row if cell)
    total = size * size
    percent = dark * 100 / total
    score += int(abs(percent - 50) // 5) * 10
    return score


def encode(data: str | bytes, *, level: str = "M") -> QrCode:
    """Encode `data` (byte mode) and pick the smallest version that fits."""
    if level not in LEVELS:
        raise QrError(f"unknown error correction level: {level!r}")
    payload = data.encode("utf-8") if isinstance(data, str) else data
    version = _choose_version(len(payload), level)
    codewords = _interleave(_encode_codewords(payload, version, level), version, level)
    if len(codewords) > _total_codewords(version):
        raise QrError("internal error: codeword overflow")

    base = _Grid(17 + 4 * version)
    _draw_finder(base, 0, 0)
    _draw_finder(base, 0, base.size - 7)
    _draw_finder(base, base.size - 7, 0)
    _draw_timing(base)
    _draw_alignment(base, version)
    _draw_version(base, version)
    _draw_format(base, level, 0)
    _draw_data(base, codewords)

    best: tuple[int, int] | None = None
    for mask in range(8):
        candidate = _apply_mask(base, mask)
        _draw_format(candidate, level, mask)
        score = _penalty(candidate)
        if best is None or score < best[0]:
            best = (score, mask)
    assert best is not None
    chosen = best[1]

    final = _apply_mask(base, chosen)
    _draw_format(final, level, chosen)
    modules = tuple(tuple(row) for row in final.modules)
    return QrCode(version=version, level=level, mask=chosen, size=final.size, modules=modules)
