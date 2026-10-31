from __future__ import annotations

import pytest
import qrcode
from qrcode.constants import (
    ERROR_CORRECT_H,
    ERROR_CORRECT_L,
    ERROR_CORRECT_M,
    ERROR_CORRECT_Q,
)

from wapy.qr.encoder import (
    LEVELS,
    QrError,
    _apply_mask,
    _choose_version,
    _data_codewords,
    _draw_alignment,
    _draw_data,
    _draw_finder,
    _draw_format,
    _draw_timing,
    _draw_version,
    _encode_codewords,
    _Grid,
    _interleave,
    encode,
)

LEVEL_CONSTANTS = {
    "L": ERROR_CORRECT_L,
    "M": ERROR_CORRECT_M,
    "Q": ERROR_CORRECT_Q,
    "H": ERROR_CORRECT_H,
}

PAYLOADS = [b"hello", b"a" * 40, b"b" * 120, b"c" * 250, b"d" * 400]
PAIRING_LIKE = (
    b"https://wa.me/settings/linked_devices#2@AbCdEf,"
    b"MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=,"
    b"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg=,"
    b"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0,1"
)


def _fixed_mask_matrix(payload: bytes, level: str, mask: int) -> _Grid:
    version = _choose_version(len(payload), level)
    codewords = _interleave(_encode_codewords(payload, version, level), version, level)
    grid = _Grid(17 + 4 * version)
    _draw_finder(grid, 0, 0)
    _draw_finder(grid, 0, grid.size - 7)
    _draw_finder(grid, grid.size - 7, 0)
    _draw_timing(grid)
    _draw_alignment(grid, version)
    _draw_version(grid, version)
    _draw_format(grid, level, mask)
    _draw_data(grid, codewords)
    masked = _apply_mask(grid, mask)
    _draw_format(masked, level, mask)
    return masked


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("payload", PAYLOADS + [PAIRING_LIKE])
@pytest.mark.parametrize("mask", range(8))
def test_matrix_matches_reference_at_fixed_mask(level: str, payload: bytes, mask: int) -> None:
    """With the mask pinned, geometry, RS blocks and format bits must match exactly."""
    reference = qrcode.QRCode(error_correction=LEVEL_CONSTANTS[level], border=0, mask_pattern=mask)
    reference.add_data(payload)
    reference.make(fit=True)
    expected = reference.get_matrix()
    actual = _fixed_mask_matrix(payload, level, mask)
    assert len(expected) == actual.size
    for row in range(actual.size):
        for col in range(actual.size):
            assert bool(expected[row][col]) == actual.modules[row][col], (row, col)


@pytest.mark.parametrize("level", LEVELS)
def test_chosen_mask_is_the_lowest_penalty(level: str) -> None:
    from wapy.qr.encoder import _penalty

    payload = b"chosen mask"
    result = encode(payload, level=level)
    scores = [_penalty(_fixed_mask_matrix(payload, level, mask)) for mask in range(8)]
    assert scores[result.mask] == min(scores)


def test_version_selection_picks_smallest_fitting() -> None:
    assert _choose_version(5, "L") == 1
    assert _choose_version(17, "L") == 1  # 12 + 136 <= 152 bits
    assert _choose_version(18, "L") == 2
    assert _choose_version(5, "H") == 1


def test_payload_too_large_is_rejected() -> None:
    with pytest.raises(QrError):
        encode(b"x" * 3000, level="H")


def test_unknown_level_is_rejected() -> None:
    with pytest.raises(QrError):
        encode(b"x", level="Z")


def test_data_capacity_matches_reference_tables() -> None:
    assert _data_codewords(1, "L") == 19
    assert _data_codewords(1, "M") == 16
    assert _data_codewords(1, "Q") == 13
    assert _data_codewords(1, "H") == 9


def test_size_follows_version_formula() -> None:
    for version in (1, 5, 10, 25, 40):
        payload = b"x" * (10 + version)
        result = encode(payload, level="L")
        if result.version == version:
            assert result.size == 17 + 4 * version


def test_bytes_and_str_inputs_agree() -> None:
    assert encode("héllo", level="M").modules == encode("héllo".encode(), level="M").modules
