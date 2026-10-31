"""Generate src/wapy/qr/tables.json from the reference `qrcode` package.

Usage: uv run python scripts/sync_qr_tables.py

The Reed-Solomon block layout and alignment pattern positions are pure data from
the QR specification. Rather than transcribe 160 table rows by hand (a classic
source of silent errors), this script extracts them once and the result is
committed. The `qrcode` package is a dev dependency only.
"""

from __future__ import annotations

import json
from pathlib import Path

from qrcode.base import rs_blocks
from qrcode.constants import (
    ERROR_CORRECT_H,
    ERROR_CORRECT_L,
    ERROR_CORRECT_M,
    ERROR_CORRECT_Q,
)
from qrcode.util import PATTERN_POSITION_TABLE

TARGET = Path(__file__).resolve().parents[1] / "src/wapy/qr/tables.json"

LEVELS = {
    "L": ERROR_CORRECT_L,
    "M": ERROR_CORRECT_M,
    "Q": ERROR_CORRECT_Q,
    "H": ERROR_CORRECT_H,
}


def main() -> None:
    blocks: dict[str, dict[str, list[list[int]]]] = {}
    for version in range(1, 41):
        per_version: dict[str, list[list[int]]] = {}
        for name, constant in LEVELS.items():
            per_version[name] = [
                [block.total_count, block.data_count] for block in rs_blocks(version, constant)
            ]
        blocks[str(version)] = per_version

    payload = {
        "source": "qrcode 8.2 (RS_BLOCK_TABLE)",
        "alignment": [list(row) for row in PATTERN_POSITION_TABLE],
        "blocks": blocks,
    }
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
    total = sum(len(entry) for level in blocks.values() for entry in level.values())
    print(f"Wrote {TARGET}: {total} block groups across 40 versions")


if __name__ == "__main__":
    main()
