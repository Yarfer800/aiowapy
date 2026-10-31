"""Generate src/wapy/protocol/wabinary/tokens.json from the reference constants.ts.

Usage: uv run python scripts/sync_wabinary_tokens.py
Requires network access. The result is committed; runtime needs no network or Node.
"""

from __future__ import annotations

import ast
import json
import urllib.request
from pathlib import Path

BAILEYS_COMMIT = "81345beb67ca3fb0eb79a2c20cd4ac24da517929"
SOURCE_URL = (
    "https://raw.githubusercontent.com/WhiskeySockets/Baileys/"
    f"{BAILEYS_COMMIT}/src/WABinary/constants.ts"
)
TARGET = Path(__file__).resolve().parents[1] / "src/wapy/protocol/wabinary/tokens.json"


def fetch_source() -> str:
    with urllib.request.urlopen(SOURCE_URL, timeout=30) as response:
        return response.read().decode("utf-8")


def extract_literal(source: str, name: str) -> object:
    """Cut out a JS array literal and parse it as a Python literal."""
    marker = f"export const {name}"
    start_of_decl = source.index(marker)
    opening = source.index("[", start_of_decl)
    depth = 0
    for index in range(opening, len(source)):
        char = source[index]
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return ast.literal_eval(source[opening : index + 1])
    raise SystemExit(f"end of literal not found: {name}")


def extract_tags(source: str) -> dict[str, int]:
    marker = "export const TAGS"
    start_of_decl = source.index(marker)
    opening = source.index("{", start_of_decl)
    closing = source.index("}", opening)
    body = source[opening + 1 : closing]
    tags: dict[str, int] = {}
    for raw_line in body.splitlines():
        line = raw_line.strip().rstrip(",")
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        tags[key.strip()] = int(value.strip().rstrip(","))
    return tags


def main() -> None:
    source = fetch_source()
    payload = {
        "source": f"Baileys {BAILEYS_COMMIT}",
        "tags": extract_tags(source),
        "single": extract_literal(source, "SINGLE_BYTE_TOKENS"),
        "double": extract_literal(source, "DOUBLE_BYTE_TOKENS"),
    }
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"Wrote {TARGET}: {len(payload['single'])} single-byte tokens")


if __name__ == "__main__":
    main()
