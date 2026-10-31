"""Dump WebSocket frames from a mitmproxy stream file.

Usage:
    uv run python tools/capture/extract-ws.py ~/captures/wa-flows.mitm
    uv run python tools/capture/extract-ws.py ~/captures/wa-flows.mitm --hex

Requires the `mitmproxy` package (installed in the dev environment, not a
project dependency).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="mitmproxy stream file")
    parser.add_argument("--hex", action="store_true", help="print frames as hex")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=120,
        help="bytes of each frame to print on the summary line (0 = all)",
    )
    args = parser.parse_args()

    try:
        from mitmproxy import io
        from mitmproxy.websocket import WebSocketData
    except ImportError:
        print("error: mitmproxy is not importable in this environment", file=sys.stderr)
        return 1

    if not args.path.exists():
        print(f"error: no such file: {args.path}", file=sys.stderr)
        return 1

    flows = 0
    frames = 0
    with args.path.open("rb") as handle:
        reader = io.FlowReader(handle)
        for flow in reader.stream():
            flows += 1
            data = getattr(flow, "websocket", None)
            if not isinstance(data, WebSocketData):
                continue
            print(f"\n# {flow.request.pretty_url}")
            for message in data.messages:
                frames += 1
                direction = "S->C" if message.from_client is False else "C->S"
                kind = "text" if message.is_text else "binary"
                payload = message.content
                shown = payload if args.max_bytes <= 0 else payload[: args.max_bytes]
                body = shown.hex() if args.hex else shown.decode("utf-8", errors="replace")
                body = body.replace("\n", "\\n")
                print(f"  {direction} {kind} {len(payload)}B  {body}")

    print(f"\nflows: {flows}, websocket frames: {frames}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
