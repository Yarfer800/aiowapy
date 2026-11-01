"""Link a device with a QR code and keep the session alive across the 515 restart.

    WAPY_PROXY=http://127.0.0.1:10809 uv run python examples/pair.py bot.session

Scan the printed QR with WhatsApp on your phone (Linked devices). Codes rotate
every 60 seconds, then every 20. When pairing succeeds the session file is saved
and the script reconnects with a login payload, as the server requires.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from aiowapy.pairing import PairingQr
from aiowapy.protocol.transport import WhatsAppTransport
from aiowapy.qr.render import render_ascii
from aiowapy.session import ClientSession

S_WHATSAPP_NET = "s.whatsapp.net"


def log_node(node: object) -> None:
    tag = getattr(node, "tag", "?")
    attrs = getattr(node, "attrs", {})
    print(f"  <- {tag} {attrs}", flush=True)


def log_sent(node: object) -> None:
    tag = getattr(node, "tag", "?")
    attrs = getattr(node, "attrs", {})
    content = getattr(node, "content", None)
    if isinstance(content, bytes):
        print(f"  -> {tag} {attrs} content={len(content)}B {content.hex()[:120]}", flush=True)
    else:
        print(f"  -> {tag} {attrs}", flush=True)


def show_qr(item: PairingQr) -> None:
    print(render_ascii(item.qr, border=1), flush=True)
    print(f"scan now - this code lives {item.ttl}s\n", flush=True)


async def main() -> int:
    session_path = Path(sys.argv[1] if len(sys.argv) > 1 else "aiowapy.session")
    proxy = os.environ.get("WAPY_PROXY") or None
    platform = os.environ.get("WAPY_PLATFORM", "chrome")

    session = ClientSession(
        session_path,
        transport_factory=lambda: WhatsAppTransport(proxy=proxy, timeout=25),
        qr_callback=show_qr,
        node_observer=log_node,
        sent_observer=log_sent,
        platform=platform,
    )
    state = await session.run()
    if state.paired and state.jid:
        print(f"paired as {state.jid} (lid {state.lid})")
        print(f"session: {session_path}")
        return 0
    print("pairing did not complete")
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
