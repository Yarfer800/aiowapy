"""Link a device by typing a code on the phone instead of scanning a QR.

    WAPY_PROXY=http://127.0.0.1:10809 uv run python examples/pair_code.py +79646669102 bot.session

The phone needs the code from the moment it is printed: open WhatsApp, choose
Linked devices, "Link with phone number", and type it in.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from aiowapy.protocol.pairing_code import generate_pairing_code
from aiowapy.protocol.transport import WhatsAppTransport
from aiowapy.session import ClientSession


async def main() -> int:
    if len(sys.argv) < 2:
        print("usage: pair_code.py <phone_number> [session_path]")
        return 2
    phone = sys.argv[1]
    session_path = Path(sys.argv[2] if len(sys.argv) > 2 else "aiowapy.session")
    proxy = os.environ.get("WAPY_PROXY") or None

    code = generate_pairing_code()
    print(f"code: {code}")
    print("WhatsApp -> Linked devices -> Link with phone number -> type the code\n")

    def show(node: object) -> None:
        tag = getattr(node, "tag", "?")
        attrs = getattr(node, "attrs", {})
        print(f"  <- {tag} {attrs}", flush=True)
        content = getattr(node, "content", None)
        if tag in ("notification", "iq") and isinstance(content, list):
            for item in content:
                body = item.content
                if isinstance(body, bytes):
                    detail = f"{len(body)}B {body[:24].hex()}"
                else:
                    detail = "nested" if isinstance(body, list) else repr(body)
                print(f"       child {item.tag} {item.attrs} {detail}", flush=True)

    session = ClientSession(
        session_path,
        transport_factory=lambda: WhatsAppTransport(proxy=proxy, timeout=25),
        node_observer=show,
    )
    state = await session.pair_with_phone_number(phone, code)
    if state.jid:
        print(f"paired as {state.jid} (lid {state.lid})")
        print(f"session: {session_path}")
        return 0
    print("pairing did not complete")
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
