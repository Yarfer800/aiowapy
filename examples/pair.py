"""Full QR pairing flow: connect, show rotating QRs, complete the link.

Run it, scan the QR with WhatsApp on your phone (Linked devices), and the script
saves the resulting session file.

    WAPY_PROXY=http://127.0.0.1:10809 uv run python examples/pair.py bot.session

Environment:
    WAPY_PROXY   HTTP proxy to reach WhatsApp through (optional)
    WAPY_PLATFORM  chrome | firefox | electron | other (default: chrome)
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

from wapy.creds import generate_credentials
from wapy.pairing import PairingQrSource
from wapy.protocol.client_payload import build_registration_payload
from wapy.protocol.pairing import (
    build_pair_device_sign_reply,
    parse_pair_success,
    verify_pair_success,
)
from wapy.protocol.stream import NodeStream, child, children
from wapy.protocol.transport import WhatsAppTransport
from wapy.protocol.wabinary import Node, decode_node, encode_node
from wapy.qr.render import render_ascii
from wapy.store import SessionStore

# The reference client ships this revision; newer ones from the web page are
# rejected by the server as 405 "client outdated".
CLIENT_VERSION = (2, 3000, 1043857760)
S_WHATSAPP_NET = "s.whatsapp.net"


async def main() -> int:
    session_path = Path(sys.argv[1] if len(sys.argv) > 1 else "wapy.session")
    credentials = generate_credentials()
    platform = os.environ.get("WAPY_PLATFORM", "chrome")
    proxy = os.environ.get("WAPY_PROXY") or None

    transport = WhatsAppTransport(proxy=proxy, timeout=25)
    stream = NodeStream(transport)
    try:
        await transport.connect()
        await transport.handshake(
            client_payload=build_registration_payload(credentials, version=CLIENT_VERSION)
        )
        print("connected, waiting for pair-device...")

        refs = await _collect_refs(transport)
        if not refs:
            print("server did not issue pairing refs")
            return 1
        print(f"got {len(refs)} refs, showing QR rotation (Ctrl+C to cancel)\n")

        source = PairingQrSource(credentials, refs, platform=platform)
        deadline = time.monotonic() + 300
        item = source.next()
        while item is not None and time.monotonic() < deadline:
            print(render_ascii(item.qr, border=1), flush=True)
            print(f"scan now - this code lives {item.ttl}s\n", flush=True)
            paired = await _wait_for_pairing(transport, credentials, timeout=item.ttl)
            if paired:
                await _save(session_path, credentials, paired)
                return 0
            item = source.next()

        print("pairing window expired")
        return 1
    finally:
        await stream.close()
        await transport.close()


async def _collect_refs(transport: WhatsAppTransport) -> list[str]:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        frame = await asyncio.wait_for(transport.recv_encrypted(), timeout=10)
        node = decode_node(frame)
        pair_device = child(node, "pair-device")
        if pair_device is None:
            continue
        await transport.send_encrypted(
            encode_node(
                Node(
                    tag="iq",
                    attrs={
                        "to": S_WHATSAPP_NET,
                        "type": "result",
                        "id": node.attrs.get("id", ""),
                    },
                )
            )
        )
        refs: list[str] = []
        for ref_node in children(pair_device, "ref"):
            content = ref_node.content
            refs.append(content.decode() if isinstance(content, bytes) else str(content))
        return refs
    return []


async def _wait_for_pairing(transport: WhatsAppTransport, credentials, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            frame = await asyncio.wait_for(transport.recv_encrypted(), timeout=1)
        except TimeoutError:
            continue
        node = decode_node(frame)
        if node.tag != "iq" or child(node, "pair-success") is None:
            continue
        pair = parse_pair_success(node, message_id=node.attrs.get("id", ""))
        identity = verify_pair_success(pair, credentials)
        reply = build_pair_device_sign_reply(node.attrs["id"], identity, key_index=0)
        await transport.send_encrypted(encode_node(reply))
        print(f"paired as {pair.jid} (lid {pair.lid})")
        print(f"signed device identity for platform {pair.platform}")
        return True
    return False


async def _save(path: Path, credentials, paired) -> None:
    async with SessionStore(path) as store:
        await store.save_creds(
            {**credentials.to_dict(), "me": {"id": paired.jid, "lid": paired.lid}}
        )
    print(f"session saved to {path}")


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
