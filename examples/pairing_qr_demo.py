"""End-to-end pairing QR demo.

Generates device credentials, takes a fake batch of pairing refs (the real ones
arrive from the server in the `pair-device` iq and are filled in by the client),
then walks the rotation exactly as the client will: 60 s for the first code,
20 s for the rest.

Run: uv run python examples/pairing_qr_demo.py
"""

from __future__ import annotations

import secrets
from pathlib import Path

from wapy.creds import generate_credentials
from wapy.pairing import PairingQrSource
from wapy.qr.render import render_ascii, render_png

OUTPUT_DIR = Path("/tmp/wapy-pairing")


def main() -> None:
    credentials = generate_credentials()
    print("device credentials generated locally")
    print(f"  registration id : {credentials.registration_id}")
    print(f"  noise key       : {credentials.noise_public.hex()[:32]}...")
    print(f"  identity key    : {credentials.identity_public.hex()[:32]}...")
    print(f"  signed prekey   : id={credentials.signed_pre_key.key_id} "
          f"signature={'valid' if credentials.verify() else 'INVALID'}")
    print(f"  adv secret      : {credentials.adv_secret_key}")
    print()

    # Stand-in for the refs the server sends in the `pair-device` node.
    refs = ["2@" + secrets.token_urlsafe(12) for _ in range(3)]

    source = PairingQrSource(credentials, refs, platform="chrome")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for index, item in enumerate(source, start=1):
        path = OUTPUT_DIR / f"qr-{index}.png"
        path.write_bytes(render_png(item.qr, scale=10))
        print(f"[{index}/{len(source)}] ttl={item.ttl}s  "
              f"version={item.qr.version}  size={item.qr.size}x{item.qr.size}")
        print(f"          payload: {item.payload[:70]}...")
        print(f"          png    : {path}")
        if index == 1:
            print()
            print(render_ascii(item.qr, border=1))
            print()

    print("refs exhausted - a new connection is required to obtain fresh ones")


if __name__ == "__main__":
    main()
