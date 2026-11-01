# Quick start

## 1. Link the device

A companion device has to be linked once. Two ways, both in `aiowapy.session`.

### QR code

```python
import asyncio

from aiowapy import Client


def show_qr(item: object) -> None:
    # item.qr holds the string WhatsApp expects; item.ascii is the terminal rendering
    print(item.ascii)  # type: ignore[attr-defined]


async def main() -> None:
    client = Client("bot.session", qr_callback=show_qr)
    await client.connect()
    print("ready:", client.info.jid)
    await client.run()


asyncio.run(main())
```

Open WhatsApp → Linked devices → Link a device and scan. The callback is called
again with a fresh code when the current one expires.

### Pairing code

Typing a code on the phone is the alternative when a camera is not available:

```python
from aiowapy.protocol.pairing_code import generate_pairing_code
from aiowapy.protocol.transport import WhatsAppTransport
from aiowapy.session import ClientSession

code = generate_pairing_code()
print("type this on the phone:", code)

session = ClientSession(
    "bot.session",
    transport_factory=lambda: WhatsAppTransport(),
)
state = await session.pair_with_phone_number("+49123456789", code)
```

A complete runnable version with node logging: `examples/pair_code.py`.

Both flows write the credentials into the session file, so the next start logs in
directly.

## 2. Connect

```python
client = Client("bot.session")
info = await client.connect()      # returns ClientInfo(jid, lid, push_name)
...
await client.close()
```

`connect()` returns when the server accepts the login. Serving continues in the
background until `close()`. If you want to block, use `await client.run()`.

## 3. Send something

```python
await client.send_text("49123456789@s.whatsapp.net", "hello")
```

The recipient JID is the phone number followed by `@s.whatsapp.net`; groups end with
`@g.us`.

## 4. Handle messages

```python
from aiowapy.events import MessageEvent
from aiowapy.router import F


@client.router.message(F.text)
async def echo(event: MessageEvent) -> None:
    await client.send_text(event.chat_jid, event.text or "")
```

## Lifecycle notes

- **Reconnect** is automatic: dropped sockets and `stream:error 515` are retried with
  exponential backoff. A `401/403/409` while connected stops the client — the device
  was revoked and re-pairing is a user decision.
- **Keepalive** is a node-level `<iq xmlns="w:p"><ping/></iq>` every 30 seconds; the
  connection counts as dead after 35 seconds of silence.
- **Session file** is created with `0600` permissions. It contains the private keys:
  treat it like a password.
