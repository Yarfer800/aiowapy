# aiowapy

An asynchronous WhatsApp Multi-Device client for Python. The protocol is implemented
from scratch — Noise handshake, Signal (X3DH + double ratchet), WABinary codec, sender
keys, media encryption, app state — with `cryptography` as the only crypto dependency.

No official Cloud API, no Go bridge, no subprocess: `import aiowapy` and go.

!!! warning "Unofficial client"
    Using this library violates WhatsApp's Terms of Service and the number may be
    banned. Use a test number and proceed at your own risk.

## Install

```bash
pip install aiowapy
```

The distribution is called **aiowapy**, the import is **`wapy`**:

```python
from aiowapy import Client
```

## A bot in 20 lines

```python
import asyncio

from aiowapy import Client
from aiowapy.events import MessageEvent
from aiowapy.router import F


async def main() -> None:
    async with Client("bot.session") as client:
        print("connected as", client.info.jid)

        @client.router.message(F.text.startswith("/ping"))
        async def ping(event: MessageEvent) -> None:
            await client.send_text(event.chat_jid, "pong", quote=event.message_id)

        await client.run()


asyncio.run(main())
```

The first run prints a QR code (or use a pairing code — see [Quick start](quickstart.md)).
After that the session file keeps the keys and later runs only log in.

## What you get

| Area | Highlights |
|---|---|
| Connection | Noise XX handshake, WABinary frames, keepalive, automatic reconnect |
| Pairing | QR code and phone-number pairing, prekey publication |
| 1:1 chat | text, replies, reactions, edits, revokes, receipts (delivery/read) |
| Media | images, video, audio, voice notes, documents, stickers — upload and download |
| Groups | info, create, add/remove/promote/demote, leave, sender keys |
| Reception | prekey and one-time prekey sessions, sender keys, retry receipts |
| Presence | available/unavailable, subscriptions, typing indicators |
| Storage | one `.session` SQLite file with chats, contacts, messages, reactions |
| History | history sync chunks from the phone, stored and queryable |
| App state | patch sync with integrity hash, mute/pin/mark-read/push-name |

Not implemented: calls, channels (newsletters), statuses, polls and buttons, LID-based
encryption. See [Protocol and limitations](protocol.md).

## Where to go next

- [Quick start](quickstart.md) — link a device and send the first message.
- [Sending](messages.md) — text, replies, reactions, edits, revokes.
- [Receiving](receiving.md) — events, router, filters.
- [Storage and history](storage.md) — what lives in `.session` and how to query it.
- [API reference](api/client.md) — every public class and method.
