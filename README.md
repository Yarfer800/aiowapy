# aiowapy

[![CI](https://github.com/Yarfer800/aiowapy/actions/workflows/ci.yml/badge.svg)](https://github.com/Yarfer800/aiowapy/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-yarfer800.github.io%2Faiowapy-green)](https://yarfer800.github.io/aiowapy/)
[![PyPI](https://img.shields.io/pypi/v/aiowapy.svg)](https://pypi.org/project/aiowapy/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://pypi.org/project/aiowapy/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An asynchronous WhatsApp Multi-Device client for Python: a native implementation of the
protocol (Noise + Signal + WABinary), no official Cloud API involved.

> ⚠️ **Unofficial client.** Using it violates WhatsApp's Terms of Service and the number
> may be banned. Use a test number and proceed at your own risk.

## Installation

```bash
pip install aiowapy
```

The distribution is called **aiowapy**, the import is **`aiowapy`**:

```python
from aiowapy import Client
```

Full documentation: **https://yarfer800.github.io/aiowapy/**

<p align="center">
  <img src="docs/assets/demo.gif" alt="aiowapy: install, connect to a scripted server, receive /ping and answer pong" width="820">
</p>

<p align="center"><em>Real run of <code>examples/offline_demo.py</code>: the server is scripted, the Signal sessions, stanzas and session file are the production code.</em></p>

## Quick start

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

The first run needs linking: scan the QR code (`qr_callback`) or use
`ClientSession.pair_with_phone_number` (see `examples/pair_code.py`). After that the
session file keeps the keys and later runs only log in.

## One session file, like Pyrogram

`.session` is SQLite and holds everything: credentials, Signal sessions, prekeys,
app state, **chats, contacts and messages**.

```python
history = await client.get_chat_history(chat_jid, limit=50)  # newest first
older = await client.get_chat_history(chat_jid, limit=50, before_timestamp=history[-1].timestamp)

chats = await client.get_chats()  # conversations, newest first
users = await client.get_users()  # contacts we have seen
chat = await client.get_chat(jid)  # Peer: .name, .push_name, .contact_name
await client.set_contact_name(jid, "Mom")
await client.download_stored(history[0])  # attachment of a stored message
```

Messages arrive from three places: live traffic, `history sync` chunks sent by the
phone, and everything the bot sends. All of it lands in the same table, so
`get_chat_history` returns a real conversation, not just what the process saw.

## Sending

```python
await client.send_text(jid, "hello")
await client.send_text(jid, "with a reply", quote=message_id)
await client.send_image(jid, picture_bytes, caption="look")
await client.send_document(jid, pdf_bytes, file_name="report.pdf", mime_type="application/pdf")
await client.send_audio(jid, voice_bytes, voice_note=True)
await client.send_reaction(jid, message_id, "\U0001f44d")
await client.edit_message(jid, message_id, "fixed text")
await client.revoke_message(jid, message_id)
await client.send_text("120363000000000001@g.us", "hello group")  # groups just work
```

`send_*` returns `SendResult(message_id, sent, failed, acked)`: a message counts as
delivered when at least one device accepted it; per-device failures are listed, not
raised.

## Receiving

```python
from aiowapy.router import F


@client.router.message(F.text.contains("invoice") & F.chat("1203630@g.us"))
async def handle(event: MessageEvent) -> None:
    await client.mark_read(event)


@client.router.message(F.media("image"))
async def on_image(event: MessageEvent) -> None:
    data = await client.download_media(event.media)
```

Events: `MessageEvent`, `ReactionEvent`, `EditEvent`, `RevokeEvent`, `HistorySyncEvent`,
`ReceiptEvent`, `PresenceEvent`, `ChatStateEvent`, `ConnectedEvent`,
`DisconnectedEvent`, `NotificationEvent`.

Presence and typing:

```python
await client.send_presence(True)
await client.subscribe_presence(jid)
await client.send_typing(jid, composing=True)
```

## Groups

```python
info = await client.group_info(group_jid)
group = await client.create_group("Team", [jid1, jid2])
await client.update_group_participants(group, "add", [jid3])
await client.leave_group(group)
```

A group message is encrypted once with a sender key; the key distribution message
travels to every member device, exactly as the reference client does it.

## App state

Contacts, mutes, pins and read markers live in WhatsApp's app state. Keys arrive from
the phone; after that:

```python
await client.sync_app_state()
await client.mute_chat(jid, True)
await client.pin_chat(jid, True)
await client.mark_chat_read(jid, True)
```

## Coverage

| Layer | Module |
|---|---|
| Noise handshake, framing | `aiowapy.protocol.noise`, `aiowapy.protocol.transport` |
| Pairing (QR and code) | `aiowapy.protocol.pairing`, `aiowapy.protocol.pairing_code` |
| WABinary codec | `aiowapy.protocol.wabinary` |
| Signal (X3DH, double ratchet) | `aiowapy.crypto.session` |
| Sending: text, media, groups | `aiowapy.messaging` |
| Receiving and decryption | `aiowapy.messaging.receiving` |
| Receipts, retry requests | `aiowapy.protocol.receipts`, `aiowapy.client` |
| Presence and typing | `aiowapy.protocol.presence` |
| Groups (sender keys) | `aiowapy.messaging.groups` |
| Media upload and download | `aiowapy.messaging.media` |
| App state sync | `aiowapy.messaging.appstate` |
| History sync | `aiowapy.messaging.history` |
| Chats, contacts, messages | `aiowapy.store` |
| Reactions, replies, edits, revokes | `aiowapy.protocol.messages` |

Not implemented: calls, channels (newsletters), statuses, polls and buttons,
LID-based encryption (LID mappings are stored and exposed, but sessions still start
on phone-number devices).

## License

MIT.
