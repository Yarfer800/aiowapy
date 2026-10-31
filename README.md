# wapy

An asynchronous WhatsApp Multi-Device client for Python: a native implementation of the
protocol (Noise + Signal + WABinary), no official Cloud API involved.

> ⚠️ **Unofficial client.** Using it violates WhatsApp's Terms of Service and the number
> may be banned. Use a test number and proceed at your own risk.

## Installation

```bash
pip install wapy
```

## Quick start

```python
import asyncio

from wapy.client import WhatsAppClient
from wapy.events import MessageEvent
from wapy.router import F


async def main() -> None:
    async with WhatsAppClient("bot.session") as client:
        print("connected as", client.info.jid)

        @client.router.message(F.text.startswith("/ping"))
        async def ping(event: MessageEvent) -> None:
            await client.send_text(event.chat_jid, "pong")

        await client.run()


asyncio.run(main())
```

The first run prints nothing to send a message with: link the device by scanning the
QR code (`qr_callback`) or, for a phone number, use `ClientSession.pair_with_phone_number`
(see `examples/pair_code.py`). The session file keeps the keys, so later runs just log in.

## What is covered

| Layer | Module | Status |
|---|---|---|
| Noise handshake, framing | `wapy.protocol.noise`, `wapy.protocol.transport` | yes |
| Pairing (QR and code) | `wapy.protocol.pairing`, `wapy.protocol.pairing_code` | yes |
| WABinary codec | `wapy.protocol.wabinary` | yes |
| Signal (X3DH, double ratchet) | `wapy.crypto.session` | yes |
| Sending (text, media, groups) | `wapy.messaging` | yes |
| Receiving and decryption | `wapy.messaging.receiving` | yes |
| Receipts, retry requests | `wapy.protocol.receipts`, `wapy.client` | yes |
| Presence and typing | `wapy.protocol.presence` | yes |
| Groups (sender keys) | `wapy.messaging.groups` | yes |
| Media upload and download | `wapy.messaging.media` | yes |
| App state sync | `wapy.messaging.appstate` | yes |
| History sync, newsletters | — | not yet |

## Sending

```python
await client.send_text("491234567890@s.whatsapp.net", "hello")
await client.send_image(chat, picture_bytes, caption="look")
await client.send_document(chat, pdf_bytes, file_name="report.pdf", mime_type="application/pdf")
await client.send_audio(chat, voice_bytes, voice_note=True)
await client.send_text("120363000000000001@g.us", "hello group")  # groups just work
```

`send_*` returns `SendResult(message_id, sent, failed, acked)`: a message is delivered
when at least one device accepted it, and failures of individual devices are listed
rather than raised.

## Receiving

Handlers are registered on `client.router` with optional filters:

```python
from wapy.router import F


@client.router.message(F.text.contains("invoice") & F.chat("1203630@g.us"))
async def handle(event: MessageEvent) -> None:
    await client.mark_read(event)


@client.router.message(F.media("image"))
async def on_image(event: MessageEvent) -> None:
    data = await client.download_media(event.media)
```

Available events: `MessageEvent`, `ReceiptEvent`, `PresenceEvent`, `ChatStateEvent`,
`ConnectedEvent`, `DisconnectedEvent`, `NotificationEvent`.

Presence and typing:

```python
await client.send_presence(True)  # available, with the push name
await client.subscribe_presence(jid)  # receive this user's updates
await client.send_typing(jid, composing=True)
```

## Groups

```python
info = await client.group_info(group_jid)  # subject, participants, settings
group = await client.create_group("Team", [jid1, jid2])
await client.update_group_participants(group, "add", [jid3])
await client.leave_group(group)
```

Group messages are encrypted once with a sender key and the key distribution message
travels to every member device, exactly as the reference client does it.

## App state

Contacts, mutes, pins and read markers live in WhatsApp's app state. Keys arrive from
the phone; after that:

```python
await client.sync_app_state()  # pull and verify patches
await client.mute_chat(jid, True)
await client.pin_chat(jid, True)
await client.mark_chat_read(jid, True)
```

## License

MIT.
