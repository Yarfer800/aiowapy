# Receiving

Incoming stanzas are decrypted, turned into events and handed to the router. Handlers can
be sync or async; a failing handler is logged and does not stop the others.

## Events

```python
from aiowapy.events import (
    ChatStateEvent,
    ConnectedEvent,
    DisconnectedEvent,
    EditEvent,
    HistorySyncEvent,
    MessageEvent,
    NotificationEvent,
    PresenceEvent,
    ReactionEvent,
    ReceiptEvent,
    RevokeEvent,
)

@client.router.on(ReceiptEvent)
async def on_receipt(event: ReceiptEvent) -> None:
    print(event.receipt_type, event.message_ids)
```

| Event | When |
|---|---|
| `MessageEvent` | decrypted text/attachment, live or from history sync |
| `ReactionEvent` | emoji reaction, `text` empty when retracted |
| `EditEvent` | someone edited a message |
| `RevokeEvent` | someone deleted a message for everyone |
| `HistorySyncEvent` | a history chunk was stored |
| `ReceiptEvent` | delivery/read confirmation |
| `PresenceEvent` | user came online/offline, last seen |
| `ChatStateEvent` | typing/recording indicator |
| `ConnectedEvent` / `DisconnectedEvent` | connection lifecycle |
| `NotificationEvent` | server notifications not modeled yet (device changes, ...) |

## Filters

`aiowapy.router.F` builds small predicates; combine them with `&`, `|`, `~`:

```python
from aiowapy.router import F

@client.router.message(F.text.startswith("/start"))
async def start(event: MessageEvent) -> None: ...

@client.router.message(F.text.contains("invoice") & F.chat("1203630@g.us"))
async def invoice(event: MessageEvent) -> None: ...

@client.router.message(~F.from_me() & F.media("image"))
async def photo(event: MessageEvent) -> None: ...

@client.router.message(F.custom(lambda e: len(e.text or "") > 500))
async def long_text(event: MessageEvent) -> None: ...
```

Available: `F.text` (`.contains`, `.startswith`, `.endswith`, `.equals`), `F.chat`,
`F.sender`, `F.message_id`, `F.from_me`, `F.media(type)`, `F.custom(predicate)`.

## Reading a message

```python
@client.router.message(F.text)
async def handler(event: MessageEvent) -> None:
    print(event.chat_jid)      # where it came from
    print(event.sender_jid)    # who wrote it (group participant for groups)
    print(event.message_id)
    print(event.text)
    print(event.timestamp)     # unix seconds from the server
    print(event.media)         # MediaInfo or None
    print(event.from_me)
    print(event.raw)           # the original Node, if you need more
```

## Read and delivery receipts

Incoming messages are acknowledged automatically (`receipt type="delivery"`), which is
what makes your bot look online. Turn it off with `auto_receipts=False` and send your
own:

```python
await client.mark_read(event)                # receipt type="read"
await client.mark_read(event, receipt_type="delivery")
```

## Retry receipts

If decryption fails, the library asks the sender to resend (`receipt type="retry"`),
and from the second attempt it includes a fresh one-time prekey so the sender can start
a new session. Five attempts is the ceiling.

If *our* outgoing message fails on the other side, they send us a retry request; the
library drops the broken session and resends the stored payload from its outbox.

## Handler errors

`router.on_error` receives `(exception, event)`; without it the traceback is logged. One
broken handler never silences the rest.
