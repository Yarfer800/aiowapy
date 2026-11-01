# Storage and history

`*.session` is a single SQLite file that holds the whole state of the account, in the
spirit of Pyrogram: credentials, Signal sessions, prekeys, app state, **chats, contacts,
messages and reactions**.

## Chats and contacts

```python
chats = await client.get_chats()          # newest conversation first
users = await client.get_users()          # contacts the bot has seen
groups = await client.get_groups()

chat = await client.get_chat(jid)
print(chat.name)          # contact name -> push name -> subject -> jid
print(chat.kind)          # "user" or "group"
print(chat.last_message_at, chat.total_messages)
```

Names are refined, never wiped: a `None` from a later stanza does not erase what is
already stored. A push name comes from the `notify` attribute of incoming messages and
from history sync; a contact name is yours:

```python
await client.set_contact_name(jid, "Mom")
await client.save_contact(jid, "Mom", phone="49123456789")
```

## Message history

```python
history = await client.get_chat_history(chat_jid, limit=50)
for message in history:                   # newest first
    print(message.timestamp, message.sender_jid, message.text, message.outgoing)

older = await client.get_chat_history(
    chat_jid, limit=50, before_timestamp=history[-1].timestamp
)

one = await client.get_message(chat_jid, message_id)
```

A stored message carries the full attachment description, so downloading works months
later:

```python
data = await client.download_stored(message)
```

You can write rows yourself — useful for importing an export or seeding a bot:

```python
await client.save_message(chat_jid, message_id, "hello", sender_jid=jid, timestamp=now)
```

## Reactions

```python
pairs = await client.reactions(chat_jid, message_id)   # [(sender_jid, emoji), ...]
```

## History sync

WhatsApp sends history to a new device in encrypted chunks announced by a protocol
message. The library downloads, decrypts and unpacks them, writes peers and messages to
the session file, and emits `HistorySyncEvent`:

```python
@client.router.on(HistorySyncEvent)
async def on_chunk(event: HistorySyncEvent) -> None:
    print(f"{event.chats} chats, {event.messages} messages, more={event.has_more}")
```

The chunk format:

| Step | Detail |
|---|---|
| Announcement | `ProtocolMessage` type 5 with `HistorySyncNotification` |
| Payload | encrypted blob on a media host, media type `md-msg-hist` |
| Encoding | AES-CBC + HMAC, then gzip, then protobuf `HistorySync` |
| Content | conversations, messages, push names, phone→LID mappings |

Duplicates are filtered: a message id is stored once, no matter how many chunks mention
it.

## Tables

| Table | Contents |
|---|---|
| `creds` | device credentials (private keys, base64) |
| `prekeys` | one-time prekeys and their upload state |
| `sessions` | Signal session records per device JID |
| `sender_keys` | sender key chains per `(group, member)` |
| `peers` | users and groups with names |
| `messages` | messages, `outgoing` flag, media JSON |
| `reactions` | one row per `(chat, message, sender)` |
| `deleted_messages` | revoked message ids |
| `lid_mappings` | phone-number JID → LID JID |
| `app_state_*` | sync keys, collection versions and the local copy |
| `groups` | cached group metadata |

Migrations are numbered files in `wapy/store/migrations/`; the schema version lives in
`meta`.
