# Sending

Every send goes through `Messenger`: it enumerates the recipient's devices, encrypts one
Signal message per device, wraps everything into a `<message>` stanza and waits for the
server ack.

## Text

```python
result = await client.send_text("49123456789@s.whatsapp.net", "hello")
print(result.message_id, result.sent, result.failed, result.acked)
```

`SendResult` has four fields:

| Field | Meaning |
|---|---|
| `message_id` | id of the stanza, also stored in the session file |
| `sent` | device JIDs the payload was encrypted for |
| `failed` | `(device_jid, reason)` for devices that could not be encrypted |
| `acked` | `True`/`False` for the server ack, `None` if not awaited |

A message counts as delivered when at least one device accepted it; per-device failures
are reported, not raised. `wait_for_message=False` returns immediately after the frame
is on the wire.

## Replies

```python
await client.send_text(chat, "answer", quote=message_id)
```

The quoted message is looked up in the session file, so its text, sender and id are
attached as `ContextInfo`. A reply to a message the bot never saw still works, just
without the quoted body.

## Reactions

```python
await client.send_reaction(chat, message_id, "\U0001f44d")
await client.send_reaction(chat, message_id, "")      # retract
```

Incoming reactions are stored per sender and dispatched as `ReactionEvent`; read them
with `await client.reactions(chat, message_id)`.

## Edit and delete

```python
await client.edit_message(chat, message_id, "corrected text")
await client.revoke_message(chat, message_id)
```

Incoming edits update the stored row, incoming revokes blank its text and mark it
delete. Both produce `EditEvent` and `RevokeEvent`.

## Message types in the stanza

The `type` attribute of `<message>` is set per content: `text`, `reaction`, `image`,
`video`, `audio`, `ptt`, `document`, `sticker`. Group messages add a single
`<enc type="skmsg">` next to the per-device `<participants>` block.

## Send results are stored

Every outgoing message is written to `.session` with `outgoing=True`, so
[history](storage.md) returns the conversation as a whole. Media descriptions are stored
too, which is what `download_stored()` uses.
