# App state

Contacts, mutes, pins, archives and read markers are not messages: they live in a
key-value store synchronized through patches. The phone owns the keys and shares them
with linked devices; patches are encrypted with those keys, chained by an additive
integrity hash.

## Sync

```python
results = await client.sync_app_state()
for result in results:
    print(result.name, result.version, result.applied, result.skipped)
```

Each collection (`critical_block`, `critical_unblock_low`, `regular`, `regular_high`,
`regular_low`) is fetched from the stored version, verified and applied. Unknown
mutations are counted as `skipped` instead of failing the whole patch.

What is verified:

| Check | Detail |
|---|---|
| Value MAC | HMAC-SHA512 over operation, key id and ciphertext, truncated |
| Index MAC | HMAC-SHA256 of the JSON index |
| Patch MAC | snapshot MAC, value MACs, version and collection name |
| Integrity | LTHash: 128-byte additive hash over `WhatsApp Patch Integrity` |

Local copy:

```python
entries = await client.app_state_entries("regular_high")
for index_json, value, timestamp in entries:
    print(index_json, timestamp)
```

## Writing

```python
await client.mute_chat(jid, True)          # mute forever
await client.pin_chat(jid, True)
await client.mark_chat_read(jid, True)
await client.set_push_name("bot")
```

Each call builds one patch, updates the integrity hash and pushes it. The reply is
checked for a `type="error"` collection; a conflict raises `AppStateSyncError`.

## Keys

Keys arrive from the phone in a protocol message (`AppStateSyncKeyShare`). The library
stores them, then runs a sync in the background:

```python
@client.router.on(NotificationEvent)
async def notifications(event: NotificationEvent) -> None:
    print(event.kind)
```

If a key is missing when a patch arrives, syncing that collection fails with
`AppStateSyncError`; the local copy stays untouched.
