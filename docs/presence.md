# Presence

```python
await client.send_presence(True)            # available, announces the push name
await client.send_presence(False)           # unavailable

await client.subscribe_presence(jid)        # ask for this user's updates

await client.send_typing(jid, composing=True)
await client.send_typing(jid, composing=True, media="audio")   # recording a voice note
await client.send_typing(jid, composing=False)                 # stopped
```

Incoming updates arrive as events:

```python
@client.router.on(PresenceEvent)
async def presence(event: PresenceEvent) -> None:
    if event.available:
        print(event.jid, "is online")
    elif event.last_seen:
        print(event.jid, "last seen", event.last_seen)
    # last_seen is None when the user hides it (last="deny")

@client.router.on(ChatStateEvent)
async def typing(event: ChatStateEvent) -> None:
    print(event.jid, event.state, event.media)
```

Notes:

- The bot is announced as available right after connecting; without it contacts see no
  name.
- The server only forwards presence for users you subscribed to, and usually only while
  you are online yourself.
- `last` with the value `deny` means the user hides their last-seen time; the library
  maps it to `last_seen=None`.
