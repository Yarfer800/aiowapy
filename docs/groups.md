# Groups

Group messages do not use per-device Signal sessions for the body. The sender creates a
**sender key** — a symmetric chain shared by the group members — encrypts once and signs
the ciphertext. The key distribution message (SKDM) travels pairwise to every member
device, attached to the same stanza.

## Sending

```python
await client.send_text("120363000000000001@g.us", "hello everyone")
await client.send_image(group_jid, data, caption="look")
```

Nothing special is needed: `send_text`/`send_media` detect `@g.us` and switch to the
group pipeline. Under the hood one stanza contains:

- `<participants>` with one `<enc type="pkmsg">` per member device (the SKDM),
- a single `<enc type="skmsg">` with the encrypted body,
- a `phash` attribute summarizing the participant list.

## Querying

```python
info = await client.group_info(group_jid)
print(info.subject, info.owner_jid, info.is_locked, info.disappearing_timer)
for participant in info.participants:
    print(participant.jid, participant.is_admin, participant.is_super_admin)

groups = await client.joined_groups()
```

Results are cached for 5 minutes in the session file; `group_info(jid, refresh=True)`
forces a server round trip.

## Managing

```python
group = await client.create_group("Team", [jid1, jid2])

await client.update_group_participants(group, "add", [jid3])
await client.update_group_participants(group, "remove", [jid3])
await client.update_group_participants(group, "promote", [jid4])
await client.update_group_participants(group, "demote", [jid4])

await client.leave_group(group)
```

Participant JIDs are stripped of their device suffix before they are sent: group
membership is per user, not per device.

## Receiving

A group message arrives with `from` set to the group and `participant` set to the
sender. The library:

1. decrypts the pairwise `<enc>` entries, which carry the sender key distribution,
2. stores the sender key under `(group, sender)`,
3. decrypts the `<enc type="skmsg">` payload,
4. dispatches `MessageEvent` with `chat_jid` = group and `sender_jid` = participant.

Out-of-order delivery is handled: skipped iterations are cached and replayed, up to 2000
messages ahead. A message older than the chain is rejected.

## Not implemented

- joining by invite link (`chat.whatsapp.com/...`),
- invite link creation and revocation,
- community/sub-group operations,
- privacy tokens for adding contacts you have never talked to.
