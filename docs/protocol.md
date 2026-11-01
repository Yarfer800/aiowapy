# Protocol and limitations

## How it fits together

```
Client            public API: connect, send, receive, reconnect
├── Router / events       application handlers and filters
├── Messenger             device list -> Signal ciphertext -> <message> stanza
│   ├── DeviceResolver    usync + prekey bundles, cached
│   ├── SignalSessions    X3DH + double ratchet, stored per device
│   └── NodeSender        transport send + ack correlation
├── MessageReceiver       decrypt pairwise and sender-key payloads
├── GroupService          group info and membership
├── GroupSender           sender keys (SKDM + skmsg)
├── MediaStorage          media upload/download, CDN metadata
├── AppStateSync          patches, MACs, LTHash
├── HistorySyncService    encrypted history blobs
└── SessionStore          one SQLite file
NodeStream -> WhatsAppTransport -> Noise -> WebSocket
```

Layer rules are enforced by a test: `protocol` and `crypto` never import the client,
`store` never imports the network, and so on.

## Wire details worth knowing

- Frames are `[3-byte length][body]`; the first frame is prefixed with the `WA` intro
  header.
- Noise is XX with the WhatsApp prologue; the transport keys are derived per direction.
- Server errors during pairing arrive as `stream:error` with the code in an attribute,
  not a child node. `515` means "device accepted, reconnect with a login payload".
- `<message>` carries per-device payloads inside `<participants>`; a group body is a
  single `<enc type="skmsg">` at the root.
- Prekey messages include a `<device-identity>` blob so the receiver can check which
  device started the session.
- Server `iq type="set"` requests must be answered with an `iq type="result"` carrying
  the same id, otherwise the connection is dropped.

## Status

The implementation is covered by 700+ offline tests, including cross-checks where one
side of a Signal or sender-key session is built by test code and decrypted by the
library.

**Live traffic has not been exercised yet.** The account used for development is
rate-limited by WhatsApp on device linking, so no message has been delivered end to end
in production. Treat the first live run as validation, not as a formality.

## Not implemented

| Missing | Impact |
|---|---|
| Calls | none for bots |
| Channels (newsletters) | cannot read or post to channels |
| Statuses | cannot view or post stories |
| Polls, buttons, lists | no structured messages |
| LID-based encryption | sessions start on phone-number devices; LID mappings are stored but unused |
| Privacy tokens (`tctoken`) | adding strangers to groups may be rejected |
| Group invite links | cannot join or create invite links |
| History on demand | history arrives only when the phone sends it |
| Thumbnails, streaming sidecars | no previews for media |

## Reference implementations

Behaviour was cross-checked against [whatsmeow](https://github.com/tulir/whatsmeow)
(MPL-2.0) and [Baileys](https://github.com/WhiskeySockets/Baileys) (MIT). No code is
copied: the wire formats and state machines were re-implemented, and this project stays
MIT.
