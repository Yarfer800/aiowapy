# Changelog

All notable changes to this project. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] — unreleased

First public release. The protocol is implemented natively; live traffic is not yet
validated against production WhatsApp.

### Added

- Noise XX handshake, WABinary codec, WebSocket transport, keepalive and reconnect.
- QR pairing and phone-number pairing, prekey publication.
- Signal: X3DH, double ratchet, session serialization, prekey and one-time prekey
  sessions.
- Sending: text, replies, reactions, edits, revokes; images, video, audio, voice notes,
  documents, stickers.
- Receiving: pairwise and sender-key decryption, automatic delivery receipts, retry
  receipts in both directions.
- Groups: info, create, participants, leave, sender keys with out-of-order handling.
- Media: encrypted upload and download with hash verification.
- App state: patch sync, MAC verification, LTHash, mute/pin/mark-read/push-name.
- History sync: encrypted chunk download, unpacking, storage.
- Storage in one `.session` file: chats, contacts, messages, reactions, LID mappings.
- Filter router with `F` helpers, events, reconnect lifecycle.
