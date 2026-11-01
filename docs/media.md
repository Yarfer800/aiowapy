# Media

Attachments are encrypted locally, uploaded to a WhatsApp media host and only the
metadata travels through the chat socket.

## Sending

```python
await client.send_image(chat, picture_bytes, caption="look")
await client.send_video(chat, video_bytes, caption="clip", seconds=12)
await client.send_audio(chat, ogg_bytes, voice_note=True, seconds=8)
await client.send_document(
    chat, pdf_bytes, file_name="report.pdf", mime_type="application/pdf"
)
```

Or the generic form:

```python
from aiowapy.protocol.media import MEDIA_IMAGE

await client.send_media(
    chat,
    data,
    MEDIA_IMAGE,
    caption="text",
    mime_type="image/jpeg",
    width=1280,
    height=720,
)
```

What happens under the hood:

1. A random 32-byte media key is generated.
2. The file is encrypted with AES-256-CBC and an HMAC-SHA256 truncated to 10 bytes;
   the key is expanded with HKDF using `WhatsApp Image Keys` (or Video/Audio/Document).
3. `file_sha256` and `file_enc_sha256` are computed.
4. The encrypted blob is POSTed to a media host obtained from `<iq xmlns="w:m">`.
5. The message contains url, direct path, media key, hashes and size.

## Receiving

Incoming attachments arrive as metadata in the `MessageEvent`; the bytes are downloaded
on demand:

```python
@client.router.message(F.media("image"))
async def on_image(event: MessageEvent) -> None:
    data = await client.download_media(event.media)
```

`download_media` fetches the encrypted blob, verifies its MAC, decrypts it and checks
`file_sha256` against the metadata. A mismatch is an error, not silent corruption.

Messages read back from the session file work the same way:

```python
for message in await client.get_chat_history(chat, limit=20):
    if message.media:
        data = await client.download_stored(message)
```

## Types and field mapping

| Media type | Message field | HKDF info |
|---|---|---|
| `image` | `ImageMessage` | `WhatsApp Image Keys` |
| `video` | `VideoMessage` | `WhatsApp Video Keys` |
| `audio` / `ptt` | `AudioMessage` | `WhatsApp Audio Keys` |
| `document` | `DocumentMessage` | `WhatsApp Document Keys` |
| `sticker` | `StickerMessage` | `WhatsApp Image Keys` |

Captions, file names, durations (`seconds`), dimensions and the voice-note flag are
carried in the same protobuf and round-trip through the session file.

## Thumbnails and streaming

JPEG thumbnails, video sidecars and streaming metadata are not produced. Clients show a
placeholder instead of a preview until the file is downloaded.
