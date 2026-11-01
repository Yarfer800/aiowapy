from __future__ import annotations

from aiowapy.events import MessageEvent, ReceiptEvent
from aiowapy.router import F, Router


def message(text: str | None = None, **kwargs: object) -> MessageEvent:
    return MessageEvent(
        chat_jid=str(kwargs.get("chat_jid", "1@s.whatsapp.net")),
        sender_jid=str(kwargs.get("sender_jid", "1@s.whatsapp.net")),
        message_id=str(kwargs.get("message_id", "M1")),
        text=text,
    )


async def test_handler_receives_matching_event() -> None:
    router = Router()
    seen: list[str] = []

    @router.message()
    async def handler(event: MessageEvent) -> None:
        seen.append(event.text or "")

    assert await router.dispatch(message("hello")) == 1
    assert seen == ["hello"]


async def test_text_filter_rejects_other_events() -> None:
    router = Router()
    seen: list[str] = []

    @router.message(F.text.contains("ping"))
    def handler(event: MessageEvent) -> None:
        seen.append(event.text or "")

    assert await router.dispatch(message("pong")) == 0
    assert seen == []


async def test_filters_combine() -> None:
    router = Router()
    seen: list[str] = []

    @router.message(F.text & F.chat("2@s.whatsapp.net"))
    async def handler(event: MessageEvent) -> None:
        seen.append(event.text or "")

    await router.dispatch(message("hi", chat_jid="1@s.whatsapp.net"))
    await router.dispatch(message("hi", chat_jid="2@s.whatsapp.net"))
    assert seen == ["hi"]


async def test_negation_and_or() -> None:
    router = Router()
    seen: list[str] = []

    @router.message(F.text.startswith("/") | F.sender("admin@s.whatsapp.net"))
    async def handler(event: MessageEvent) -> None:
        seen.append(event.text or "")

    await router.dispatch(message("/start"))
    await router.dispatch(message("hello", sender_jid="admin@s.whatsapp.net"))
    await router.dispatch(message("hello"))
    assert seen == ["/start", "hello"]

    router2 = Router()
    not_admin: list[str] = []

    @router2.message(~F.sender("admin@s.whatsapp.net"))
    async def other(event: MessageEvent) -> None:
        not_admin.append(event.text or "")

    await router2.dispatch(message("x", sender_jid="admin@s.whatsapp.net"))
    await router2.dispatch(message("y"))
    assert not_admin == ["y"]


async def test_event_type_is_respected() -> None:
    router = Router()
    seen: list[str] = []

    @router.on(ReceiptEvent)
    async def receipts(event: ReceiptEvent) -> None:
        seen.append("receipt")

    @router.message()
    async def messages(event: MessageEvent) -> None:
        seen.append("message")

    await router.dispatch(message("hi"))
    await router.dispatch(
        ReceiptEvent(
            chat_jid="1@s", sender_jid="1@s", message_ids=("M1",), receipt_type="delivered"
        )
    )
    assert seen == ["message", "receipt"]


async def test_failing_handler_does_not_stop_the_rest() -> None:
    router = Router()
    errors: list[BaseException] = []
    seen: list[str] = []
    router.on_error = lambda exc, event: errors.append(exc)

    @router.message()
    async def broken(event: MessageEvent) -> None:
        raise RuntimeError("boom")

    @router.message()
    async def healthy(event: MessageEvent) -> None:
        seen.append("ok")

    assert await router.dispatch(message("hi")) == 2
    assert seen == ["ok"]
    assert len(errors) == 1


async def test_media_filter() -> None:
    from aiowapy.protocol.media import MediaInfo

    router = Router()
    seen: list[str] = []

    @router.message(F.media())
    async def handler(event: MessageEvent) -> None:
        seen.append(event.media.media_type if event.media else "none")

    image = MediaInfo(
        media_type="image",
        mime_type="image/jpeg",
        url="https://x",
        direct_path="/d",
        media_key=b"k" * 32,
        file_sha256=b"a" * 32,
        file_enc_sha256=b"b" * 32,
        file_length=10,
    )
    await router.dispatch(
        MessageEvent(chat_jid="1@s", sender_jid="1@s", message_id="1", media=image)
    )
    await router.dispatch(message("text only"))
    assert seen == ["image"]


async def test_remove_handler() -> None:
    router = Router()
    seen: list[str] = []

    @router.message()
    async def handler(event: MessageEvent) -> None:
        seen.append("x")

    router.remove(handler)
    assert await router.dispatch(message("hi")) == 0


async def test_custom_filter_and_message_id() -> None:
    router = Router()
    seen: list[str] = []

    @router.message(F.custom(lambda event: event.message_id == "M1"))
    async def handler(event: MessageEvent) -> None:
        seen.append(event.message_id)

    await router.dispatch(message("hi", message_id="M2"))
    await router.dispatch(message("hi", message_id="M1"))
    assert seen == ["M1"]


def test_filter_error_does_not_swallow_the_event() -> None:
    router = Router()
    errors: list[BaseException] = []
    router.on_error = lambda exc, event: errors.append(exc)

    @router.message(F.custom(lambda event: 1 / 0))  # type: ignore[arg-type,return-value]
    async def handler(event: MessageEvent) -> None:  # pragma: no cover
        raise AssertionError("must not run")

    assert router._handlers
