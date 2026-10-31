from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from wapy.events import AnyEvent, MessageEvent

logger = logging.getLogger("wapy")

Handler = Callable[[Any], Awaitable[None] | None]


class Filter:
    """Predicate over an event, combinable with `&`, `|` and `~`."""

    def __call__(self, event: AnyEvent) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    def __and__(self, other: Filter) -> Filter:
        return _All(self, other)

    def __or__(self, other: Filter) -> Filter:
        return _AnyOf(self, other)

    def __invert__(self) -> Filter:
        return _Not(self)


class _All(Filter):
    def __init__(self, *filters: Filter) -> None:
        self._filters = filters

    def __call__(self, event: AnyEvent) -> bool:
        return all(item(event) for item in self._filters)


class _AnyOf(Filter):
    def __init__(self, *filters: Filter) -> None:
        self._filters = filters

    def __call__(self, event: AnyEvent) -> bool:
        return any(item(event) for item in self._filters)


class _Not(Filter):
    def __init__(self, inner: Filter) -> None:
        self._inner = inner

    def __call__(self, event: AnyEvent) -> bool:
        return not self._inner(event)


class _Field(Filter):
    def __init__(self, name: str, expected: object) -> None:
        self._name = name
        self._expected = expected

    def __call__(self, event: AnyEvent) -> bool:
        return bool(getattr(event, self._name, None) == self._expected)


class _Predicate(Filter):
    def __init__(self, predicate: Callable[[AnyEvent], bool]) -> None:
        self._predicate = predicate

    def __call__(self, event: AnyEvent) -> bool:
        return self._predicate(event)


class TextFilter(Filter):
    """Matches events that carry text, optionally constrained by substring or prefix."""

    def __call__(self, event: AnyEvent) -> bool:
        text = getattr(event, "text", None)
        return isinstance(text, str) and bool(text)

    def contains(self, fragment: str) -> Filter:
        return _All(self, _Predicate(lambda event: fragment in (getattr(event, "text", "") or "")))

    def startswith(self, prefix: str) -> Filter:
        return _All(
            self, _Predicate(lambda event: (getattr(event, "text", "") or "").startswith(prefix))
        )

    def endswith(self, suffix: str) -> Filter:
        return _All(
            self, _Predicate(lambda event: (getattr(event, "text", "") or "").endswith(suffix))
        )

    def equals(self, expected: str) -> Filter:
        return _All(self, _Predicate(lambda event: getattr(event, "text", None) == expected))


class _MediaFilter(Filter):
    def __init__(self, media_type: str | None) -> None:
        self._media_type = media_type

    def __call__(self, event: AnyEvent) -> bool:
        media = getattr(event, "media", None)
        if media is None:
            return False
        return self._media_type is None or media.media_type == self._media_type


class F:
    """Ready-made filters, in the style of a bot framework's `F` namespace."""

    text = TextFilter()

    @staticmethod
    def chat(jid: str) -> Filter:
        return _Field("chat_jid", jid)

    @staticmethod
    def sender(jid: str) -> Filter:
        return _Field("sender_jid", jid)

    @staticmethod
    def message_id(message_id: str) -> Filter:
        return _Field("message_id", message_id)

    @staticmethod
    def from_me(value: bool = True) -> Filter:
        return _Field("from_me", value)

    @staticmethod
    def media(media_type: str | None = None) -> Filter:
        return _MediaFilter(media_type)

    @staticmethod
    def custom(predicate: Callable[[AnyEvent], bool]) -> Filter:
        return _Predicate(predicate)


class Router:
    """Event handlers with optional filters, dispatched in registration order."""

    def __init__(self) -> None:
        self._handlers: list[tuple[type, tuple[Filter, ...], Handler]] = []
        self.on_error: Callable[[BaseException, AnyEvent], None] | None = None

    def on(self, event_type: type, *filters: Filter) -> Callable[[Handler], Handler]:
        def register(handler: Handler) -> Handler:
            self._handlers.append((event_type, filters, handler))
            return handler

        return register

    def message(self, *filters: Filter) -> Callable[[Handler], Handler]:
        return self.on(MessageEvent, *filters)

    def remove(self, handler: Handler) -> None:
        self._handlers = [item for item in self._handlers if item[2] != handler]

    async def dispatch(self, event: AnyEvent) -> int:
        """Call every matching handler; returns how many ran."""
        called = 0
        for event_type, filters, handler in list(self._handlers):
            if not isinstance(event, event_type):
                continue
            try:
                if not all(item(event) for item in filters):
                    continue
            except Exception as exc:  # a broken filter must not swallow the event
                self._report(exc, event)
                continue
            called += 1
            try:
                result = handler(event)
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:
                self._report(exc, event)
        return called

    def _report(self, exc: BaseException, event: AnyEvent) -> None:
        if self.on_error is not None:
            self.on_error(exc, event)
        else:
            logger.exception("handler failed for %s", type(event).__name__, exc_info=exc)
