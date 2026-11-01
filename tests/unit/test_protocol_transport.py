from __future__ import annotations

import pytest

from aiowapy.protocol.noise import INTRO_MAGIC
from aiowapy.protocol.transport import (
    FrameParser,
    TransportError,
    build_intro_header,
    encode_frame,
)


def test_intro_header_plain() -> None:
    assert build_intro_header() == INTRO_MAGIC == b"WA\x06\x03"


def test_intro_header_with_routing() -> None:
    routing = bytes.fromhex("082308120808")
    header = build_intro_header(routing)
    assert header[:4] == b"ED\x00\x01"
    assert int.from_bytes(header[4:7], "big") == len(routing)
    assert header[7 : 7 + len(routing)] == routing
    assert header[7 + len(routing) :] == INTRO_MAGIC


def test_encode_frame_without_intro() -> None:
    frame = encode_frame(b"hello")
    assert frame == b"\x00\x00\x05hello"


def test_encode_frame_with_intro() -> None:
    frame = encode_frame(b"hi", intro=INTRO_MAGIC, include_intro=True)
    assert frame == INTRO_MAGIC + b"\x00\x00\x02hi"


def test_encode_frame_matches_captured_sizes() -> None:
    body = bytes(36)
    assert len(encode_frame(body, intro=INTRO_MAGIC, include_intro=True)) == 43
    assert len(encode_frame(bytes(347))) == 350


def test_encode_frame_rejects_oversized_payload() -> None:
    with pytest.raises(TransportError):
        encode_frame(bytes((1 << 24) + 1))


def test_parser_handles_partial_data() -> None:
    parser = FrameParser()
    frame = encode_frame(b"payload")
    assert parser.feed(frame[:2]) == []
    assert parser.feed(frame[2:5]) == []
    assert parser.feed(frame[5:]) == [b"payload"]


def test_parser_handles_several_frames_in_one_chunk() -> None:
    parser = FrameParser()
    data = encode_frame(b"one") + encode_frame(b"two") + encode_frame(b"three")
    assert parser.feed(data) == [b"one", b"two", b"three"]


def test_parser_keeps_remainder_for_next_chunk() -> None:
    parser = FrameParser()
    data = encode_frame(b"one") + encode_frame(b"two")
    assert parser.feed(data[:-1]) == [b"one"]
    assert parser.feed(data[-1:]) == [b"two"]


def test_parser_waits_for_a_large_frame() -> None:
    parser = FrameParser()
    # A 3-byte length can never exceed the 16 MiB limit, so the parser buffers.
    assert parser.feed(b"\xff\xff\xff" + bytes(10)) == []
