from __future__ import annotations

import pytest

from wapy.messaging.devices import (
    CachedDeviceResolver,
    DeviceError,
    DeviceInfo,
)
from wapy.messaging.messenger import MessagingError, Messenger, SendResult
from wapy.protocol.messages import EncryptedDevice
from wapy.protocol.wabinary import Node

JID = "491234567890@s.whatsapp.net"


def make_device(device_jid: str) -> DeviceInfo:
    return DeviceInfo(
        jid=device_jid,
        identity_key=b"\x01" * 32,
        signed_pre_key=b"\x02" * 32,
        signed_pre_key_id=1,
        registration_id=42,
    )


class FakeFetcher:
    def __init__(self, devices: list[DeviceInfo]) -> None:
        self.devices = devices
        self.calls = 0

    async def fetch(self, jid: str) -> list[DeviceInfo]:
        self.calls += 1
        return list(self.devices)


class FakeDevices:
    def __init__(self, devices: list[DeviceInfo]) -> None:
        self._devices = devices
        self.calls = 0

    async def devices(self, jid: str) -> list[DeviceInfo]:
        self.calls += 1
        return list(self._devices)


class FakeSessions:
    def __init__(self, *, failing: set[str] | None = None) -> None:
        self.failing = failing or set()
        self.seen: list[str] = []

    async def encrypt(self, device: DeviceInfo, plaintext: bytes) -> EncryptedDevice:
        self.seen.append(device.jid)
        if device.jid in self.failing:
            raise RuntimeError("no session")
        return EncryptedDevice(device_jid=device.jid, ciphertext=b"cipher-" + plaintext)


class FakeSender:
    def __init__(self, *, acked: bool = True) -> None:
        self.sent: list[Node] = []
        self.acked = acked
        self.waited: list[tuple[str, float]] = []

    async def send(self, node: Node) -> None:
        self.sent.append(node)

    async def wait_for_ack(self, message_id: str, *, timeout: float) -> bool:
        self.waited.append((message_id, timeout))
        return self.acked


def build(
    devices: list[DeviceInfo], **kwargs: object
) -> tuple[Messenger, FakeSender, FakeSessions]:
    sender = FakeSender(**kwargs)  # type: ignore[arg-type]
    sessions = FakeSessions()
    messenger = Messenger(sender, FakeDevices(devices), sessions, id_factory=lambda: "MSG1")
    return messenger, sender, sessions


async def test_send_text_builds_one_enc_per_device() -> None:
    devices = [
        make_device("491234567890:1@s.whatsapp.net"),
        make_device("491234567890:2@s.whatsapp.net"),
    ]
    messenger, sender, sessions = build(devices)

    result = await messenger.send_text(JID, "hi")

    assert result.sent == [device.jid for device in devices]
    assert result.failed == []
    assert result.acked is True
    assert sessions.seen == [device.jid for device in devices]

    node = sender.sent[0]
    assert node.tag == "message"
    assert node.attrs["to"] == JID
    assert node.attrs["id"] == "MSG1"
    assert isinstance(node.content, list) and len(node.content) == 2


async def test_message_carries_the_encoded_text() -> None:
    from wapy.protocol.messages import decode_text

    messenger, sender, _ = build([make_device("1:1@s.whatsapp.net")])
    await messenger.send_text(JID, "hello")
    enc = sender.sent[0].content[0]  # type: ignore[index]
    assert isinstance(enc.content, bytes)
    assert enc.content.startswith(b"cipher-")
    # the encrypted payload is a Message protobuf, not the raw text
    assert decode_text(enc.content[len(b"cipher-") :]) == "hello"


async def test_without_waiting_no_ack_is_requested() -> None:
    messenger, sender, _ = build([make_device("1:1@s.whatsapp.net")])
    result = await messenger.send_text(JID, "hi", wait_for_message=False)
    assert result.acked is None
    assert sender.waited == []


async def test_missing_ack_is_reported_but_not_an_error() -> None:
    messenger, _, _ = build([make_device("1:1@s.whatsapp.net")], acked=False)
    result = await messenger.send_text(JID, "hi")
    assert result.acked is False
    assert result.delivered_to_someone is True


async def test_one_failing_device_does_not_sink_the_message() -> None:
    devices = [make_device("1:1@s.whatsapp.net"), make_device("1:2@s.whatsapp.net")]
    sender = FakeSender()
    sessions = FakeSessions(failing={"1:2@s.whatsapp.net"})
    messenger = Messenger(sender, FakeDevices(devices), sessions, id_factory=lambda: "M")

    result = await messenger.send_text(JID, "hi")

    assert result.sent == ["1:1@s.whatsapp.net"]
    assert result.failed == [("1:2@s.whatsapp.net", "no session")]
    assert len(sender.sent[0].content) == 1  # type: ignore[arg-type]


async def test_all_devices_failing_raises() -> None:
    devices = [make_device("1:1@s.whatsapp.net")]
    messenger = Messenger(
        FakeSender(),
        FakeDevices(devices),
        FakeSessions(failing={"1:1@s.whatsapp.net"}),
        id_factory=lambda: "M",
    )
    with pytest.raises(MessagingError):
        await messenger.send_text(JID, "hi")


async def test_no_devices_raises() -> None:
    messenger = Messenger(FakeSender(), FakeDevices([]), FakeSessions(), id_factory=lambda: "M")
    with pytest.raises(MessagingError):
        await messenger.send_text(JID, "hi")


async def test_empty_text_is_rejected_before_any_network_call() -> None:
    from wapy.protocol.messages import MessageError

    messenger, sender, _ = build([make_device("1:1@s.whatsapp.net")])
    with pytest.raises(MessageError):
        await messenger.send_text(JID, "")
    assert sender.sent == []


async def test_device_cache_serves_repeat_calls() -> None:
    fetcher = FakeFetcher([make_device("1:1@s.whatsapp.net")])
    clock = [0.0]
    resolver = CachedDeviceResolver(fetcher, ttl=300, clock=lambda: clock[0])

    await resolver.devices(JID)
    await resolver.devices(JID)
    assert fetcher.calls == 1


async def test_device_cache_expires() -> None:
    fetcher = FakeFetcher([make_device("1:1@s.whatsapp.net")])
    clock = [0.0]
    resolver = CachedDeviceResolver(fetcher, ttl=300, clock=lambda: clock[0])

    await resolver.devices(JID)
    clock[0] = 301.0
    await resolver.devices(JID)
    assert fetcher.calls == 2


async def test_device_cache_invalidation() -> None:
    fetcher = FakeFetcher([make_device("1:1@s.whatsapp.net")])
    resolver = CachedDeviceResolver(fetcher, ttl=300, clock=lambda: 0.0)

    await resolver.devices(JID)
    resolver.invalidate(JID)
    await resolver.devices(JID)
    assert fetcher.calls == 2


async def test_zero_ttl_is_rejected() -> None:
    with pytest.raises(DeviceError):
        CachedDeviceResolver(FakeFetcher([]), ttl=0)


def test_send_result_defaults() -> None:
    result = SendResult(message_id="M")
    assert result.sent == [] and result.failed == [] and result.acked is None
    assert result.delivered_to_someone is False
