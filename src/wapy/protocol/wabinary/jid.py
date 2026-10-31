"""Wire representation of a JID: `user[:device][_agent]@server`."""

from __future__ import annotations

from dataclasses import dataclass

WA_DOMAIN_WHATSAPP = 0
WA_DOMAIN_LID = 1
WA_DOMAIN_HOSTED = 128
WA_DOMAIN_HOSTED_LID = 129

_DOMAIN_TO_SERVER = {
    WA_DOMAIN_LID: "lid",
    WA_DOMAIN_HOSTED: "hosted",
    WA_DOMAIN_HOSTED_LID: "hosted.lid",
}


@dataclass(frozen=True, slots=True)
class FullJid:
    user: str
    server: str
    device: int | None = None
    agent: int | None = None
    domain_type: int = WA_DOMAIN_WHATSAPP


def jid_encode(
    user: str | int | None,
    server: str,
    device: int | None = None,
    agent: int | None = None,
) -> str:
    """Build a JID. Zero device/agent values are omitted, matching the reference."""
    parts = "" if user is None else str(user)
    if agent:
        parts += f"_{agent}"
    if device:
        parts += f":{device}"
    return f"{parts}@{server}"


def jid_decode(jid: str | None) -> FullJid | None:
    """Parse a JID; returns None when the string is not a JID."""
    if not jid:
        return None
    separator = jid.find("@")
    if separator < 0:
        return None
    server = jid[separator + 1 :]
    user_combined = jid[:separator]
    user_agent, _, device_raw = user_combined.partition(":")
    user, _, agent_raw = user_agent.partition("_")
    device = int(device_raw) if device_raw else None
    agent = int(agent_raw) if agent_raw else None
    if server == "lid":
        domain_type = WA_DOMAIN_LID
    elif server == "hosted":
        domain_type = WA_DOMAIN_HOSTED
    elif server == "hosted.lid":
        domain_type = WA_DOMAIN_HOSTED_LID
    elif agent is not None:
        domain_type = agent
    else:
        domain_type = WA_DOMAIN_WHATSAPP
    return FullJid(
        user=user,
        server=server,
        device=device,
        agent=agent,
        domain_type=domain_type,
    )


def server_from_domain_type(server: str, domain_type: int | None) -> str:
    """Server implied by the domain type (used for AD_JID)."""
    if domain_type is None:
        return server
    return _DOMAIN_TO_SERVER.get(domain_type, server)
