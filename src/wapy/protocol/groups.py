from __future__ import annotations

from dataclasses import dataclass, field

from wapy.errors import WapyError
from wapy.protocol.stream import child, children
from wapy.protocol.wabinary import Node

GROUP_SERVER = "@g.us"
S_WHATSAPP_NET = "@s.whatsapp.net"

ACTION_ADD = "add"
ACTION_REMOVE = "remove"
ACTION_PROMOTE = "promote"
ACTION_DEMOTE = "demote"
_PARTICIPANT_ACTIONS = {ACTION_ADD, ACTION_REMOVE, ACTION_PROMOTE, ACTION_DEMOTE}

ADMIN = "admin"
SUPERADMIN = "superadmin"


class GroupError(WapyError):
    """A group request or response is malformed."""


@dataclass(frozen=True, slots=True)
class GroupParticipant:
    jid: str
    is_admin: bool = False
    is_super_admin: bool = False
    lid: str | None = None
    phone_number: str | None = None

    @property
    def is_any_admin(self) -> bool:
        return self.is_admin or self.is_super_admin


@dataclass(frozen=True, slots=True)
class GroupInfo:
    jid: str
    subject: str
    owner_jid: str | None = None
    participants: list[GroupParticipant] = field(default_factory=list)
    topic: str | None = None
    topic_id: str | None = None
    is_locked: bool = False
    is_announce: bool = False
    is_ephemeral: bool = False
    disappearing_timer: int = 0
    participant_count: int = 0
    addressing_mode: str | None = None

    @property
    def participant_jids(self) -> list[str]:
        return [participant.jid for participant in self.participants]


def build_group_iq(group_jid: str, iq_type: str, content: list[Node], message_id: str) -> Node:
    return Node(
        tag="iq",
        attrs={"to": group_jid, "type": iq_type, "xmlns": "w:g2", "id": message_id},
        content=content,
    )


def build_group_info_query(group_jid: str, message_id: str) -> Node:
    return build_group_iq(
        group_jid,
        "get",
        [Node(tag="query", attrs={"request": "interactive"})],
        message_id,
    )


def build_joined_groups_query(message_id: str) -> Node:
    return build_group_iq(
        GROUP_SERVER,
        "get",
        [
            Node(
                tag="participating",
                attrs={},
                content=[Node(tag="participants", attrs={}), Node(tag="description", attrs={})],
            )
        ],
        message_id,
    )


def build_create_group(subject: str, participants: list[str], message_id: str) -> Node:
    if not participants:
        raise GroupError("a group needs at least one participant")
    content = [
        Node(
            tag="create",
            attrs={"subject": subject},
            content=[
                Node(
                    tag="participant",
                    attrs={"jid": _bare(jid)},
                )
                for jid in participants
            ],
        )
    ]
    return build_group_iq(GROUP_SERVER, "set", content, message_id)


def build_leave_group(group_jid: str, message_id: str) -> Node:
    return build_group_iq(
        GROUP_SERVER,
        "set",
        [Node(tag="leave", attrs={}, content=[Node(tag="group", attrs={"id": group_jid})])],
        message_id,
    )


def build_participants_update(
    group_jid: str, action: str, participants: list[str], message_id: str
) -> Node:
    if action not in _PARTICIPANT_ACTIONS:
        raise GroupError(f"unknown participant action: {action!r}")
    if not participants:
        raise GroupError("no participants given")
    return build_group_iq(
        group_jid,
        "set",
        [
            Node(
                tag=action,
                attrs={},
                content=[
                    Node(tag="participant", attrs={"jid": _bare(jid)}) for jid in participants
                ],
            )
        ],
        message_id,
    )


def _bare(jid: str) -> str:
    """Group membership is per user, not per device: drop the `:device` part."""
    if ":" in jid and "@" in jid:
        user, rest = jid.split(":", 1)
        server = rest.split("@", 1)[1]
        return f"{user}@{server}"
    return jid


def _participant(node: Node) -> GroupParticipant | None:
    jid = node.attrs.get("jid") or node.attrs.get("phone_number")
    if not jid:
        return None
    kind = node.attrs.get("type", "")
    return GroupParticipant(
        jid=jid,
        is_admin=kind == ADMIN,
        is_super_admin=kind == SUPERADMIN,
        lid=node.attrs.get("lid"),
        phone_number=node.attrs.get("phone_number"),
    )


def parse_group_info(node: Node) -> GroupInfo:
    group = child(node, "group")
    if group is None:
        raise GroupError("response carries no group node")
    group_id = group.attrs.get("id")
    if not group_id:
        raise GroupError("group node carries no id")
    participants = [
        participant
        for item in children(group, "participant")
        if (participant := _participant(item)) is not None
    ]
    ephemeral = child(group, "ephemeral")
    description = child(group, "description")
    topic: str | None = None
    topic_id: str | None = None
    if description is not None:
        body = child(description, "body")
        if body is not None and isinstance(body.content, bytes):
            topic = body.content.decode("utf-8", errors="replace")
        topic_id = description.attrs.get("id")
    try:
        size = int(group.attrs.get("size", "0"))
    except ValueError:
        size = 0
    return GroupInfo(
        jid=f"{group_id}{GROUP_SERVER}",
        subject=group.attrs.get("subject", ""),
        owner_jid=group.attrs.get("creator"),
        participants=participants,
        topic=topic,
        topic_id=topic_id,
        is_locked=child(group, "locked") is not None,
        is_announce=child(group, "announcement") is not None,
        is_ephemeral=ephemeral is not None,
        disappearing_timer=_int_attr(ephemeral, "expiration"),
        participant_count=size or len(participants),
        addressing_mode=group.attrs.get("addressing_mode"),
    )


def parse_joined_groups(node: Node) -> list[GroupInfo]:
    groups = child(node, "groups")
    if groups is None:
        return []
    result: list[GroupInfo] = []
    for group in children(groups, "group"):
        single = Node(tag="iq", attrs=node.attrs, content=[group])
        result.append(parse_group_info(single))
    return result


def parse_created_group(node: Node) -> str:
    group = child(node, "group")
    if group is None or not group.attrs.get("id"):
        raise GroupError("the server did not return the new group")
    return f"{group.attrs['id']}{GROUP_SERVER}"


def parse_participants_update(node: Node, action: str) -> list[GroupParticipant]:
    if action not in _PARTICIPANT_ACTIONS:
        raise GroupError(f"unknown participant action: {action!r}")
    container = child(node, action)
    if container is None:
        raise GroupError(f"response carries no {action} node")
    return [
        participant
        for item in children(container, "participant")
        if (participant := _participant(item)) is not None
    ]


def _int_attr(node: Node | None, name: str) -> int:
    if node is None:
        return 0
    try:
        return int(node.attrs.get(name, "0"))
    except ValueError:
        return 0
