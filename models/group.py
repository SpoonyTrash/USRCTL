from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from utils.errors import GroupMembershipError, InvalidGidError, ValidationError
from utils.validators import validate_groupname, validate_username

NORMAL_GROUP_MIN_GID = 1000
ROOT_GID = 0
RECOMMENDED_MEMBER_LIMIT = 100

ADMIN_GROUP_NAMES = frozenset({"sudo", "wheel", "admin"})
SERVICE_GROUP_NAMES = frozenset(
    {
        "daemon",
        "bin",
        "sys",
        "systemd-journal",
        "www-data",
        "messagebus",
        "docker"
    }
)

PROTECTED_GROUP_NAME = frozenset(
    {
        "root",
        "sudo",
        "wheel",
        "adm",
        "shadow",
        "systemd-journal",
        "docker",
        "staff"
    }
)
RESERVED_STATUS_GROUP_NAMES = frozenset({"root", "shadow"})

_SENSITIVE_METADATA_KEYS = frozenset(
    {
        "password",
        "passwd",
        "hash",
        "secret",
        "token",
        "credential",
        "credentials",
        "gshadow"
    }
)

class GroupType(str, Enum):
    NORMAL = "normal"
    SYSTEM = "system"
    ADMINISTRATIVE = "administrative"
    SERVICE = "service"
    PROTECTED = "protected"
    UNKNOWN = "unknown"

class GroupStatus(str, Enum):
    ACTIVE = "active"
    PROTECTED = "protected"
    RESERVED = "reserved"
    UNKNOWN = "unknown"

class GroupOrigin(str, Enum):
    SYSTEM = "system"
    CLI_INPUT = "cli_input"
    TEMPLATE = "template"
    BACKUP = "backup"
    REPORT = "report"
    TEST = "test"
    UNKNOWN = "unknown"

class MembershipAction(str, Enum):
    ADD = "add"
    REMOVE = "remove"
    REPLACE = "replace"
    LIST = "list"

class MembershipType(str, Enum):
    EXPLICIT = "explicit"
    PRIMARY = "primary"
    SECONDARY = "secondary"
    INHERITED = "inherited"
    SYSTEM_DETECTED = "system_detected"
    UNKNOWN = "unknown"

@dataclass(slots=True)
class SystemGroup:
    groupname: str
    gid: int | None = None
    members: list[str] = field(default_factory=list)
    group_type: GroupType = GroupType.UNKNOWN
    status: GroupStatus = GroupStatus.UNKNOWN
    is_admin: bool = False
    is_protected: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    primary_members: list[str] = field(default_factory=list)
    secondary_members: list[str] = field(default_factory=list)
    inherited_members: list[str] = field(default_factory=list)
    origin: GroupOrigin = GroupOrigin.SYSTEM

    def __post_init__(self) -> None:
        self._normalize_and_validate()

    @property
    def is_root_group(self) -> bool:
        return self.groupname == "root" or self.gid == ROOT_GID

    @property
    def is_system_group(self) -> bool:
        if self.group_type == GroupType.SYSTEM:
            return True
        return self.gid is not None and self.gid < NORMAL_GROUP_MIN_GID

    @property
    def is_normal_group(self) -> bool:
        return(
            self.group_type == GroupType.NORMAL
            and not self.is_system_group
            and not self.is_administrative_group
            and not self.is_protected_group
        )
    
    @property
    def is_administrative_group(self) -> bool:
        return(
            self.is_admin
            or self.group_type == GroupType.ADMINISTRATIVE
            or self.groupname in ADMIN_GROUP_NAMES
            or self.is_root_group
        )
    
    @property
    def is_protected_group(self) -> bool:
        return(
            self.is_protected
            or self.status in {GroupStatus.PROTECTED, GroupStatus.RESERVED}
            or self.group_type == GroupType.PROTECTED
            or self.groupname in PROTECTED_GROUP_NAME
            or self.is_root_group
        )
    
    @property
    def has_members(self) -> bool:
        return self.member_count > 0
    
    @property
    def all_members(self) -> list[str]:
        return _dedupe_names(
            [
                *self.members,
                *self.primary_members,
                *self.secondary_members,
                *self.inherited_members
            ],
            field_name="members",
            validate_as_username=True
        )
    
    @property
    def member_count(self) -> int:
        return len(self.all_members)
    
    @property
    def explicit_member_count(self) -> int:
        return len(self.members)
    
    @property
    def administrative_members(self) -> list[str]:
        if self.is_administrative_group:
            return self.all_members
        configured = self.metadata.get("administrative_members", [])
        return _dedupe_names(configured, field_name="administrative_members", validate_as_username=True)
    
    @property
    def has_many_members(self) -> bool:
        return self.member_count > RECOMMENDED_MEMBER_LIMIT
    
    @property
    def safe_for_deletion(self) -> bool:
        return not self.is_root_group and not self.is_protected_group and not self.has_members
    
    def has_member(self, username: str) -> bool:
        normalized = validate_username(username, allow_reserved=True)
        return normalized in self.all_members
    
    def _normalize_and_validate(self) -> None:
        self.origin = _coerce_enum(self.origin, GroupOrigin, GroupOrigin.SYSTEM)
        allow_reserved = self.origin in {GroupOrigin.SYSTEM, GroupOrigin.BACKUP}
        self.groupname = validate_groupname(self.groupname, allow_reserved=allow_reserved)
        self.gid = _validate_optional_gid(self.gid)
        self.group_type = _coerce_enum(self.group_type, GroupType, GroupType.UNKNOWN)
        self.status = _coerce_enum(self.status, GroupStatus, GroupStatus.UNKNOWN)
        self.is_admin = _coerce_bool(self.is_admin, field_name="is_admin")
        self.is_protected = _coerce_bool(self.is_protected, field_name="is_protected")

        self.members = _dedupe_names(self.members, field_name="members", validate_as_username=True)
        self.primary_members = _dedupe_names(self.primary_members, field_name="primary_members", validate_as_username=True)
        self.secondary_members = _dedupe_names(self.secondary_members, field_name="secondary_members", validate_as_username=True)
        self.inherited_members = _dedupe_names(
            self.inherited_members, field_name="inherited_members", validate_as_username=True
        )

        self.metadata = _safe_metadata(self.metadata)

        if self.groupname in ADMIN_GROUP_NAMES or self.group_type == GroupType.ADMINISTRATIVE:
            self.is_admin = True
        if self.groupname in PROTECTED_GROUP_NAME or self.is_root_group or self.group_type == GroupType.PROTECTED:
            self.is_protected = True
        if self.is_admin and self.group_type == GroupType.UNKNOWN:
            self.group_type = GroupType.ADMINISTRATIVE
        if self.is_protected and self.status == GroupStatus.UNKNOWN:
            self.status = GroupStatus.PROTECTED
        if self.groupname in RESERVED_STATUS_GROUP_NAMES and self.status == GroupStatus.UNKNOWN:
            self.status = GroupStatus.RESERVED
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "groupname": self.groupname,
            "gid": self.gid,
            "members": list(self.members),
            "primary_members": list(self.primary_members),
            "secondary_members": list(self.secondary_members),
            "inherited_members": list(self.inherited_members),
            "all_members": self.all_members,
            "member_count": self.member_count,
            "group_type": self.group_type.value,
            "status": self.status.value,
            "is_admin": self.is_administrative_group,
            "is_protected": self.is_protected_group,
            "is_system": self.is_system_group,
            "origin": self.origin.value,
            "security": self.security_info.to_dict(),
            "metadata": _json_compatible(self.metadata)
        }
    
    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "groupname": self.groupname,
            "gid": self.gid,
            "group_type": self.group_type.value,
            "status": self.status.value,
            "is_admin": self.is_administrative_group,
            "is_protected": self.is_protected_group,
            "member_count": self.member_count,
            "origin": self.origin.value
        }

    def to_report_dict(self) -> dict[str, Any]:
        return {
            "groupname": self.groupname,
            "gid": self.gid,
            "group_type": self.group_type.value,
            "status": self.status.value,
            "members": list(self.members),
            "member_count": self.member_count,
            "explicit_member_count": self.explicit_member_count,
            "primary_members": list(self.primary_members),
            "secondary_members": list(self.secondary_members),
            "administrative_members": self.administrative_members,
            "is_admin": self.is_administrative_group,
            "is_protected": self.is_protected_group,
            "is_system": self.is_system_group,
            "has_members": self.has_members,
            "has_many_members": self.has_many_members,
            "safe_for_deletion": self.safe_for_deletion
        }
    
    def to_summary_dict(self) -> dict[str, Any]:
        return self.summary.to_dict()
    
    def to_json_dict(self) -> dict[str, Any]:
        return _json_compatible(self.to_dict())
    
    @property
    def summary(self) -> "GroupSummary":
        return GroupSummary.from_group(self)
    
    @property
    def security_info(self) -> "GroupSecurityInfo":
        warnings: list[str] = []
        if self.is_root_group:
            warnings.append("Root group must not be modified casually.")
        if self.is_protected_group:
            warnings.append("Protected group requires strong validation before changes.")
        if self.is_administrative_group:
            warnings.append("Members may receive elevated privileges.")
        if self.has_many_members:
            warnings.append("Group has more members than the recommended reporting limit.")

        return GroupSecurityInfo(
            grants_elevated_privileges=self.is_administrative_group or self.is_root_group,
            is_protected=self.is_protected_group,
            has_administrative_members=bool(self.administrative_members),
            deletion_should_be_blocked=not self.safe_for_deletion,
            warnings=warnings
        ) 
    
    @classmethod
    def from_group_entry(cls, entry: Mapping[str, Any]) -> "SystemGroup":
        return cls(
            groupname=str(entry.get("groupname", entry.get("name", ""))).strip(),
            gid=_coerce_optional_int(entry.get("gid"), field_name="gid", error_cls=InvalidGidError),
            members=_coerce_member_list(entry.get("members")),
            group_type=_coerce_group_type(entry.get("group_type"), entry),
            status=_coerce_enum(entry.get("status"), GroupStatus, GroupStatus.UNKNOWN),
            is_admin=_coerce_bool(entry.get("is_admin", False), field_name="is_admin", default=False),
            is_protected=_coerce_bool(entry.get("is_protected", False), field_name="is_protected", default=False),
            metadata=dict(entry.get("metadata") or {}),
            origin=_coerce_enum(entry.get("origin"), GroupOrigin, GroupOrigin.SYSTEM)
        )
    
    @classmethod
    def from_etc_group_line(cls, line: str) -> "SystemGroup":
        if not isinstance(line, str) or not line.strip():
            raise GroupMembershipError("group entry line must be a non-empty string.")
        parts = line.rstrip("\n").split(":")
        if len(parts) != 4:
            raise GroupMembershipError("group entry line must contain four colon-separated fields.")
        groupname, _password_marker, gid, members = parts
        return cls.from_group_entry(
            {
                "groupname": groupname,
                "gid": gid,
                "members": [member for member in members.split(",") if member],
                "origin": GroupOrigin.SYSTEM,
                "metadata": {"password_marker_present": bool(_password_marker)}
            }
        )
    
    @classmethod
    def from_system_data(cls, payload: Mapping[str, Any]) -> "SystemGroup":
        return cls(
            groupname=str(payload.get("groupname", payload.get("name", ""))).strip(),
            gid=_coerce_optional_int(payload.get("gid"), field_name="gid", error_cls=InvalidGidError),
            members=_coerce_member_list(payload.get("members")),
            primary_members=_coerce_member_list(payload.get("primary_members")),
            secondary_members=_coerce_member_list(payload.get("secondary_members")),
            inherited_members=_coerce_member_list(payload.get("inherited_members")),
            group_type=_coerce_group_type(payload.get("group_type"), payload),
            status=_coerce_enum(payload.get("status"), GroupStatus, GroupStatus.UNKNOWN),
            is_admin=_coerce_bool(payload.get("is_admin", False), field_name="is_admin", default=False),
            is_protected=_coerce_bool(payload.get("is_protected", False), field_name="is_protected", default=False),
            metadata=dict(payload.get("metadata") or {}),
            origin=_coerce_enum(payload.get("origin"), GroupOrigin, GroupOrigin.SYSTEM)
        )
    
    @classmethod
    def partial(
        cls,
        groupname: str,
        *,
        gid: int | None = None,
        metadata: Mapping[str, Any] | None = None,
        origin: GroupOrigin = GroupOrigin.SYSTEM
    ) -> "SystemGroup":
        return cls(groupname=groupname, gid=gid, metadata=dict(metadata or {}), origin=origin)
    
    @classmethod
    def create_spec(cls, groupname: str) -> "GroupCreateSpec":
        return GroupCreateSpec.minimal(groupname)
    
    @classmethod
    def create_advanced_spec(
        cls,
        groupname: str,
        *,
        gid: int | None = None,
        members: Sequence[str] | None = None,
        group_type: GroupType = GroupType.NORMAL,
        metadata: Mapping[str, Any] | None = None
    ) -> "GroupCreateSpec":
        return GroupCreateSpec.advanced(
            groupname,
            gid=gid,
            members=list(members or []),
            group_type=group_type,
            metadata=dict(metadata or {})
        )
    
    @classmethod
    def membership_operation(
        cls,
        groupname: str,
        username: str,
        action: MembershipAction,
        *,
        membership_type: MembershipType = MembershipType.SECONDARY,
        force: bool = False,
        safe: bool = True,
        metadata: Mapping[str, Any] | None = None,
        allow_reserved: bool = False
    ) -> "GroupMembershipSpec":
        return GroupMembershipSpec(
            groupname=groupname,
            username=username,
            action=action,
            membership_type=membership_type,
            force=force,
            safe=safe,
            metadata=dict(metadata or {}),
            allow_reserved=allow_reserved
        )
    
@dataclass(slots=True)
class GroupMemberRef:
    username: str
    membership_type: MembershipType = MembershipType.UNKNOWN
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.username = validate_username(self.username, allow_reserved=True)
        self.membership_type = _coerce_enum(self.membership_type, MembershipType, MembershipType.UNKNOWN)
        self.metadata = _safe_metadata(self.metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "membership_type": self.membership_type.value,
            "metadata": _json_compatible(self.metadata)
        }


@dataclass(slots=True)
class GroupCreateSpec:
    groupname: str
    gid: int | None = None
    group_type: GroupType = GroupType.NORMAL
    members: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    origin: GroupOrigin = GroupOrigin.CLI_INPUT

    def __post_init__(self) -> None:
        self.origin = _coerce_enum_strict(
            self.origin, 
            GroupOrigin, 
            field_name="origin")
        allow_reserved = self.origin in {GroupOrigin.SYSTEM, GroupOrigin.BACKUP}
        self.groupname = validate_groupname(self.groupname, allow_reserved=allow_reserved)
        self.gid = _validate_optional_gid(self.gid)
        self.group_type = _coerce_enum_strict(
            self.group_type, 
            GroupType, 
            field_name="group_type")
        self.members = _dedupe_names(self.members, field_name="members", validate_as_username=True)
        self.metadata = _safe_metadata(self.metadata)

    @classmethod
    def minimal(cls, groupname: str) -> "GroupCreateSpec":
        return cls(groupname=groupname)
    
    @classmethod
    def advanced(
        cls,
        groupname: str,
        *,
        gid: int | None = None,
        members: Sequence[str] | None = None,
        group_type: GroupType = GroupType.NORMAL,
        metadata: Mapping[str, Any] | None = None,
        origin: GroupOrigin = GroupOrigin.CLI_INPUT
    ) -> "GroupCreateSpec":
        return cls(
            groupname=groupname,
            gid=gid,
            group_type=group_type,
            members=list(members or []),
            metadata=dict(metadata or {}),
            origin=origin
        )
    
    @classmethod
    def from_template(cls, template_data: Mapping[str, Any]) -> "GroupCreateSpec":
        return cls.from_cli_args(template_data, origin=GroupOrigin.TEMPLATE)

    @classmethod
    def from_cli_args(
        cls,
        cli_data: Mapping[str, Any],
        *,
        origin: GroupOrigin = GroupOrigin.CLI_INPUT
    ) -> "GroupCreateSpec":
        return cls(
            groupname=str(cli_data.get("groupname", cli_data.get("name", ""))).strip(),
            gid=_coerce_optional_int(cli_data.get("gid"), field_name="gid", error_cls=InvalidGidError),
            group_type=cli_data.get("group_type", GroupType.NORMAL),
            members=_coerce_member_list(cli_data.get("members")),
            metadata=dict(cli_data.get("metadata") or {}),
            origin=origin
        )
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "groupname": self.groupname,
            "gid": self.gid,
            "group_type": self.group_type.value,
            "members": list(self.members),
            "metadata": _json_compatible(self.metadata),
            "origin": self.origin.value
        }

@dataclass(slots=True)
class GroupUpdateSpec:
    groupname: str
    new_groupname: str | None = None
    new_gid: int | None = None
    members_to_add: list[str] = field(default_factory=list)
    members_to_remove: list[str] = field(default_factory=list)
    replace_members: list[str] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    origin: GroupOrigin = GroupOrigin.CLI_INPUT
    allow_reserved: bool = False

    def __post_init__(self) -> None:
        self.groupname = validate_groupname(self.groupname, allow_reserved=True)
        if self.new_groupname is not None:
            self.new_groupname = validate_groupname(self.new_groupname, allow_reserved=False)
        self.new_gid = _validate_optional_gid(self.new_gid)
        self.members_to_add = _dedupe_names(self.members_to_add, field_name="members_to_add", validate_as_username=True)
        self.members_to_remove = _dedupe_names(self.members_to_remove, field_name="members_to_remove", validate_as_username=True)
        if self.replace_members is not None:
            self.replace_members = _dedupe_names(self.replace_members, field_name="replace_members", validate_as_username=True)
        overlap = set(self.members_to_add).intersection(self.members_to_remove)
        if overlap:
            raise GroupMembershipError("members cannot be added and removed in the same update.", details={"members": sorted(overlap)})
        self.metadata = _safe_metadata(self.metadata)
        self.origin = _coerce_enum_strict(
            self.origin, 
            GroupOrigin, 
            field_name="origin"
        )
        if not self.has_changes:
            raise ValidationError(
                "Group update requires at least one change.",
                details={"groupname": self.groupname}
            )

    @property
    def has_changes(self) -> bool:
        return any(
            [
                self.new_groupname is not None,
                self.new_gid is not None,
                bool(self.members_to_add),
                bool(self.members_to_remove),
                self.replace_members is not None,
                bool(self.metadata)
            ]
        )
    
    @classmethod
    def from_cli_args(
        cls,
        cli_data: Mapping[str, Any],
        *,
        origin: GroupOrigin = GroupOrigin.CLI_INPUT
    ) -> "GroupUpdateSpec":
        return cls(
            groupname=str(cli_data.get("groupname", cli_data.get("name", ""))).strip(),
            new_groupname=_coerce_optional_str(cli_data.get("new_groupname")),
            new_gid=_coerce_optional_int(cli_data.get("new_gid"), field_name="new_gid", error_cls=InvalidGidError),
            members_to_add=_coerce_member_list(cli_data.get("members_to_add")),
            members_to_remove=_coerce_member_list(cli_data.get("members_to_remove")),
            replace_members=(
                None
                if cli_data.get("replace_members") is None
                else _coerce_member_list(cli_data.get("replace_members"))
            ),
            metadata=dict(cli_data.get("metadata") or {}),
            origin=origin
        )
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "groupname": self.groupname,
            "new_groupname": self.new_groupname,
            "new_gid": self.new_gid,
            "members_to_add": list(self.members_to_add),
            "members_to_remove": list(self.members_to_remove),
            "replace_members": list(self.replace_members) if self.replace_members is not None else None,
            "metadata": _json_compatible(self.metadata),
            "origin": self.origin.value,
            "has_changes": self.has_changes
        }


    
@dataclass(slots=True)
class GroupMembershipSpec:
    groupname: str
    username: str | None = None
    action: MembershipAction = MembershipAction.LIST
    membership_type: MembershipType = MembershipType.SECONDARY
    force: bool = False
    safe: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    origin: GroupOrigin = GroupOrigin.CLI_INPUT
    allow_reserved: bool = False

    def __post_init__(self) -> None:
        self.allow_reserved = _coerce_bool(
            self.allow_reserved,
            field_name="allow_reserved",
            default=False
        )
        self.groupname = validate_groupname(self.groupname, allow_reserved=self.allow_reserved)
        self.action = _coerce_enum_strict(
            self.action,
            MembershipAction, 
            field_name="action")
        self.membership_type = _coerce_enum_strict(
            self.membership_type,
            MembershipType,
            field_name="membership_type"
        )
        self.force = _coerce_bool(self.force, field_name="force")
        self.safe = _coerce_bool(self.safe, field_name="safe")
        if self.username is None:
            if self.action != MembershipAction.LIST:
                raise GroupMembershipError("username is required for membership changes.")
        else:
            self.username = validate_username(self.username, allow_reserved=True)
        self.metadata = _safe_metadata(self.metadata)
        self.origin = _coerce_enum_strict(
            self.origin, 
            GroupOrigin, 
            field_name="origin")
    
    @classmethod
    def add(
        cls,
        groupname: str,
        username: str,
        *,
        membership_type: MembershipType = MembershipType.SECONDARY,
        force: bool = False,
        safe: bool = True,
        allow_reserved: bool = False
    ) -> "GroupMembershipSpec":
        return cls(
            groupname=groupname,
            username=username,
            action=MembershipAction.ADD,
            membership_type=membership_type,
            force=force,
            safe=safe,
            allow_reserved=allow_reserved
        )
    
    @classmethod
    def remove(
        cls,
        groupname: str,
        username: str,
        *,
        membership_type: MembershipType = MembershipType.SECONDARY,
        force: bool = False,
        safe: bool = True,
        allow_reserved: bool = False
    ) -> "GroupMembershipSpec":
        return cls(
            groupname=groupname,
            username=username,
            action=MembershipAction.REMOVE,
            membership_type=membership_type,
            force=force,
            safe=safe,
            allow_reserved=allow_reserved
        )

    @classmethod
    def list_members(
        cls, 
        groupname: str,
        *,
        allow_reserved: bool = False
    ) -> "GroupMembershipSpec":
        return cls(
            groupname=groupname, 
            action=MembershipAction.LIST,
            allow_reserved=allow_reserved
        )
    
    @classmethod
    def replace(
        cls,
        groupname: str,
        *,
        force: bool = False,
        safe: bool = True,
        metadata: Mapping[str, Any] | None = None,
        allow_reserved: bool = False
    ) -> "GroupMembershipSpec":
        return cls(
            groupname=groupname,
            action=MembershipAction.REPLACE,
            membership_type=MembershipType.EXPLICIT,
            force=force,
            safe=safe,
            metadata=dict(metadata or {}),
            allow_reserved=allow_reserved
        )
    
    @classmethod
    def from_cli_args(
        cls,
        cli_data: Mapping[str, Any],
        *,
        origin: GroupOrigin = GroupOrigin.CLI_INPUT,
        allow_reserved: bool = False
    ) -> "GroupMembershipSpec":
        return cls(
            groupname=str(cli_data.get("groupname", cli_data.get("group", ""))).strip(),
            username=_coerce_optional_str(cli_data.get("username", cli_data.get("user"))),
            action=cli_data.get("action", MembershipAction.LIST),
            membership_type=cli_data.get("membership_type", MembershipType.SECONDARY),
            force=_coerce_bool(cli_data.get("force", False), field_name="force"),
            safe=_coerce_bool(cli_data.get("safe", True), field_name="safe"),
            metadata=dict(cli_data.get("metadata") or {}),
            origin=origin,
            allow_reserved=_coerce_bool(
                cli_data.get("allow_reserved", allow_reserved),
                field_name="allow_reserved",
                default=False
            )
        )
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "groupname": self.groupname,
            "username": self.username,
            "action": self.action.value,
            "membership_type": self.membership_type.value,
            "force": self.force,
            "safe": self.safe,
            "allow_reserved": self.allow_reserved,
            "metadata": _json_compatible(self.metadata),
            "origin": self.origin.value
        }
    
@dataclass(slots=True)
class GroupSummary:
    groupname: str
    gid: int | None = None
    member_count: int = 0
    group_type: GroupType = GroupType.UNKNOWN
    is_admin: bool = False
    is_protected: bool = False

    def __post_init__(self) -> None:
        self.groupname = validate_groupname(self.groupname, allow_reserved=True)
        self.gid = _validate_optional_gid(self.gid)
        self.member_count = _validate_non_negative_int(self.member_count, "member_count", ValidationError)
        self.group_type = _coerce_enum(self.group_type, GroupType, GroupType.UNKNOWN)
        self.is_admin = _coerce_bool(self.is_admin, field_name="is_admin")
        self.is_protected = _coerce_bool(self.is_protected, field_name="is_protected")

    @classmethod
    def from_group(cls, group: SystemGroup) -> "GroupSummary":
        return cls(
            groupname=group.groupname,
            gid=group.gid,
            member_count=group.member_count,
            group_type=group.group_type,
            is_admin=group.is_administrative_group,
            is_protected=group.is_protected_group
        )
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "groupname": self.groupname,
            "gid": self.gid,
            "member_count": self.member_count,
            "group_type": self.group_type.value,
            "is_admin": self.is_admin,
            "is_protected": self.is_protected
        }


@dataclass(slots=True)
class GroupSecurityInfo:
    grants_elevated_privileges: bool = False
    is_protected: bool = False
    has_administrative_members: bool = False
    deletion_should_be_blocked: bool = False
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.grants_elevated_privileges = _coerce_bool(
            self.grants_elevated_privileges, field_name="grants_elevated_privileges"
        )
        self.is_protected = _coerce_bool(self.is_protected, field_name="is_protected")
        self.has_administrative_members = _coerce_bool(self.has_administrative_members, field_name="has_administrative_members")
        self.deletion_should_be_blocked = _coerce_bool(
            self.deletion_should_be_blocked, 
            field_name="deletion_should_be_blocked"
        )
        self.warnings = _dedupe_text(self.warnings, field_name="warnings")
    
    @classmethod
    def from_group(cls, group: SystemGroup) -> "GroupSecurityInfo":
        return group.security_info
    
    def to_dict(self) -> dict[str, Any]:
        return{
            "grants_elevated_privileges": self.grants_elevated_privileges,
            "is_protected": self.is_protected,
            "has_administrative_members": self.has_administrative_members,
            "deletion_should_be_blocked": self.deletion_should_be_blocked,
            "warnings": list(self.warnings)
        }
    
        



def _validate_optional_gid(value: Any) -> int | None:
    return _coerce_optional_int(value, field_name="gid", error_cls=InvalidGidError)

def _validate_non_negative_int(value: Any, field_name: str, error_cls: type[Exception]) -> int:
    if isinstance(value, bool):
        raise error_cls(f"{field_name} must be an integer, not boolean.")
    if not isinstance(value, int):
        raise error_cls(f"{field_name} must be an integer.")
    if value < 0:
        raise error_cls(f"{field_name} must be a non-negative integer.")
    return value

def _coerce_optional_int(value: Any, *, field_name: str, error_cls: type[Exception]) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise error_cls(f"{field_name} must be an integer, not boolean.")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise error_cls(f"{field_name} must be an integer.") from exc
    if normalized < 0:
        raise error_cls(f"{field_name} must be a non-negative integer.")
    return normalized

def _coerce_bool(
        value: Any, 
        *, 
        field_name: str,
        default: bool | None = None
    ) -> bool:
    if value is None:
        if default is not None:
            return default
        raise ValidationError(
            f"{field_name} must be a boolean-like value.",
            details={"field": field_name, "value": value}
        )
    if isinstance(value, bool):
        return value
    
    if isinstance(value, int):
        if value in (0, 1):
            return bool(value)
        raise ValidationError(
            f"{field_name} must be a boolean-like value.",
            details={"field": field_name, "value": value}
        )
    
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1"}:
            return True
        if normalized in {"false", "no", "0"}:
            return False
        raise ValidationError(
            f"{field_name} must be one of: true/false, yes/no, 1/0.",
            details={"field": field_name, "value": value}
        )
    raise ValidationError(
        f"{field_name} must be boolean-like value.", 
        details={"field": field_name, "value": value})

def _coerce_enum(
        value: Any, 
        enum_cls: type[Enum], 
        default: Enum
    ) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(str(value))
    except ValueError:
        return default
    
def _coerce_enum_strict(
        value: Any,
        enum_cls: type[Enum],
        *,
        field_name: str,
        error_cls: type[Exception] = ValidationError
) -> Any:
    allowed = ", ".join(member.value for member in  enum_cls)

    if isinstance(value, enum_cls):
        return value
    
    if value is None or value == "":
        raise error_cls(
            f"{field_name} is required and must be one of: {allowed}"
        )
    
    try:
        return enum_cls(str(value))
    except ValueError as exc:
        raise error_cls(
            f"{field_name} must be one of: {allowed} (received {value!r})."
        )

def _coerce_group_type(value: Any, payload: Mapping[str, Any]) -> GroupType:
    explicit = _coerce_enum(value, GroupType, GroupType.UNKNOWN)
    if explicit != GroupType.UNKNOWN:
        return explicit
    
    name = str(payload.get("groupname", payload.get("name", ""))).strip().lower()
    gid = _coerce_optional_int(payload.get("gid"), field_name="gid", error_cls=InvalidGidError)
    if name in PROTECTED_GROUP_NAME or gid == ROOT_GID:
        return GroupType.PROTECTED
    if name in ADMIN_GROUP_NAMES:
        return GroupType.ADMINISTRATIVE
    if name in SERVICE_GROUP_NAMES:
        return GroupType.SERVICE
    if gid is not None and gid < NORMAL_GROUP_MIN_GID:
        return GroupType.SYSTEM
    if gid is not None:
        return GroupType.NORMAL
    return GroupType.UNKNOWN
    
def _coerce_member_list(values: Any) -> list[str]:
    if values is None or values == "":
        return []
    if isinstance(values, str):
        values = [part for part in values.split(",") if part]
    if not isinstance(values, Sequence):
        raise GroupMembershipError("members must be a sequence of usernames.")
    return _dedupe_names(values, field_name="members", validate_as_username=True)
    
def _dedupe_names(values: Any, *, field_name: str, validate_as_username: bool) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        raise GroupMembershipError(f"{field_name} must be a sequence, not a string.")
    if not isinstance(values, Sequence):
        raise GroupMembershipError(f"{field_name} must be a sequence.")
    
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_value in values:
        value = str(raw_value).strip()
        if not value:
            raise GroupMembershipError(f"{field_name} cannot contain empty values.")
        value = validate_username(value, allow_reserved=True) if validate_as_username else value
        if value not in seen:
            seen.add(value)
            normalized.append(value)
    return normalized

def _dedupe_text(values: Any, *, field_name: str) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, Sequence):
        raise ValidationError(f"{field_name} must be a sequence.")
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_value in values:
        value = str(raw_value).strip()
        if not value:
            continue
        if value not in seen:
            seen.add(value)
            normalized.append(value)
    return normalized

def _coerce_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None

        
def _safe_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    if metadata is None:
        return {}
    if not isinstance(metadata, Mapping):
        raise ValidationError("metadata must be a mapping.")
    safe: dict[str, Any] = {}
    for key, value in metadata.items():
        normalized_key = str(key).strip()
        if not normalized_key:
            raise ValidationError("metadata keys cannot be empty.")
        if normalized_key.lower() in _SENSITIVE_METADATA_KEYS:
            continue
        safe[normalized_key] = _json_compatible(value)
    return safe

def _json_compatible(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_compatible(item) for key, item  in value.items()}
    if isinstance(value, tuple | set | frozenset):
        return [_json_compatible(item) for item in value]
    if isinstance(value, list):
        return [_json_compatible(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value    
    return str(value)

__all__ = [
    "SystemGroup",
    "GroupMemberRef",
    "GroupCreateSpec",
    "GroupUpdateSpec",
    "GroupMembershipSpec",
    "GroupSummary",
    "GroupSecurityInfo",
    "GroupType",
    "GroupStatus",
    "MembershipType",
    "GroupOrigin",
    "MembershipAction",
    "NORMAL_GROUP_MIN_GID",
    "ROOT_GID",
    "RECOMMENDED_MEMBER_LIMIT",
    "ADMIN_GROUP_NAMES",
    "SERVICE_GROUP_NAMES",
    "PROTECTED_GROUP_NAME",
    "RESERVED_STATUS_GROUP_NAMES"
]