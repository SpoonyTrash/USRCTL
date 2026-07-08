from pathlib import Path
from typing import Any, Mapping, Sequence

from models.group import (
    GroupCreateSpec,
    GroupMembershipSpec,
    GroupOrigin, 
    GroupStatus,
    GroupSummary, 
    GroupType, 
    GroupUpdateSpec,
    MembershipAction,
    SystemGroup,
    
)

from system.executor import CommandExecutor, ExecutorConfig

from system.result import DryRunResult, ImpactLevel, ImpactMetadata, ResultStatus, SystemResult
from utils.errors import (
  CommandExecutionError,
  GroupAlreadyExistsError,
  GroupMembershipError, 
  GroupNotFoundError,
  InsufficientPermissionsError, 
  InvalidGidError,
  UserAlreadyInGroupError,
  UserNotFoundError,
  UserNotInGroupError
)
from utils.validators import validate_gid, validate_groupname, validate_username


CMD_GROUPADD = "groupadd"
CMD_GROUPDEL = "groupdel"
CMD_GROUPMOD = "groupmod"
CMD_GETENT = "getent"
CMD_ID = "id"
CMD_GROUPS = "groups"
CMD_USERMOD = "usermod"
CMD_GPASSWD = "gpasswd"

REQUIRED_COMMANDS = frozenset({CMD_GROUPADD, CMD_GROUPDEL, CMD_GROUPMOD, CMD_GETENT, CMD_ID, CMD_GROUPS, CMD_USERMOD, CMD_GPASSWD})

ETC_GROUP = Path("/etc/group")
ETC_PASSWD = Path("/etc/passwd")

ACTION_CREATE_GROUP = "create_group"
ACTION_DELETE_GROUP = "delete_group"
ACTION_RENAME_GROUP = "rename_group"
ACTION_CHANGE_GROUP_GID = "change_group_gid"
ACTION_ADD_USER_TO_GROUP = "add_user_to_group"
ACTION_REMOVE_USER_FROM_GROUP = "remove_user_from_group"
ACTION_REPLACE_GROUP_MEMBERS = "replace_group_members"

ADMIN_GROUPS = frozenset({"sudo", "wheel", "admin", "adm"})
PROTECTED_GROUPS = frozenset({"root", "shadow", "sudo", "wheel", "adm", "systemd-journal", "daemon", "bin", "sys"})
ROOT_GROUP_NAME = "root"
ROOT_GID = 0
SYSTEM_GROUP_MAX_GID = 999

ETC_GROUP_FIELDS = ("groupname", "password_placeholder", "gid", "members")
FIELD_SEPARATOR = ":"
MEMBER_SEPARATOR = ","
LINE_SEPARATOR = "\n"
GROUPS_OUTPUT_SEPARATOR = " "

ACTION_QUERY_GROUP = "query_group"

def _normalize_groupname(groupname: str, *, allow_reserved: bool = True) -> str:
    return validate_groupname(str(groupname).strip(), allow_reserved=allow_reserved)

def _normalize_username(username: str) -> str:
    return validate_username(str(username).strip(), allow_reserved=True)

def _coerce_bool(value: Any, *, field_name: str, default: bool = False) -> bool:
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        if value in (0, 1):
            return bool(value)
        raise GroupMembershipError(
            f"{field_name} must be a boolean-like value.",
            details={field_name: value},
        )

    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in {"true", "yes", "y", "1"}:
            return True

        if normalized in {"false", "no", "n", "0"}:
            return False

        raise GroupMembershipError(
            f"{field_name} must be one of: true/false, yes/no, 1/0.",
            details={field_name: value},
        )

    raise GroupMembershipError(
        f"{field_name} must be a boolean-like value.",
        details={field_name: value},
    )

def _normalize_gid(gid: Any, *, allow_system_gid: bool = True) -> int:
    if isinstance(gid, bool):
        raise InvalidGidError(
            "GID must be an integer, not boolean.",
            details={"gid": gid},
        )
    
    if allow_system_gid:
        try:
            value = int(gid)
        except (TypeError, ValueError) as exc:
            raise InvalidGidError("GID must be an integer.", details={"gid": gid}) from exc
        if value < 0:
            raise InvalidGidError("GID must be a non-negative integer.", details={"gid": value})
        return value
    return validate_gid(gid, allow_system_gid=False)

def _normalize_members(members: Sequence[str] | str | None) -> list[str]:
    if members is None:
        return []
    raw_members = members.split(MEMBER_SEPARATOR) if isinstance(members, str) else list(members)
    normalized: list[str] = []
    seen: set[str] = set()
    for member in raw_members:
        value = str(member).strip()
        if not value:
            continue
        value = _normalize_username(value)
        if value not in seen:
            normalized.append(value)
            seen.add(value)
    return normalized

def _normalize_group_list(groups: Sequence[str] | str | None) -> list[str]:
    if groups is None:
        return []
    raw_groups = groups.replace(MEMBER_SEPARATOR, GROUPS_OUTPUT_SEPARATOR).split() if isinstance(groups, str) else list(groups)
    normalized: list[str] = []
    seen: set[str] = set()
    for group in raw_groups:
        value = str(group).strip()
        if not value:
            continue
        value = _normalize_groupname(value, allow_reserved=True)
        if value not in seen:
            normalized.append(value)
            seen.add(value)
    return normalized

def _parse_etc_group_line(line: str) -> dict[str, Any]:
    raw = str(line).rstrip(LINE_SEPARATOR)
    parts = raw.split(FIELD_SEPARATOR)
    if len(parts) != len(ETC_GROUP_FIELDS):
        raise GroupMembershipError("Invalid /etc/group entry format.", details={"line": raw, "expected_fields": ETC_GROUP_FIELDS})
    groupname, _password_placeholder, gid, members = parts
    return {"groupname": _normalize_groupname(groupname, allow_reserved=True), "gid": _normalize_gid(gid), "members": _normalize_members(members)}

def _parse_getent_group_output(output: str) -> SystemGroup | None:
    clean = str(output).strip()
    if not clean:
        return None
    first_line = clean.splitlines()[0]
    return _group_from_data(_parse_etc_group_line(first_line))

def _parse_id_groups_output(output: str) -> list[str]:
    return _normalize_group_list(str(output).strip())

def _group_type_for(groupname: str, gid: int | None) -> GroupType:
    if groupname in PROTECTED_GROUPS or gid == ROOT_GID:
        return GroupType.PROTECTED
    if groupname in ADMIN_GROUPS:
        return GroupType.ADMINISTRATIVE
    if gid is not None and gid <= SYSTEM_GROUP_MAX_GID:
        return GroupType.SYSTEM
    return GroupType.NORMAL

def _group_from_data(data: Mapping[str, Any], *, primary_members: Sequence[str] | None = None) -> SystemGroup:
    groupname = _normalize_groupname(str(data["groupname"]), allow_reserved=True)
    gid = _normalize_gid(data.get("gid"), allow_system_gid=True) if data.get("gid") is not None else None
    group_type = _group_type_for(groupname, gid)
    return SystemGroup.from_system_data(
        {
            "groupname": groupname,
            "gid": gid,
            "members": _normalize_members(data.get("members")),
            "primary_members": _normalize_members(primary_members),
            "group_type": group_type,
            "status": GroupStatus.PROTECTED if groupname in PROTECTED_GROUPS or gid == ROOT_GID else GroupStatus.ACTIVE,
            "is_admin": groupname in ADMIN_GROUPS or gid == ROOT_GID,
            "is_protected": groupname in PROTECTED_GROUPS or gid == ROOT_GID,
            "origin": GroupOrigin.SYSTEM,
            "metadata": {"source": "getent_group", "password_data_exposed": False},
        }
    )

def _build_groupadd_command(
    groupname: str, 
    *, 
    gid: int | None = None, 
    system: bool = False
) -> list[str]:
    command = [CMD_GROUPADD]
    if system:
        command.append("--system")
    if gid is not None:
        command.extend(["--gid", str(_normalize_gid(gid, allow_system_gid=system))])
    command.append(_normalize_groupname(groupname, allow_reserved=False))
    return command

def _build_groupdel_command(groupname: str) -> list[str]:
    return [CMD_GROUPDEL, _normalize_groupname(groupname, allow_reserved=True)]

def _build_groupmod_command(
    groupname: str, 
    *, 
    new_groupname: str | None = None, 
    new_gid: int | None = None
) -> list[str]:
    command = [CMD_GROUPMOD]
    if new_gid is not None:
        command.extend(["--gid", str(_normalize_gid(new_gid, allow_system_gid=True))])
    if new_groupname is not None:
        command.extend(["--new-name", _normalize_groupname(new_groupname, allow_reserved=False)])
    command.append(_normalize_groupname(groupname, allow_reserved=True))
    return command

def _build_add_member_command(groupname: str, username: str) -> list[str]:
    return [CMD_GPASSWD, "--add", _normalize_username(username), _normalize_groupname(groupname, allow_reserved=True)]

def _build_remove_member_command(groupname: str, username: str) -> list[str]:
    return [CMD_GPASSWD, "--delete", _normalize_username(username), _normalize_groupname(groupname, allow_reserved=True)]

def _build_getent_group_command(groupname: str | None = None) -> list[str]:
    command = [CMD_GETENT, "group"]
    if groupname is not None:
        command.append(_normalize_groupname(groupname, allow_reserved=True))
    return command

def _build_getent_group_by_gid_command(gid: int) -> list[str]:
    return [CMD_GETENT, "group", str(_normalize_gid(gid, allow_system_gid=True))]

def _build_id_groups_command(username: str) -> list[str]:
    return [CMD_ID, "-nG", _normalize_username(username)]

def _build_getent_passwd_command(username: str | None = None) -> list[str]:
    command = [CMD_GETENT, "passwd"]
    if username is not None:
        command.append(_normalize_username(username))
    return command


class LinuxGroupManager:
    def __init__(self, executor: CommandExecutor | None = None, *, dry_run: bool = False) -> None:
        self.executor = executor or CommandExecutor(ExecutorConfig(dry_run=dry_run))
        self.dry_run = dry_run

    def group_exists(self, groupname: str) -> bool:
        result = self.executor.execute(
            _build_getent_group_command(groupname), 
            action=ACTION_QUERY_GROUP, 
            target=groupname, 
            dry_run=False
        )
        return bool(result.ok and result.execution and result.execution.stdout.strip())
    
    def get_group(self, groupname: str) -> SystemGroup:
        groupname = _normalize_groupname(groupname, allow_reserved=True)
        result = self.executor.execute(
            _build_getent_group_command(groupname), 
            action=ACTION_QUERY_GROUP, 
            target=groupname, 
            dry_run=False
        )
        if not result.ok or not result.execution or not result.execution.stdout.strip():
            raise GroupNotFoundError("Group not found.", details={"groupname": groupname})
        group = _parse_getent_group_output(result.execution.stdout)
        if group is None:
            raise GroupNotFoundError("Group not found.", details={"groupname": groupname})
        return group

    def get_group_by_gid(self, gid: int) -> SystemGroup:
        normalized_gid = _normalize_gid(gid, allow_system_gid=True)
        result = self.executor.execute(
            _build_getent_group_by_gid_command(normalized_gid), 
            action=ACTION_QUERY_GROUP, 
            target=str(normalized_gid), 
            dry_run=False
        )
        if not result.ok or not result.execution or not result.execution.stdout.strip():
            raise GroupNotFoundError("Group not found for GID.", details={"gid": normalized_gid})
        group = _parse_getent_group_output(result.execution.stdout)
        if group is None:
            raise GroupNotFoundError("Group not found for GID.", details={"gid": normalized_gid})
        return group

    def list_groups(self) -> list[SystemGroup]:
        result = self.executor.execute(
            _build_getent_group_command(), 
            action=ACTION_QUERY_GROUP, 
            target="all_groups", 
            dry_run=False
        )
        if not result.ok or not result.execution:
            self._raise_from_result(
                result, 
                action=ACTION_QUERY_GROUP, 
                groupname="all_groups"
            )
        groups: list[SystemGroup] = []
        for line in result.execution.stdout.splitlines():
            if line.strip():
                groups.append(_group_from_data(_parse_etc_group_line(line)))
        return groups
    
    def list_normal_groups(self) -> list[SystemGroup]:
        return [group for group in self.list_groups() if group.group_type == GroupType.NORMAL]
    
    def list_system_groups(self) -> list[SystemGroup]:
        return [group for group in self.list_groups() if group.is_system_group]
    
    def list_admin_groups(self) -> list[SystemGroup]:
        return [group for group in self.list_groups() if self.is_admin_group(group.groupname, group.gid)]
    
    def get_group_members(self, groupname: str) -> list[str]:
        return self.get_group(groupname).members
    
    def get_group_details(self, groupname: str, *, include_primary_members: bool = True) -> dict[str, Any]:
        group = self.get_group(groupname)
        primary_members = self.get_primary_members_for_group(group.gid) if include_primary_members and group.gid is not None else []
        enriched = _group_from_data(group.to_dict(), primary_members=primary_members)
        return {
            "group": enriched,
            "gid": enriched.gid,
            "members": enriched.members,
            "primary_members": primary_members,
            "group_type": enriched.group_type.value,
            "is_admin": self.is_admin_group(enriched.groupname, enriched.gid),
            "is_protected": self.is_protected_group(enriched.groupname, enriched.gid),
            "metadata": {"source": "linux_groups", "files_consulted": [str(ETC_GROUP), str(ETC_PASSWD)]},
        }
    
    def create_group(
        self, 
        groupname: str, 
        *, 
        gid: int | None = None, 
        system: bool = False, 
        members: Sequence[str] | None = None, 
        dry_run: bool | None = None
    ) -> SystemResult:
        system = _coerce_bool(
            system,
            field_name="system",
            default=False,
        )
        spec = GroupCreateSpec.advanced(
            groupname, 
            gid=gid, 
            members=members, 
            group_type=GroupType.SYSTEM if system else GroupType.NORMAL
        )
        return self.create_group_from_spec(spec, dry_run=dry_run)

    def create_group_from_spec(
        self, 
        spec: GroupCreateSpec, 
        *, 
        dry_run: bool | None = None
    ) -> SystemResult:
        groupname = _normalize_groupname(spec.groupname, allow_reserved=False)
        gid = None if spec.gid is None else _normalize_gid(spec.gid, allow_system_gid=True)
        system = spec.group_type == GroupType.SYSTEM

        self.ensure_group_absent(groupname)

        if gid is not None:
            self.ensure_gid_available(gid)

        warnings = self._security_warnings(
            groupname, 
            gid, 
            operation="create"
        )
        command = _build_groupadd_command(
            groupname, 
            gid=gid, 
            system=system
        )
        result = self._execute_mutation(
            command, 
            action=ACTION_CREATE_GROUP, 
            target=groupname,             
            warnings=warnings, 
            dry_run=dry_run
        )
        if result.ok and not result.dry_run and spec.members:
            member_results = [self.add_user_to_group(member, groupname, dry_run=dry_run).summary() for member in spec.members]            
            result.details["initial_member_results"] = member_results
        return result
    
    def delete_group(
        self,
        groupname: str,
        *,
        dry_run: bool | None = None,
        allow_protected: bool = False,
        allow_non_empty: bool = False,
        allow_primary_group: bool = False,
    ) -> SystemResult:
        groupname = _normalize_groupname(groupname, allow_reserved=True)
        allow_non_empty = _coerce_bool(
            allow_non_empty,
            field_name="allow_non_empty",
            default=False,
        )
        allow_primary_group = _coerce_bool(
            allow_primary_group,
            field_name="allow_primary_group",
            default=False,
        )
        allow_protected = _coerce_bool(
            allow_protected,
            field_name="allow_protected",
            default=False,
        )

        group = self.get_group(groupname)
        self.ensure_not_protected_group(
            group.groupname,
            group.gid,
            operation="delete_group",
            allow_protected=allow_protected,
        )
        primary_members = (
            self.get_primary_members_for_group(group.gid)
            if group.gid is not None
            else []
        )

        if group.members and not allow_non_empty:
            raise GroupMembershipError(
                "Cannot delete group with explicit members.",
                details={
                    "groupname": groupname,
                    "members": group.members,
                    "allow_non_empty_required": True,
                },
            )

        if primary_members and not allow_primary_group:
            raise GroupMembershipError(
                "Cannot delete group used as primary group.",
                details={
                    "groupname": groupname,
                    "primary_members": primary_members,
                    "allow_primary_group_required": True,
                },
            )
        warnings = self._security_warnings(
            group.groupname,
            group.gid,
            operation="delete"
        )
        command = _build_groupdel_command(group.groupname)        
        return self._execute_mutation(
            command,
            action=ACTION_DELETE_GROUP,
            target=group.groupname,
            warnings=warnings,
            dry_run=dry_run,
            metadata=self._with_allow_protected_audit({}, allow_protected=allow_protected),
        )
    
    def group_has_members(self, groupname: str) -> bool:
        return bool(self.get_group_members(groupname))

    def group_is_primary_in_use(self, groupname: str) -> bool:
        group = self.get_group(groupname)
        return bool(group.gid is not None and self.get_primary_members_for_group(group.gid))
    
    def rename_group(
        self,
        groupname: str,
        new_groupname: str,
        *,
        dry_run: bool | None = None,
        allow_protected: bool = False
    ) -> SystemResult:
        groupname = _normalize_groupname(groupname, allow_reserved=True)
        new_groupname = _normalize_groupname(new_groupname, allow_reserved=False)
        allow_protected = _coerce_bool(
            allow_protected,
            field_name="allow_protected",
            default=False,
        )

        group = self.get_group(groupname)
        self.ensure_not_protected_group(
            group.groupname,
            group.gid,
            operation="rename_group",
            allow_protected=allow_protected,
        )
        self.ensure_group_absent(new_groupname)

        command = _build_groupmod_command(group.groupname, new_groupname=new_groupname)
        warnings = self._security_warnings(group.groupname, group.gid, operation="rename")
        return self._execute_mutation(
            command,
            action=ACTION_RENAME_GROUP,
            target=group.groupname,
            warnings=warnings,
            dry_run=dry_run,
            metadata=self._with_allow_protected_audit({"new_groupname": new_groupname}, allow_protected=allow_protected),
        )
    
    def change_gid(
        self, 
        groupname: str, 
        new_gid: int, 
        *, 
        dry_run: bool | None = None,
        allow_protected: bool = False,
    ) -> SystemResult:
        groupname = _normalize_groupname(groupname, allow_reserved=True)
        new_gid = _normalize_gid(new_gid, allow_system_gid=True)
        allow_protected = _coerce_bool(
            allow_protected,
            field_name="allow_protected",
            default=False,
        )

        group = self.get_group(groupname)

        self.ensure_not_protected_group(
            group.groupname,
            group.gid,
            operation="change_gid",
            allow_protected=allow_protected,
        )

        self.ensure_gid_available(new_gid)
        warnings = self._security_warnings(
            group.groupname, 
            group.gid, 
            operation="change_gid"
        )
        warnings.append("Changing a GID may leave existing filesystem ownership pointing to the old numeric GID.")
        command = _build_groupmod_command(group.groupname, new_gid=new_gid)
        return self._execute_mutation(
            command,
            action=ACTION_CHANGE_GROUP_GID,
            target=group.groupname,
            warnings=warnings,
            dry_run=dry_run,
            metadata=self._with_allow_protected_audit({"new_gid": new_gid}, allow_protected=allow_protected),
        )

    def modify_group_from_spec(self, spec: GroupUpdateSpec, *, dry_run: bool | None = None) -> list[SystemResult]:
        results: list[SystemResult] = []
        current_name = spec.groupname
        if spec.new_gid is not None:
            results.append(self.change_gid(current_name, spec.new_gid, dry_run=dry_run))
        if spec.new_groupname is not None:
            results.append(self.rename_group(current_name, spec.new_groupname, dry_run=dry_run))
            current_name = spec.new_groupname
        for member in spec.members_to_add:
            results.append(self.add_user_to_group(member, current_name, dry_run=dry_run))
        for member in spec.members_to_remove:
            results.append(self.remove_user_from_group(member, current_name, dry_run=dry_run))
        if spec.replace_members is not None:
            results.append(self.replace_group_members(current_name, spec.replace_members, dry_run=dry_run))
        return results

    def add_user_to_group(
        self,
        username: str,
        groupname: str,
        *,
        dry_run: bool | None = None,
        allow_protected: bool = False,
    ) -> SystemResult:
        username = _normalize_username(username)
        groupname = _normalize_groupname(groupname, allow_reserved=True)
        allow_protected = _coerce_bool(
            allow_protected,
            field_name="allow_protected",
            default=False,
        )

        self.ensure_user_exists(username)
        group = self.get_group(groupname)

        self.ensure_not_protected_group(
            group.groupname,
            group.gid,
            operation="add_user_to_group",
            allow_protected=allow_protected,
        )

        if groupname in self.get_groups_for_user(username):            
            raise UserAlreadyInGroupError("User already belongs to group.", details={"username": username, "groupname": groupname})
        warnings = self._security_warnings(group.groupname, group.gid, operation="add_member")        
        return self._execute_mutation(
            _build_add_member_command(group.groupname, username),
            action=ACTION_ADD_USER_TO_GROUP,
            target=group.groupname,
            user=username,
            warnings=warnings,
            dry_run=dry_run,
            metadata=self._with_allow_protected_audit({}, allow_protected=allow_protected),
        )
    
    def remove_user_from_group(
        self,
        username: str,
        groupname: str,
        *,
        dry_run: bool | None = None,
        allow_protected: bool = False,
    ) -> SystemResult:
        username = _normalize_username(username)
        groupname = _normalize_groupname(groupname, allow_reserved=True)
        allow_protected = _coerce_bool(
            allow_protected,
            field_name="allow_protected",
            default=False,
        )

        self.ensure_user_exists(username)
        group = self.get_group(groupname)

        self.ensure_not_protected_group(
            group.groupname,
            group.gid,
            operation="remove_user_from_group",
            allow_protected=allow_protected,
        )

        if groupname not in self.get_groups_for_user(username):            
            raise UserNotInGroupError("User does not belong to group.", details={"username": username, "groupname": groupname})
        warnings = self._security_warnings(group.groupname, group.gid, operation="remove_member")
        return self._execute_mutation(
            _build_remove_member_command(group.groupname, username),
            action=ACTION_REMOVE_USER_FROM_GROUP,
            target=group.groupname,
            user=username,
            warnings=warnings,
            dry_run=dry_run,
            metadata=self._with_allow_protected_audit({}, allow_protected=allow_protected),
        ) 
    
    def is_user_in_group(self, username: str, groupname: str) -> bool:
        username = _normalize_username(username)
        groupname = _normalize_groupname(groupname, allow_reserved=True)
        self.ensure_user_exists(username)
        return groupname in self.get_groups_for_user(username)

    def get_groups_for_user(self, username: str) -> list[str]:
        username = _normalize_username(username)
        result = self.executor.execute(
            _build_id_groups_command(username), 
            action=ACTION_QUERY_GROUP, 
            target=username, 
            dry_run=False
        )
        if not result.ok or not result.execution:
            self._raise_from_result(
                result, 
                action=ACTION_QUERY_GROUP, 
                groupname=username
            )
        return _parse_id_groups_output(result.execution.stdout)
    
    def replace_group_members(
        self,
        groupname: str,
        members: Sequence[str],
        *,
        dry_run: bool | None = None,
        allow_protected: bool = False,
    ) -> SystemResult:        
        groupname = _normalize_groupname(groupname, allow_reserved=True)
        allow_protected = _coerce_bool(
            allow_protected,
            field_name="allow_protected",
            default=False,
        )
        group = self.get_group(groupname)

        self.ensure_not_protected_group(
            group.groupname,
            group.gid,
            operation="replace_group_members",
            allow_protected=allow_protected,
        )
        desired = set(_normalize_members(members))
        current = set(group.members)        
        to_add = sorted(desired - current)
        to_remove = sorted(current - desired)
        warnings = self._security_warnings(group.groupname, group.gid, operation="replace_members")
        warnings.append("Replacing group members may remove existing access; primary memberships are not changed.")
        effective_dry_run = _coerce_bool(dry_run, field_name="dry_run", default=self.dry_run)
        audit = self._with_allow_protected_audit({}, allow_protected=allow_protected)
        if effective_dry_run:
            details = {
                "groupname": group.groupname,
                "members_to_add": to_add,
                "members_to_remove": to_remove,
            }
            details.update(audit)            
            return DryRunResult(
                action=ACTION_REPLACE_GROUP_MEMBERS,
                target=group.groupname,                
                message="Group membership replacement simulated.",
                details=details,
                warnings=warnings,
                impact=ImpactMetadata(level=ImpactLevel.HIGH, affected_resources=[group.groupname]),
            )
        applied: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []
        for member in to_add:
            try:
                applied.append(
                    self.add_user_to_group(
                        member,
                        group.groupname,
                        dry_run=False,
                        allow_protected=allow_protected,
                    ).summary()
                )
            except Exception as exc:
                failed.append(
                    {
                        "member": member,
                        "action": "add",
                        "error": str(exc),
                    }
                )
        for member in to_remove:
            try:
                applied.append(
                    self.remove_user_from_group(
                        member,
                        group.groupname,
                        dry_run=False,
                        allow_protected=allow_protected,
                    ).summary()
                )
            except Exception as exc:
                failed.append(
                    {
                        "member": member,
                        "action": "remove",
                        "error": str(exc),
                    }
                )

        details = {
            "applied": applied,
            "failed": failed,
            "members_to_add": to_add,
            "members_to_remove": to_remove,
        }
        details.update(audit)
        return SystemResult(
            ok=not failed,
            status=ResultStatus.SUCCESS if not failed else ResultStatus.PARTIAL,
            action=ACTION_REPLACE_GROUP_MEMBERS,
            target=group.groupname,
            message="Group memberships replaced." if not failed else "Group memberships partially replaced.",
            details=details,
            warnings=warnings,
            changed=bool(applied),
            impact=ImpactMetadata(level=ImpactLevel.HIGH, affected_resources=[group.groupname], applied_resources=[group.groupname] if applied else []),
        )

    def apply_membership_spec(
        self,
        spec: GroupMembershipSpec,
        *,
        dry_run: bool | None = None,
    ) -> SystemResult:
        if spec.action == MembershipAction.ADD:
            if spec.username is None:
                raise GroupMembershipError("username is required for add membership.")
            return self.add_user_to_group(spec.username, spec.groupname, dry_run=dry_run)
        if spec.action == MembershipAction.REMOVE:
            if spec.username is None:
                raise GroupMembershipError("username is required for remove membership.")
            return self.remove_user_from_group(spec.username, spec.groupname, dry_run=dry_run)
        if spec.action == MembershipAction.REPLACE:
            replacement = spec.metadata.get("members", [])
            return self.replace_group_members(spec.groupname, replacement, dry_run=dry_run)
        return SystemResult(
            ok=True,
            status=ResultStatus.SUCCESS,
            action=ACTION_QUERY_GROUP,
            target=spec.groupname,
            message="Group members listed.",
            details={
                "groupname": spec.groupname,
                "members": self.get_group_members(spec.groupname),
            },
            changed=False,
        )
    
    def is_root_group(self, groupname: str | None = None, gid: int | None = None) -> bool:
        return groupname == ROOT_GROUP_NAME or gid == ROOT_GID
    
    def is_sudo_group(self, groupname: str) -> bool:
        return _normalize_groupname(groupname, allow_reserved=True) == "sudo"
    
    def is_wheel_group(self, groupname: str) -> bool:
        return _normalize_groupname(groupname, allow_reserved=True) == "wheel"
    
    def is_admin_group(self, groupname: str, gid: int | None = None) -> bool:
        groupname = _normalize_groupname(groupname, allow_reserved=True)
        return groupname in ADMIN_GROUPS or self.is_root_group(groupname, gid)
    
    def is_protected_group(self, groupname: str, gid: int | None = None) -> bool:
        groupname = _normalize_groupname(groupname, allow_reserved=True)
        return groupname in PROTECTED_GROUPS or self.is_root_group(groupname, gid)
    
    def grants_elevated_privileges(self, groupname: str, gid: int | None = None) -> bool:
        return self.is_admin_group(groupname, gid)

    def check_required_commands(self) -> dict[str, bool]:
        return {binary: self.executor.check_dependency(binary).ok for binary in sorted(REQUIRED_COMMANDS)}
    
    def ensure_group_absent(self, groupname: str) -> None:
        if self.group_exists(groupname):
            raise GroupAlreadyExistsError("Group already exists.", details={"groupname": groupname})
        
    def ensure_group_exists(self, groupname: str) -> None:
        if not self.group_exists(groupname):
            raise GroupNotFoundError("Group not found.", details={"groupname": groupname})
        
    def ensure_gid_available(self, gid: int) -> None:
        try:
            self.get_group_by_gid(gid)
        except GroupNotFoundError:
            return
        raise InvalidGidError("GID is already in use.", details={"gid": gid})
    
    def ensure_not_protected_group(
        self,
        groupname: str,
        gid: int | None = None,
        *,
        operation: str,
        allow_protected: bool = False,
    ) -> None:
        groupname = _normalize_groupname(groupname, allow_reserved=True)
        allow_protected = _coerce_bool(
            allow_protected,
            field_name="allow_protected",
            default=False,
        )

        if self.is_protected_group(groupname, gid) and not allow_protected:
            raise GroupMembershipError(
                "Operation is blocked for protected group.",
                details={
                    "groupname": groupname,
                    "gid": gid,
                    "operation": operation,
                    "allow_protected_required": True,
                },
            )

        if self.is_admin_group(groupname, gid) and not allow_protected:
            raise GroupMembershipError(
                "Operation is blocked for administrative group.",
                details={
                    "groupname": groupname,
                    "gid": gid,
                    "operation": operation,
                    "allow_protected_required": True,
                },
            )


    def ensure_user_exists(self, username: str) -> None:
        username = _normalize_username(username)
        result = self.executor.execute(
            _build_getent_passwd_command(username), 
            action=ACTION_QUERY_GROUP, 
            target=username, 
            dry_run=False
        )
        if not result.ok or not result.execution or not result.execution.stdout.strip():
            raise UserNotFoundError("User not found.", details={"username": username})
        
    def validate_group_not_protected(self, groupname: str) -> list[str]:
        return self._security_warnings(groupname, None, operation="validate")
    
    def get_primary_members_for_group(self, gid: int | None) -> list[str]:
        if gid is None:
            return []
        normalized_gid = _normalize_gid(gid, allow_system_gid=True)
        result = self.executor.execute(
            _build_getent_passwd_command(), 
            action=ACTION_QUERY_GROUP, 
            target="passwd", 
            dry_run=False
        )
        if not result.ok or not result.execution:
            return []
        members: list[str] = []
        for line in result.execution.stdout.splitlines():
            parts = line.split(FIELD_SEPARATOR)
            if len(parts) >= 4 and parts[3].isdigit() and int(parts[3]) == normalized_gid:
                members.append(parts[0])
        return _normalize_members(members)
    
    def _raise_from_result(self, result: SystemResult, *, action: str, groupname: str) -> None:
        stderr = result.execution.stderr.lower() if result.execution else ""
        stdout = result.execution.stdout.lower() if result.execution else ""
        combined = f"{stderr} {stdout}"
        details = {"action": action, "groupname": groupname, "result": result.summary()}
        if "already exists" in combined or "exists" in combined:
            raise GroupAlreadyExistsError("Group already exists.", details=details)
        if "does not exist" in combined or "not found" in combined or "no such" in combined:
            raise GroupNotFoundError("Group not found.", details=details)
        if "gid" in combined and ("in use" in combined or "not unique" in combined or "exists" in combined):
            raise InvalidGidError("GID conflict detected.", details=details)
        if "permission denied" in combined or "not permitted" in combined:
            raise InsufficientPermissionsError("Insufficient permissions for group operation.", details=details)
        if "user" in combined and ("does not exist" in combined or "not found" in combined):
            raise UserNotFoundError("User not found.", details=details)
        if "not a member" in combined or "is not a member" in combined:
            raise UserNotInGroupError("User is not a member of the group.", details=details)
        if "already a member" in combined:
            raise UserAlreadyInGroupError("User already belongs to the group.", details=details)
        raise CommandExecutionError("Linux group command failed.", details=details)
    
    def _with_allow_protected_audit(
        self,
        metadata: Mapping[str, Any],
        *,
        allow_protected: bool,
    ) -> dict[str, Any]:
        audited = dict(metadata)

        if allow_protected:
            audited["allow_protected"] = True

        return audited

    def _execute_mutation(
        self,
        command: Sequence[str],
        *,
        action: str,
        target: str,
        user: str | None = None,
        warnings: Sequence[str] = (),
        dry_run: bool | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> SystemResult:
        operation_metadata = {
            "group": target,
            "user": user,
            "warnings": list(warnings),
            "module": "system/linux_groups",
        }
        if metadata:
            operation_metadata.update(dict(metadata))

        result = self.executor.execute(
            command,
            action=action,
            target=target,
            dry_run=_coerce_bool(dry_run, field_name="dry_run", default=self.dry_run),
            metadata=operation_metadata
        )
        result.warnings.extend(warning for warning in warnings if warning not in result.warnings)
        result.details.update({
            "group": target, 
            "user": user, 
            "changes_applied": result.changed, 
            "resources_affected": [target] + ([user] if user else [])
        })
        if metadata:
            result.details.update(dict(metadata))
        if not result.ok:
            self._raise_from_result(result, action=action, groupname=target)
        return result
    
    def build_query_result(self, groupname: str) -> SystemResult:
        group = self.get_group(groupname)
        return SystemResult(
            ok=True, 
            status=ResultStatus.SUCCESS, 
            action=ACTION_QUERY_GROUP, 
            target=group.groupname, 
            message="Group query completed.", 
            details=group.to_dict()
        )
    
    def to_summary(self, group: SystemGroup) -> GroupSummary:
        return group.summary

    def _security_warnings(
        self, 
        groupname: str, 
        gid: int | None, 
        *, 
        operation: str
    ) -> list[str]:
        warnings: list[str] = []
        groupname = _normalize_groupname(groupname, allow_reserved=True)
        if self.is_protected_group(groupname, gid):
            warnings.append(f"Operation '{operation}' targets protected group '{groupname}'.")
        if self.is_admin_group(groupname, gid):
            warnings.append(f"Operation '{operation}' targets administrative/elevated group '{groupname}'.")
        if operation in {"delete", "change_gid", "replace_members", "add_member", "remove_member"} and self.is_admin_group(groupname, gid):
            warnings.append("This operation may change administrative privileges.")
        return warnings

__all__ = [
    "ADMIN_GROUPS",
    "PROTECTED_GROUPS",
    "REQUIRED_COMMANDS",
    "LinuxGroupManager",
]