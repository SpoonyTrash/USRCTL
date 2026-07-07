from pathlib import Path
from typing import Any, Mapping, Sequence

from models.user import (
    AccountStatus,
    PasswordStatus,
    PrivilegeLevel,
    SystemUser,
    UserCreateSpec,
    UserSummary,
    UserType,
    UserUpdateSpec,
)
from system.executor import CommandExecutor
from system.result import CommandResult, DryRunResult, ImpactLevel, ImpactMetadata, ResultStatus, SystemResult
from utils.errors import (
    AccountLockError,
    CommandExecutionError,
    HomeDirectoryError,
    InsufficientPermissionsError,
    InvalidShellError,
    InvalidUidError,
    UserAlreadyExistsError,
    UserNotFoundError, 
    ResourceNotFoundError,
    ValidationError,
    GroupMembershipError,   
)
from utils.validators import validate_username, validate_groupname

CMD_USERADD = "useradd"
CMD_USERMOD = "usermod"
CMD_USERDEL = "userdel"
CMD_ID = "id"
CMD_GETENT = "getent"
CMD_PASSWD = "passwd"

PASSWD_PATH = Path("/etc/passwd")
SHADOW_PATH = Path("/etc/shadow")
GROUP_PATH = Path("/etc/group")
SHELLS_PATH = Path("/etc/shells")
DEFAULT_HOME_ROOT = Path("/home")

NON_INTERACTIVE_SHELLS = frozenset({"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/nologin"})
ADMIN_GROUPS = frozenset({"sudo", "wheel", "admin", "adm"})
PROTECTED_USERS = frozenset({"root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody"})
PASSWD_FIELDS = ("username", "password", "uid", "gid", "gecos", "home", "shell")
NORMAL_USER_MIN_UID = 1000
REQUIRED_COMMANDS = (CMD_USERADD, CMD_USERMOD, CMD_USERDEL, CMD_ID, CMD_GETENT, CMD_PASSWD)

def _normalize_username(username: str, *, allow_reserved: bool = True) -> str:
    return validate_username(str(username).strip(), allow_reserved=allow_reserved) 

def _normalize_home(home: str | Path | None) -> str | None:
    if home is None:
        return None
    text = str(home).strip()
    if not text:
        return None

    path = Path(text)

    if not path.is_absolute():
        raise HomeDirectoryError(
            "Home directory must be an absolute path.",
            details={"home": text},
        )

    return str(path)
def _normalize_shell(shell: str | Path | None) -> str | None:
    if shell is None:
        return None
    text = str(shell).strip()
    if not text:
        return None
    if not text.startswith("/"):
        raise InvalidShellError("Shell must be an absolute path.", details={"shell": text})
    return str(Path(text))

def _normalize_groups(groups: Sequence[str] | str | None) -> list[str]:
    if groups is None:
        return []
    raw = groups.split(",") if isinstance(groups, str) else groups
    seen: set[str] = set()

    normalized: list[str] = []
    
    for item in raw:
        try:
            group = validate_groupname(str(item).strip(), allow_reserved=True)
        except GroupMembershipError as exc:
            raise ValidationError(
                "Group name format is invalid.",
                details=exc.details,
                cause=exc,
            ) from exc

        if group not in seen:
            seen.add(group)
            normalized.append(group)

    return normalized

def _validate_uid(uid: Any) -> int:
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 0:
        raise InvalidUidError(
            "UID must be a non-negative integer.",
            details={"uid": uid},
        )
    return uid
    
def _validate_gid(gid: Any) -> int:
    if isinstance(gid, bool) or not isinstance(gid, int) or gid < 0:
        raise ValidationError(
            "GID must be a non-negative integer.",
            details={"gid": gid},
        )
    return gid


def _coerce_bool(value: Any, *, field_name: str, default: bool = False) -> bool:
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        if value in (0, 1):
            return bool(value)
        raise ValidationError(f"{field_name} must be a boolean-like value.")

    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1"}:
            return True
        if normalized in {"false", "no", "n", "0"}:
            return False
        raise ValidationError(
            f"{field_name} must be one of: true/false, yes/no, 1/0."
        )

    raise ValidationError(f"{field_name} must be a boolean-like value.")

def _normalize_gecos(gecos: Any) -> str:
    text = str(gecos).strip()

    if not text:
        raise ValidationError("GECOS cannot be empty.")

    if ":" in text or "\n" in text or "\r" in text:
        raise ValidationError(
            "GECOS cannot contain ':' or line breaks.",
            details={"gecos": text},
        )

    return text

def _parse_passwd_line(line: str) -> dict[str, Any]:
    parts = line.rstrip("\n").split(":")
    if len(parts) != len(PASSWD_FIELDS):
        raise ValidationError("Unexpected /etc/passwd entry format.", details={"line": line})
    data = dict(zip(PASSWD_FIELDS, parts, strict=True))
    try:
        data["uid"] = int(data["uid"])
        data["gid"] = int(data["gid"])
    except ValueError as exc:
        raise ValidationError("Invalid numeric UID/GID in passwd entry.", details={"line": line}, cause=exc) from exc
    return data

def _parse_getent_passwd(output: str) -> dict[str, Any]:
    line = next((item for item in output.splitlines() if item.strip()), "")
    if not line:
        raise UserNotFoundError("User not found in getent passwd output.")
    return _parse_passwd_line(line)

def _parse_id_output(output: str) -> dict[str, Any]:
    payload: dict[str, Any] = {"groups": []}
    for token in output.strip().split():
        if token.startswith("uid="):
            try:
                payload["uid"] = int(token.split("=", 1)[1].split("(", 1)[0])
            except ValueError as exc:
                raise ValidationError(
                    "Invalid uid value in id output.",
                    details={"output": output},
                    cause=exc,
                ) from exc        
        elif token.startswith("gid="):
            try:
                payload["gid"] = int(token.split("=", 1)[1].split("(", 1)[0])
            except ValueError as exc:
                raise ValidationError(
                    "Invalid gid value in id output.",
                    details={"output": output},
                    cause=exc,
                ) from exc
        elif token.startswith("groups="):
            groups: list[str] = []
            for item in token.split("=", 1)[1].split(","):
                if "(" in item and ")" in item:
                    groups.append(item.split("(", 1)[1].split(")", 1)[0])
            payload["groups"] = _normalize_groups(groups)
    return payload

def _parse_groups_output(output: str, *, colon_format: bool = False) -> list[str]:
    text = output.strip()
    if colon_format and ":" in text:  
        text = text.split(":", 1)[1]
    return _normalize_groups(text.split())

def _user_type_for_uid(uid: int | None, groups: Sequence[str]) -> UserType:
    if uid == 0:
        return UserType.ADMIN
    if uid is not None and uid < NORMAL_USER_MIN_UID:
        return UserType.SYSTEM
    if any(group in ADMIN_GROUPS for group in groups):
        return UserType.ADMIN
    return UserType.REGULAR

def _build_useradd_command(spec: UserCreateSpec) -> list[str]:
    command = [CMD_USERADD]
    if spec.uid is not None:
        command.extend(["--uid", str(spec.uid)])
    if spec.gid is not None:
        command.extend(["--gid", str(spec.gid)])
    if spec.home:
        command.extend(["--home-dir", str(Path(spec.home))])
    if spec.create_home:
        command.append("--create-home")
    else:
        command.append("--no-create-home")
    if spec.shell:
        command.extend(["--shell", spec.shell])
    if spec.groups:
        command.extend(["--groups", ",".join(_normalize_groups(spec.groups))])
    command.append(spec.username)
    return command

def _build_userdel_command(username: str, *, remove_home: bool = False) -> list[str]:
    command = [CMD_USERDEL]
    if remove_home:
        command.append("--remove")
    command.append(username)
    return command

def _build_usermod_command(username: str, **changes: Any) -> list[str]:
    command = [CMD_USERMOD]
    if changes.get("uid") is not None:
        command.extend(["--uid", str(changes["uid"])])
    if changes.get("home") is not None:
        command.extend(["--home", str(Path(changes["home"]))])
        if changes.get("move_home"):
            command.append("--move-home")
    if changes.get("shell") is not None:
        command.extend(["--shell", str(changes["shell"])])
    if changes.get("gecos") is not None:
        command.extend(["--comment", _normalize_gecos(changes["gecos"])])
    if changes.get("groups") is not None:
        command.extend(["--groups", ",".join(_normalize_groups(changes["groups"]))])
    if changes.get("append_groups"):
        command.append("--append")
    if changes.get("lock"):
        command.append("--lock")
    if changes.get("unlock"):
        command.append("--unlock")
    command.append(username)
    return command

def _build_getent_passwd_command(identifier: str | int | None = None) -> list[str]:
    command = [CMD_GETENT, "passwd"]
    if identifier is not None:
        command.append(str(identifier))
    return command

def _build_id_command(username: str) -> list[str]:
    return [CMD_ID, username]

class LinuxUserManager:
    def __init__(self, executor: CommandExecutor | None = None, *, dry_run: bool | None = None) -> None:
        self.executor = executor or CommandExecutor()
        if dry_run is not None:
            self.executor.config.dry_run = dry_run
        self.passwd_path = PASSWD_PATH
        self.shadow_path = SHADOW_PATH
        self.group_path = GROUP_PATH
        self.shells_path = SHELLS_PATH
        self.home_root = DEFAULT_HOME_ROOT

    def user_exists(self, username: str) -> bool:
        username = _normalize_username(username)
        result = self._execute_query(_build_getent_passwd_command(username), action="query_user", target=username)
        return result.ok

    def get_user(self, username: str, *, include_groups: bool = True, include_status: bool = True) -> SystemUser:
        username = _normalize_username(username)
        result = self._execute_query(_build_getent_passwd_command(username), action="query_user", target=username)
        if not result.ok:
            self._raise_user_not_found(username, result)
        user = self._user_from_passwd(_parse_getent_passwd(result.execution.stdout if result.execution else ""))
        if include_groups:
            user.groups = self.get_user_groups(username)
        if include_status:
            locked = self.is_user_locked(username)
            user.account_locked = locked
            user.status = AccountStatus.LOCKED if locked else AccountStatus.ACTIVE
            user.password_status = PasswordStatus.LOCKED if locked else PasswordStatus.UNKNOWN
        return self._mark_privileges(user)

    def get_user_by_uid(self, uid: int) -> SystemUser:
        uid = _validate_uid(uid)
        result = self._execute_query(_build_getent_passwd_command(uid), action="query_user", target=str(uid))
        if not result.ok:
            raise UserNotFoundError("User with UID not found.", details={"uid": uid})
        return self._mark_privileges(self._user_from_passwd(_parse_getent_passwd(result.execution.stdout if result.execution else "")))

    def _user_from_passwd(self, payload: Mapping[str, Any]) -> SystemUser:
        user = SystemUser.from_passwd_entry(payload)
        user.metadata.update({"source": str(self.passwd_path), "passwd_fields": PASSWD_FIELDS})
        return user
    
    def list_users(
        self,
        *,
        include_groups: bool = True,
        include_status: bool = False,
    ) -> list[SystemUser]:
        result = self._execute_query(_build_getent_passwd_command(), action="query_user", target="all")
        if not result.ok:
            self._raise_from_result(result, default_message="Unable to list system users.")
        users = []
        for line in (result.execution.stdout if result.execution else "").splitlines():
            if line.strip():
                user = self._user_from_passwd(_parse_passwd_line(line))

                if include_groups:
                    user.groups = self.get_user_groups(user.username)

                if include_status:
                    locked = self.is_user_locked(user.username)
                    user.account_locked = locked
                    user.status = AccountStatus.LOCKED if locked else AccountStatus.ACTIVE
                    user.password_status = PasswordStatus.LOCKED if locked else PasswordStatus.UNKNOWN

                users.append(self._mark_privileges(user))        
        return users

    def list_normal_users(self) -> list[SystemUser]:
        return [user for user in self.list_users(include_groups=True) if not user.is_system_user]

    def list_system_users(self) -> list[SystemUser]:
        return [user for user in self.list_users(include_groups=True) if user.is_system_user]

    def get_user_details(self, username: str) -> SystemUser:
        username = _normalize_username(username)
        return self.get_user(username, include_groups=True, include_status=True)

    def list_user_summaries(self) -> list[UserSummary]:
        return [user.to_summary() for user in self.list_users()]
    
    def create_user(
        self, 
        username: str, 
        *, 
        uid: int | None = None, 
        home: str | None = None, 
        shell: str | None = None, 
        groups: Sequence[str] | None = None, 
        create_home: bool = True, 
        dry_run: bool | None = None
    ) -> SystemResult:
        username = _normalize_username(username, allow_reserved=False)
        uid = None if uid is None else _validate_uid(uid)
        normalized_shell = _normalize_shell(shell) or "/bin/sh"
        self.ensure_shell_installed(normalized_shell)
        spec = UserCreateSpec(
            username=username, 
            uid=uid, 
            home=_normalize_home(home), 
            shell=normalized_shell,
            groups=_normalize_groups(groups), 
            create_home=create_home
        )
        return self.create_user_from_spec(spec, dry_run=dry_run)

    def create_user_from_spec(
        self, 
        spec: UserCreateSpec, 
        *, 
        dry_run: bool | None = None
    ) -> SystemResult:
        normalized_shell = _normalize_shell(spec.shell) or "/bin/sh"
        normalized_spec = UserCreateSpec(
            username=_normalize_username(spec.username, allow_reserved=False),
            uid=None if spec.uid is None else _validate_uid(spec.uid),
            gid=None if spec.gid is None else _validate_gid(spec.gid),
            home=_normalize_home(spec.home),
            shell=normalized_shell,
            groups=_normalize_groups(spec.groups),
            create_home=spec.create_home,
        )
        self.ensure_user_absent(normalized_spec.username)
        if normalized_spec.uid is not None:
            self.ensure_uid_available(normalized_spec.uid)
        self.ensure_shell_installed(normalized_shell)
        command = _build_useradd_command(normalized_spec)
        warnings = self.warn_if_protected_user(normalized_spec.username)
        return self._execute_user_command(
            command, 
            action="create_user", 
            username=normalized_spec.username, 
            dry_run=dry_run, 
            changes={
                "created_user": normalized_spec.username, 
                "create_home": normalized_spec.create_home, 
                "home": normalized_spec.home, 
                "uid": normalized_spec.uid, 
                "groups": list(normalized_spec.groups)
            }, 
            warnings=warnings, 
            affected=[normalized_spec.username, normalized_spec.home or str(self.home_root / normalized_spec.username)],
            impact=ImpactLevel.MEDIUM
        )

    def delete_user(
        self, 
        username: str, 
        *, 
        remove_home: bool = False, 
        dry_run: bool | None = None,
        allow_protected: bool = False
    ) -> SystemResult:        
        username = _normalize_username(username)
        self.ensure_user_exists(username)
        self.ensure_not_protected_user(username, operation="delete_user", allow_protected=allow_protected)
        warnings = self.warn_if_protected_user(username)
        action = "delete_user_home" if remove_home else "delete_user"
        affected = [username]
        if remove_home:
            try:
                affected.append(self.get_user(
                    username, 
                    include_groups=False, 
                    include_status=False).home or str(self.home_root / username))
            except UserNotFoundError:
                affected.append(str(self.home_root / username))
        return self._execute_user_command(
            _build_userdel_command(username, remove_home=remove_home), 
            action=action, 
            username=username, 
            dry_run=dry_run, 
            changes={"deleted_user": username, "remove_home": remove_home}, 
            warnings=warnings, 
            affected=affected, 
            impact=ImpactLevel.CRITICAL if remove_home else ImpactLevel.HIGH
        )

    def delete_user_only(
        self,
        username: str,
        *,
        dry_run: bool | None = None,
        allow_protected: bool = False,
    ) -> SystemResult:
        return self.delete_user(
            username,
            remove_home=False,
            dry_run=dry_run,
            allow_protected=allow_protected,
        )

    def delete_user_and_home(
        self,
        username: str,
        *,
        dry_run: bool | None = None,
        allow_protected: bool = False,
    ) -> SystemResult:
        return self.delete_user(
            username,
            remove_home=True,
            dry_run=dry_run,
            allow_protected=allow_protected,
        )

    def delete_user_and_home(self, username: str, *, dry_run: bool | None = None) -> SystemResult:
        return self.delete_user(username, remove_home=True, dry_run=dry_run)
    
    def modify_user(
        self, 
        spec: UserUpdateSpec, 
        *, 
        move_home: bool = False, 
        dry_run: bool | None = None,
        allow_protected: bool = False
    ) -> SystemResult:        
        spec.username = _normalize_username(spec.username)
        self.ensure_not_protected_user(spec.username, operation="modify_user", allow_protected=allow_protected)
        self.ensure_user_exists(spec.username)
        command = _build_usermod_command(
            spec.username, 
            home=spec.new_home, 
            move_home=move_home, 
            shell=spec.new_shell, 
            groups=spec.groups
        )
        if command == [CMD_USERMOD, spec.username]:
            return self._skipped_result(
                "modify_user", 
                spec.username, 
                "No usermod-compatible changes requested."
            )
        if spec.new_shell:
            self.ensure_shell_installed(spec.new_shell)
        return self._execute_user_command(
            command, 
            action="modify_user", 
            username=spec.username, 
            dry_run=dry_run, 
            changes={
                "new_home": spec.new_home, 
                "move_home": move_home, 
                "new_shell": spec.new_shell, 
                "groups": spec.groups
            }, 
            warnings=self.warn_if_protected_user(spec.username), 
            affected=[spec.username, spec.new_home] if spec.new_home else [spec.username], 
            impact=ImpactLevel.MEDIUM)

    def change_uid(            
        self, 
        username: str, 
        uid: int, *, 
        dry_run: bool | None = None,
        allow_protected: bool = False
    ) -> SystemResult:        
        username = _normalize_username(username)
        self.ensure_not_protected_user(username, operation="change_uid", allow_protected=allow_protected)
        self.ensure_user_exists(username)
        self.ensure_uid_available(uid)
        return self._execute_user_command(
            _build_usermod_command(username, uid=uid), 
            action="modify_user", 
            username=username, 
            dry_run=dry_run, 
            changes={"uid": uid}, 
            warnings=self.warn_if_protected_user(username), 
            affected=[username], 
            impact=ImpactLevel.HIGH
        )

    def change_home(
        self, 
        username: str, 
        home: str, 
        *, 
        move_home: bool = False, 
        dry_run: bool | None = None,
        allow_protected: bool = False
    ) -> SystemResult:
        username = _normalize_username(username)
        home = _normalize_home(home) or ""
        if not home:
            raise HomeDirectoryError("Home directory path cannot be empty.")
        self.ensure_user_exists(username)
        self.ensure_not_protected_user(username, operation="change_home", allow_protected=allow_protected)
        return self._execute_user_command(
            _build_usermod_command(
                username, 
                home=home, 
                move_home=move_home
            ), 
            action="change_user_home", 
            username=username, 
            dry_run=dry_run, 
            changes={"home": home, "move_home": move_home}, 
            warnings=self.warn_if_protected_user(username), 
            affected=[username, home], 
            impact=ImpactLevel.HIGH if move_home else ImpactLevel.MEDIUM)

    def change_shell(
        self, 
        username: str, 
        shell: str, 
        *, 
        dry_run: bool | None = None,
        allow_protected: bool = False
    ) -> SystemResult:
        username = _normalize_username(username)
        shell = _normalize_shell(shell) or ""
        self.ensure_user_exists(username)
        self.ensure_shell_installed(shell)
        self.ensure_not_protected_user(username, operation="change_shell", allow_protected=allow_protected)
        return self._execute_user_command(
            _build_usermod_command(username, shell=shell), 
            action="change_user_shell", 
            username=username, 
            dry_run=dry_run, 
            changes={"shell": shell}, 
            warnings=self.warn_if_protected_user(username), 
            affected=[username], 
            impact=ImpactLevel.MEDIUM
        )

    def change_gecos(
        self, 
        username: str, 
        gecos: str, 
        *, 
        dry_run: bool | None = None,
        allow_protected: bool = False
    ) -> SystemResult:
        username = _normalize_username(username)
        self.ensure_user_exists(username)
        self.ensure_not_protected_user(username, operation="change_gecos", allow_protected=allow_protected)
        return self._execute_user_command(
            _build_usermod_command(username, gecos=gecos), 
            action="modify_user", 
            username=username, 
            dry_run=dry_run, 
            changes={"gecos": gecos}, 
            warnings=[], 
            affected=[username], 
            impact=ImpactLevel.LOW
        )

    def replace_user_groups(
        self, 
        username: str, 
        groups: Sequence[str], 
        *, 
        dry_run: bool | None = None,
        allow_protected: bool = False
    ) -> SystemResult:
        username = _normalize_username(username)
        self.ensure_not_protected_user(username, operation="replace_user_groups", allow_protected=allow_protected)
        return self.assign_secondary_groups(
            username, 
            groups, 
            append=False, 
            dry_run=dry_run,
            allow_protected=allow_protected
        )

    def add_user_to_groups(
        self, 
        username: str, 
        groups: Sequence[str], 
        *, 
        dry_run: bool | None = None,
        allow_protected: bool = False
    ) -> SystemResult:
        username = _normalize_username(username)
        self.ensure_not_protected_user(username, operation="add_user_to_groups", allow_protected=allow_protected)
        return self.assign_secondary_groups(
            username, 
            groups, 
            append=True, 
            dry_run=dry_run, 
            allow_protected=allow_protected
        )

    def remove_user_from_groups(
        self, 
        username: str, 
        groups: Sequence[str], 
        *, 
        dry_run: bool | None = None,
        allow_protected: bool = False
    ) -> SystemResult:
        username = _normalize_username(username)
        self.ensure_not_protected_user(username, operation="remove_user_from_groups", allow_protected=allow_protected)
        self.ensure_user_exists(username)
        remove = set(_normalize_groups(groups))
        if not remove:
            return self._skipped_result(
                "remove_user_from_groups",
                username,
                "No groups requested for removal.",
            )
        current = self.get_secondary_groups(username)
        remaining = [group for group in current if group not in remove]
        return self._execute_user_command(
            _build_usermod_command(username, groups=remaining),
            action="remove_user_from_groups",
            username=username,
            dry_run=dry_run,
            changes={
                "removed_groups": sorted(remove),
                "remaining_groups": remaining,
            },
            warnings=self.warn_if_protected_user(username),
            affected=[username, *sorted(remove), *remaining],
            impact=ImpactLevel.MEDIUM,
        )

    def lock_user(
        self, 
        username: str, 
        *, 
        dry_run: bool | None = None,
        allow_protected: bool = False
    ) -> SystemResult:
        username = _normalize_username(username)
        self.ensure_not_protected_user(username, operation="lock_user", allow_protected=allow_protected)
        self.ensure_user_exists(username)
        return self._execute_user_command(
            _build_usermod_command(username, lock=True), 
            action="lock_user", 
            username=username, 
            dry_run=dry_run, 
            changes={"locked": True}, 
            warnings=self.warn_if_protected_user(username), 
            affected=[username], 
            impact=ImpactLevel.HIGH
        )

    def unlock_user(
        self, 
        username: str, 
        *, 
        dry_run: bool | None = None,
        allow_protected: bool = False,
    ) -> SystemResult:
        username = _normalize_username(username)
        self.ensure_not_protected_user(username, operation="unlock_user", allow_protected=allow_protected)
        self.ensure_user_exists(username)
        return self._execute_user_command(
            _build_usermod_command(username, unlock=True), 
            action="unlock_user", 
            username=username, 
            dry_run=dry_run, 
            changes={"locked": False}, 
            warnings=self.warn_if_protected_user(username), 
            affected=[username], 
            impact=ImpactLevel.HIGH
        )

    def get_password_lock_status(self, username: str) -> PasswordStatus:
        username = _normalize_username(username)
        result = self._execute_query(
            [CMD_PASSWD, "--status", username],
            action="query_user_lock_status",
            target=username,
        )
        if not result.ok:
            return PasswordStatus.UNKNOWN        
        stdout = result.execution.stdout.strip() if result.execution else ""
        parts = stdout.split()

        if len(parts) <= 1:
            return PasswordStatus.UNKNOWN

        if parts[1] in {"L", "LK"}:
            return PasswordStatus.LOCKED

        if parts[1] == "NP":
            return PasswordStatus.NO_PASSWORD

        if parts[1] in {"P", "PS"}:
            return PasswordStatus.SET

        return PasswordStatus.UNKNOWN

    def is_user_locked(self, username: str) -> bool:
        username = _normalize_username(username)
        return self.get_password_lock_status(username) == PasswordStatus.LOCKED

   #CONTINUAR CORRECCION AQUI 
    def has_non_interactive_shell(self, username: str) -> bool:
        username = _normalize_username(username)
        return (self.get_user(
            username, 
            include_groups=False, 
            include_status=False).shell or ""
        ) in NON_INTERACTIVE_SHELLS

    def get_user_groups(self, username: str) -> list[str]:
        username = _normalize_username(username)
        result = self._execute_query([CMD_ID, "-nG", username], action="query_user", target=username)
        if not result.ok:
            self._raise_user_not_found(username, result)
        return _parse_groups_output(
            result.execution.stdout if result.execution else "",
            colon_format=False,
        )    
    def get_primary_group(self, username: str) -> int | None:
        username = _normalize_username(username)
        return self.get_user(username, include_groups=False, include_status=False).gid

    def get_secondary_groups(self, username: str) -> list[str]:
        username = _normalize_username(username)
        user = self.get_user(
            username, 
            include_groups=False, 
            include_status=False
        )
        groups = self.get_user_groups(username)
        primary_name = self._group_name_by_gid(user.gid)
        return [group for group in groups if group != primary_name]

    def assign_secondary_groups(
        self, 
        username: str, 
        groups: Sequence[str], 
        *, 
        append: bool = False, 
        dry_run: bool | None = None,
        allow_protected: bool = False
    ) -> SystemResult:
        username = _normalize_username(username)
        self.ensure_not_protected_user(
            username,
            operation="assign_secondary_groups",
            allow_protected=allow_protected,
        )
        self.ensure_user_exists(username)
        normalized = _normalize_groups(groups)
        if append and not normalized:
            return self._skipped_result(
                "assign_user_groups",
                username,
                "No groups requested for append operation.",
            )
        command = _build_usermod_command(
            username, 
            groups=normalized, 
            append_groups=append
        )
        self.ensure_not_protected_user(username, operation="assign_secondary_groups", allow_protected=allow_protected)
        return self._execute_user_command(
            command, 
            action="assign_user_groups", 
            username=username, 
            dry_run=dry_run, 
            changes={"groups": normalized, "append": append}, 
            warnings=self.warn_if_protected_user(username), 
            affected=[username, *normalized], 
            impact=ImpactLevel.MEDIUM
        )
    
    def user_in_group(self, username: str, group: str) -> bool:
        username = _normalize_username(username)
        group_text = str(group).strip()
        if not group_text:
            raise ValidationError("Group name cannot be empty.")
        group = validate_groupname(group_text, allow_reserved=True)        
        return group in self.get_user_groups(username)
    
    def is_root_user(self, user: str | SystemUser) -> bool:
        if isinstance(user, SystemUser):
            return user.is_root
        username = _normalize_username(user)
        return username == "root" or self.get_user(
            username, 
            include_groups=False, 
            include_status=False
        ).uid == 0

    def is_sudo_user(self, username: str) -> bool:
        username = _normalize_username(username)
        return self.user_in_group(username, "sudo")
    
    def is_wheel_user(self, username: str) -> bool:
        username = _normalize_username(username)
        return self.user_in_group(username, "wheel")

    def has_admin_privileges(self, username: str, *, admin_groups: Sequence[str] | None = None) -> bool:
        username = _normalize_username(username)
        user = self.get_user(username, include_groups=True, include_status=False)
        groups = set(user.groups)
        return user.is_root or bool(groups.intersection(set(admin_groups or ADMIN_GROUPS)))

    def mark_user_privileges(self, user: SystemUser) -> SystemUser:
        return self._mark_privileges(user)
    
    def check_required_commands(self) -> dict[str, bool]:
        return {
            binary: self.executor.check_dependency(binary).ok
            for binary in REQUIRED_COMMANDS
        }
    
    def ensure_user_absent(self, username: str) -> None:
        username = _normalize_username(username, allow_reserved=False)
        if self.user_exists(username):
            raise UserAlreadyExistsError("User already exists.", details={"username": username})
        
    def ensure_user_exists(self, username: str) -> None:
        username = _normalize_username(username)
        if not self.user_exists(username):
            raise UserNotFoundError("User not found.", details={"username": username})

    def ensure_uid_available(self, uid: int) -> None:
        uid = _validate_uid(uid)
        result = self._execute_query(_build_getent_passwd_command(uid), action="query_user", target=str(uid))
        if result.ok:
            raise InvalidUidError("UID is already in use.", details={"uid": uid})
    
    def ensure_shell_installed(self, shell: str) -> None:
        shell = _normalize_shell(shell) or ""
        if not shell:
            raise InvalidShellError("Shell cannot be empty.")
        if self.shells_path.exists():
            try:
                shells = {line.strip() for line in self.shells_path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")}
            except OSError as exc:
                raise InvalidShellError("Unable to read /etc/shells.", details={"path": str(self.shells_path)}, cause=exc) from exc
            if shell not in shells and shell not in NON_INTERACTIVE_SHELLS:
                raise InvalidShellError("Shell is not listed in /etc/shells.", details={"shell": shell})
        elif not Path(shell).exists():
            raise InvalidShellError("Shell path does not exist.", details={"shell": shell})
    
    def ensure_not_protected_user(
        self,
        username: str,
        *,
        operation: str,
        allow_protected: bool = False,
    ) -> None:
        username = _normalize_username(username)
        allow_protected = _coerce_bool(
            allow_protected,
            field_name="allow_protected",
            default=False,
        )

        if username in PROTECTED_USERS and not allow_protected:
            raise ValidationError(
                "Operation is blocked for protected system user.",
                details={
                    "username": username,
                    "operation": operation,
                    "allow_protected_required": True,
                },
            )

    def warn_if_protected_user(self, username: str) -> list[str]:
        username = _normalize_username(username)
        if username in PROTECTED_USERS:
            return [f"'{username}' is a protected or critical system account."]
        return []
    
    def _execute_query(
        self,
        command: list[str],
        *,
        action: str,
        target: str,
    ) -> SystemResult:
        return self.executor.execute(
            command,
            action=action,
            target=target,
            dry_run=False,
        )



    def _raise_from_result(self, result: SystemResult, *, default_message: str) -> None:
        stderr = result.execution.stderr.lower() if result.execution else ""
        if "permission denied" in stderr or "not permitted" in stderr:
            raise InsufficientPermissionsError(default_message, details=result.to_log_record())
        if "not found" in stderr or "does not exist" in stderr:
            raise ResourceNotFoundError(default_message, details=result.to_log_record())
        raise CommandExecutionError(default_message, details=result.to_log_record())

    def _raise_user_not_found(self, username: str, result: SystemResult | None = None) -> None:
        raise UserNotFoundError("User not found.", details={"username": username, "result": result.to_log_record() if result else None})

    def _translate_mutation_failure(self, result: SystemResult, username: str) -> None:
        if result.ok or isinstance(result, DryRunResult):
            return
        stderr = (result.execution.stderr if result.execution else "").lower()
        if "already exists" in stderr or "not unique" in stderr:
            raise UserAlreadyExistsError("User already exists.", details=result.to_log_record())
        if "does not exist" in stderr or "not found" in stderr or "no such user" in stderr:
            raise UserNotFoundError("User not found.", details={"username": username, **result.to_log_record()})
        if "permission denied" in stderr or "not permitted" in stderr:
            raise InsufficientPermissionsError("Insufficient permissions for user operation.", details=result.to_log_record())
        if "uid" in stderr:
            raise InvalidUidError("Invalid or conflicting UID.", details=result.to_log_record())
        if "shell" in stderr:
            raise InvalidShellError("Invalid shell.", details=result.to_log_record())
        if "home" in stderr:
            raise HomeDirectoryError("Home directory operation failed.", details=result.to_log_record())
        if result.action in {"lock_user", "unlock_user"}:
            raise AccountLockError("Unable to lock or unlock user.", details=result.to_log_record())
        raise CommandExecutionError("Linux user command failed.", details=result.to_log_record())
    
    def _execute_user_command(
        self, 
        command: list[str], 
        *, 
        action: str, 
        username: str, 
        dry_run: bool | None, 
        changes: Mapping[str, Any], 
        warnings: Sequence[str], 
        affected: Sequence[str | None], 
        impact: ImpactLevel
    ) -> SystemResult:
        result = self.executor.execute(
            command, 
            action=action, 
            target=username, 
            dry_run=dry_run, 
            metadata={
                "changes": dict(changes), 
                "affected_resources": [item for item in affected if item], 
                "module": "system.linux_users"
            }
        )
        result.details.setdefault("changes", dict(changes))
        result.details.setdefault("status_final", "simulated" if result.dry_run else ("applied" if result.ok else "failed"))
        result.details.setdefault("impact", impact.value)
        for warning in warnings:
            if warning not in result.warnings:
                result.warnings.append(warning)
        resources = [str(item) for item in affected if item]
        result.impact = ImpactMetadata(
            level=max(
                result.impact.level, 
                impact, 
                key=lambda level: [ImpactLevel.NONE, ImpactLevel.LOW, ImpactLevel.MEDIUM, ImpactLevel.HIGH, ImpactLevel.CRITICAL].index(level)
            ), 
            affected_resources=resources or result.impact.affected_resources, 
            applied_resources=resources if result.changed else [], 
            skipped_changes=[] if result.changed else resources
            )
        self._translate_mutation_failure(result, username)
        return result
    
    def _skipped_result(
        self, 
        action: str, 
        username: str, 
        message: str
    ) -> SystemResult:
        return SystemResult(
            ok=True, 
            status=ResultStatus.SKIPPED, 
            action=action, 
            target=username, 
            message=message, 
            changed=False, 
            dry_run=False
        ) 

    def _mark_privileges(self, user: SystemUser) -> SystemUser:
        user.is_sudo = any(group in {"sudo", "wheel"} for group in user.groups)
        if user.uid == 0 or user.username == "root":
            user.privilege_level = PrivilegeLevel.ROOT
            user.user_type = UserType.ADMIN
        elif "sudo" in user.groups:
            user.privilege_level = PrivilegeLevel.SUDO
            user.user_type = UserType.ADMIN
        elif any(group in ADMIN_GROUPS for group in user.groups):
            user.privilege_level = PrivilegeLevel.ADMIN_GROUP
            user.user_type = UserType.ADMIN
        else:
            user.privilege_level = PrivilegeLevel.NONE
            user.user_type = _user_type_for_uid(user.uid, user.groups)
        return user

    def is_non_interactive_shell(self, shell: str | None) -> bool:
        return str(shell or "").strip() in NON_INTERACTIVE_SHELLS

    def protected_users(self) -> frozenset[str]:
        return PROTECTED_USERS
    
    def administrative_groups(self) -> frozenset[str]:
        return ADMIN_GROUPS
    
    def _group_name_by_gid(self, gid: int | None) -> str | None:
        if gid is None:
            return None
        result = self._execute_query([CMD_GETENT, "group", str(gid)], action="query_user", target=str(gid))
        if not result.ok or not result.execution.stdout.strip():
            return None
        return result.execution.stdout.split(":", 1)[0].strip() or None

LinuxUsers = LinuxUserManager

__all__ = [
  "ADMIN_GROUPS",
  "PROTECTED_USERS",
  "DEFAULT_HOME_ROOT",
  "NON_INTERACTIVE_SHELLS",
  "PASSWD_FIELDS",
  "LinuxUserManager",
  "LinuxUsers",
]