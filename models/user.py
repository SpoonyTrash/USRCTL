from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from typing import Any, Mapping

from utils.errors import InvalidGidError, InvalidUidError, InvalidShellError
from utils.validators import validate_username

ADMIN_GROUP_NAMES = frozenset({"sudo", "wheel", "adm"})
DEFAULT_USER_SHELL = "/bin/sh"
NON_INTERACTIVE_SHELL = frozenset({"/usr/bin/nologin", "/sbin/nologin", "/bin/false"})
NORMAL_USER_MIN_UID = 1000

class AccountStatus(str, Enum):
    ACTIVE = "active"
    LOCKED = "locked"
    EXPIRED = "expired"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"

class UserType(str, Enum):
    REGULAR = "regular"
    SYSTEM = "system"
    ADMIN = "admin"
    SERVICE = "service"

class PasswordStatus(str, Enum):
    SET = "set"
    LOCKED = "locked"
    EXPIRED = "expired"
    MUST_CHANGE = "must_change"
    UNKNOWN = "unknown"

class PrivilegeLevel(str, Enum):
    NONE = "none"
    ADMIN_GROUP = "admin_group"
    SUDO = "sudo"
    ROOT = "root"

class ModelOrigin(str, Enum):
    SYSTEM = "system"
    CLI_INPUT = "cli_input"
    TEMPLATE = "template"
    BACKUP = "backup"
    REPORT = "report"
    TEST = "test"

@dataclass(slots=True)
class SystemUser:
    username: str
    uid: int | None = None
    gid: int | None = None
    home: str | None = None
    shell: str = DEFAULT_USER_SHELL
    groups: list[str] = field(default_factory=list)
    status: AccountStatus = AccountStatus.UNKNOWN
    user_type: UserType = UserType.REGULAR
    privilege_level: PrivilegeLevel = PrivilegeLevel.NONE
    is_sudo: bool = False
    origin: ModelOrigin = ModelOrigin.SYSTEM

    expires_at: date | None = None
    password_last_changed_at: date | None = None
    password_max_days: int | None = None
    password_warn_days: int | None = None
    inactivity_days: int | None = None
    requires_password_change: bool = False
    account_locked: bool = False
    password_status: PasswordStatus = PasswordStatus.UNKNOWN

    gecos: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._normalize_and_validate()

    @property
    def is_root(self) -> bool:
        return self.uid == 0 or self.username == "root" or  self.privilege_level == PrivilegeLevel.ROOT
    
    @property
    def is_system_user(self) -> bool:
        if self.user_type == UserType.SYSTEM:
            return True
        return self.uid is not None and self.uid < NORMAL_USER_MIN_UID

    @property
    def is_regular_user(self) -> bool:
        return not self.is_system_user and self.user_type == UserType.REGULAR

    @property
    def has_home(self) -> bool:
        return bool(self.home and self.home.strip())
    
    @property
    def has_interactive_shell(self) -> bool:
        return bool(self.shell and self.shell not in NON_INTERACTIVE_SHELL)
    
    @property
    def has_admin_privileges(self) -> bool:
        if self.is_root or self.is_sudo:
            return True
        if self.privilege_level in {PrivilegeLevel.ROOT, PrivilegeLevel.SUDO, PrivilegeLevel.ADMIN_GROUP}:
            return True
        return any(group in ADMIN_GROUP_NAMES for group in self.groups)
    
    @property
    def is_locked(self) -> bool:
        return self.account_locked or self.status == AccountStatus.LOCKED or self.password_status == PasswordStatus.LOCKED
        
    @property
    def is_expired(self) -> bool:
        if self.status == AccountStatus.EXPIRED or self.password_status == PasswordStatus.EXPIRED:
            return True
        return self.expires_at is not None and self.expires_at < date.today()


    def _normalize_and_validate(self) -> None:
        self.username = validate_username(self.username, allow_reserved=True)
        self.status = _coerce_enum(self.status, AccountStatus, AccountStatus.UNKNOWN)
        self.user_type = _coerce_enum(self.user_type, UserType, UserType.REGULAR)
        self.privilege_level = _coerce_enum(self.privilege_level, PrivilegeLevel, PrivilegeLevel.NONE)
        self.origin = _coerce_enum(self.origin, ModelOrigin, ModelOrigin.SYSTEM)
        self.password_status = _coerce_enum(self.password_status, PasswordStatus, PasswordStatus.UNKNOWN)
        
        self.uid = self._validate_non_negative_int(self.uid, "uid", InvalidUidError)
        self.gid = self._validate_non_negative_int(self.gid, "gid", InvalidGidError)

        if self.home is not None:
            self.home = str(self.home).strip()
            if not self.home:
                self.home = None
        
        if not isinstance(self.shell, str) or not self.shell.strip():
            raise InvalidShellError("shell must be a non-empty string")
        self.shell = self.shell.strip()

        self.groups = sorted({str(group).strip() for group in self.groups if str(group).strip()})
    
    @staticmethod
    def _validate_non_negative_int(
        value: int | None, 
        field_name: str,
        error_cls: type[Exception]
    ) -> int | None:
        if value is None:
            return None
        if not isinstance(value, int) or value < 0:
            raise error_cls(f"{field_name} must be a non-negative integer")
        return value
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "uid": self.uid,
            "gid": self.gid,
            "home": self.home,
            "shell": self.shell,
            "groups": list(self.groups),
            "status": self.status.value,
            "user_type": self.user_type.value,
            "privilege_level": self.privilege_level.value,
            "is_sudo": self.is_sudo,
            "origin": self.origin.value,
            "security": self.security_info.to_dict(),
            "gecos": self.gecos,
            "metadata": dict(self.metadata)
        }
    
    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "uid": self.uid,
            "status": self.status.value,
            "is_sudo": self.is_sudo,
            "account_locked": self.is_locked,
            "expires_at": _date_to_iso(self.expires_at),
            "groups": list(self.groups),
            "origin": self.origin.value,
        }
    
    def to_report_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "uid": self.uid,
            "gid": self.gid,
            "home": self.home,
            "shell": self.shell,
            "groups": list(self.groups),
            "status": self.status.value,
            "user_type": self.user_type.value,
            "is_system_user": self.is_system_user,
            "has_interactive_shell": self.has_interactive_shell,
            "has_admin_privileges": self.has_admin_privileges,
            "expires_at": _date_to_iso(self.expires_at),
            "password_last_changed_at": _date_to_iso(self.password_last_changed_at),
            "origin": self.origin.value,
        }
    
    def to_summary(self) -> "UserSummary":
        return UserSummary(
            username=self.username,
            uid=self.uid,
            home=self.home,
            shell=self.shell,
            status=self.status,
            is_sudo=self.is_sudo,
            primary_group=self.gid,
            groups=list(self.groups)
        )
    
    @property
    def security_info(self) -> "UserSecurityInfo":
        return UserSecurityInfo(
            password_status=self.password_status,
            requires_password_change=self.requires_password_change,
            password_last_changed_at=self.password_last_changed_at,
            password_max_days=self.password_max_days,
            password_warn_days=self.password_warn_days,
            expires_at=self.expires_at,
            inactivity_days=self.inactivity_days,
            account_locked=self.account_locked
        )
    
    @classmethod
    def from_passwd_entry(cls, entry: Mapping[str, Any]) -> "SystemUser":
        return cls(
            username=str(entry.get("username", "")).strip(),
            uid=_coerce_int(entry.get("uid")),
            gid=_coerce_int(entry.get("gid")),
            gecos=_coerce_optional_str(entry.get("gecos")),
            home=_coerce_optional_str(entry.get("home")),
            shell=_coerce_optional_str(entry.get("shell")) or DEFAULT_USER_SHELL,
            origin=ModelOrigin.SYSTEM
        )
    
    @classmethod
    def from_system_data(cls, payload: Mapping[str, Any]) -> "SystemUser":
        return cls(
            username=str(payload.get("username", "")).strip(),
            uid=_coerce_int(payload.get("uid")),
            gid=_coerce_int(payload.get("gid")),
            home=_coerce_optional_str(payload.get("home")),
            shell=_coerce_optional_str(payload.get("shell")) or DEFAULT_USER_SHELL,
            groups=_coerce_groups(payload.get("groups")),
            status=_coerce_enum(payload.get("status"), AccountStatus, AccountStatus.UNKNOWN),
            user_type=_coerce_enum(payload.get("user_type"), UserType, UserType.REGULAR),
            privilege_level=_coerce_enum(payload.get("privilege_level"), PrivilegeLevel, PrivilegeLevel.NONE),
            is_sudo=bool(payload.get("is_sudo", False)),
            expires_at=_coerce_date(payload.get("expires_at")),
            password_last_changed_at=_coerce_date(payload.get("password_last_changed_at")),
            password_max_days=_coerce_int(payload.get("password_max_days")),
            password_warn_days = _coerce_int(payload.get("password_warn_days")),
            inactivity_days = _coerce_int(payload.get("inactivity_days")),
            requires_password_change=bool(payload.get("requires_password_change", False)),
            account_locked=bool(payload.get("account_locked", False)),
            password_status=_coerce_enum(payload.get("password_status"), PasswordStatus, PasswordStatus.UNKNOWN),
            gecos=_coerce_optional_str(payload.get("gecos")),
            metadata=dict(payload.get("metadata") or {}),
            origin=ModelOrigin.SYSTEM
        )
    
    @classmethod
    def from_partial(cls, payload: Mapping[str, Any]) -> "SystemUser":
        return cls.from_system_data(payload)

@dataclass(slots=True)
class UserStatus:
    status: AccountStatus = AccountStatus.UNKNOWN
    account_locked: bool = False
    expires_at: date | None = None
    inactivity_days: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "account_locked": self.account_locked,
            "expires_at": _date_to_iso(self.expires_at),
            "inactivity_days": self.inactivity_days
        }

@dataclass(slots=True)
class UserCreateSpec:
    username:str
    uid: int | None = None
    gid: int | None = None
    home: str | None = None
    create_home: bool = True
    shell: str = DEFAULT_USER_SHELL
    groups: list[str] = field(default_factory=list)
    template: str | None = None
    limits: dict[str, Any] = field(default_factory=dict)
    initial_password_policy: dict[str, Any] = field(default_factory=dict)
    force_password_change: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    origin: ModelOrigin = ModelOrigin.CLI_INPUT

    def __post_init__(self) -> None:
        self.username = validate_username(self.username, allow_reserved=True)
        self.uid = SystemUser._validate_non_negative_int(self.uid, "uid")
        self.gid = SystemUser._validate_non_negative_int(self.gid, "gid")
        self.shell = (self.shell or "").strip()
        if not self.shell:
            raise InvalidShellError("shell must be a non-empty string")
        self.groups = sorted({str(group).strip() for group in self.groups if str(group).strip()})
    
    @classmethod
    def minimal(cls, username: str) -> "UserCreateSpec":
        return cls(username=username)
    
    @classmethod
    def advanced(
        cls,
        username: str,
        *,
        uid: int | None = None,
        home: str | None = None,
        shell: str = DEFAULT_USER_SHELL,
        groups: list[str] | None = None
    ) -> "UserCreateSpec":
        return cls(username=username, uid=uid, home=home, shell=shell, groups=groups or [])
    
    @classmethod
    def from_template(cls, template_data: Mapping[str, Any]) -> "UserCreateSpec":
        return cls.from_cli_args(template_data, origin=ModelOrigin.TEMPLATE)

    @classmethod
    def from_cli_args(
        cls,
        cli_data: Mapping[str, Any],
        *,
        origin: ModelOrigin = ModelOrigin.CLI_INPUT
    ) -> "UserCreateSpec":
        return cls(
            username=str(cli_data.get("username", "")).strip(),
            uid=_coerce_int(cli_data.get("uid")),
            gid=_coerce_int(cli_data.get("gid")),
            home=_coerce_optional_str(cli_data.get("home")),
            create_home=bool(cli_data.get("create_home", True)),
            shell=_coerce_optional_str(cli_data.get("shell")) or DEFAULT_USER_SHELL,
            groups=_coerce_groups(cli_data.get("groups")),
            template=_coerce_optional_str(cli_data.get("template")),
            limits=dict(cli_data.get("limits") or {}),
            initial_password_policy=dict(cli_data.get("initial_password_policy") or {}),
            force_password_change=bool(cli_data.get("force_password_change", False)),
            metadata=dict(cli_data.get("metadata") or {}),
            origin=origin, 
        )
    
    def to_dict(self) -> dict[str, Any]:
        return{
            "username": self.username,
            "uid": self.uid,
            "gid": self.gid,
            "home": self.home,
            "create_home": self.create_home,
            "shell": self.shell,
            "groups": list(self.groups),
            "template": self.template,
            "limits": dict(self.limits),
            "initial_password_policy": dict(self.initial_password_policy),
            "force_password_change": self.force_password_change,
            "metadata": dict(self.metadata),
            "origin": self.origin.value
        }

@dataclass(slots=True)
class UserUpdateSpec:
    username: str
    new_home: str | None = None
    new_shell: str | None = None
    groups: list[str] | None = None
    lock_account: bool | None = None
    expires_at: date | None = None
    inactivity_days: int | None = None
    password_max_days: int | None = None
    password_warn_days: int | None = None
    requires_password_change: bool | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "new_home": self.new_home,
            "new_shell": self.new_shell,
            "groups": list(self.groups or []),
            "lock_account": self.lock_account,
            "expires_at": _date_to_iso(self.expires_at),
            "inactivity_days": self.inactivity_days,
            "password_max_days": self.password_max_days,
            "password_warn_days": self.password_warn_days,
            "requires_password_change": self.requires_password_change,
            "metadata": dict(self.metadata),
        }

    
    
@dataclass(slots=True)
class UserSecurityInfo:
    password_status: PasswordStatus = PasswordStatus.UNKNOWN
    requires_password_change: bool = False
    password_last_changed_at: date | None = None
    password_max_days: int | None = None
    password_warn_days: int | None = None
    expires_at: date | None = None
    inactivity_days: int | None = None
    account_locked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "password_status": self.password_status.value,
            "requires_password_change": self.requires_password_change,
            "password_last_changed_at": _date_to_iso(self.password_last_changed_at),
            "password_max_days": self.password_max_days,
            "password_warn_days": self.password_warn_days,
            "expires_at": _date_to_iso(self.expires_at),
            "inactivity_days": self.inactivity_days,
            "account_locked": self.account_locked
        }

@dataclass(slots=True)
class UserSummary:
    username: str
    uid: int | None
    home: str | None
    shell: str
    status: AccountStatus
    is_sudo: bool
    primary_group: int | None
    groups: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "uid": self.uid,
            "home": self.home,
            "shell": self.shell,
            "status": self.status.value,
            "is_sudo": self.is_sudo,
            "primary_group": self.primary_group,
            "groups": list(self.groups)
        }
    
def _coerce_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None

def _coerce_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, int):
        return value
    return int(str(value).strip())

def _coerce_groups(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",")]
    else:
        parts = [str(part).strip() for part in value]
    return sorted({part for part in parts if part})

def _coerce_enum(value: Any, enum_cls: type[Enum], default: Enum) -> Any:
    if isinstance(value, enum_cls):
        return value
    if value is None:
        return default
    try:
        return enum_cls(value)
    except ValueError:
        return default

def _coerce_date(value: Any) -> date | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))

def _date_to_iso(value: date | None) -> str | None:
    return value.isoformat() if value else None

__all__ = [
    "AccountStatus",
    "UserType",
    "PasswordStatus",
    "PrivilegeLevel",
    "ModelOrigin",
    "SystemUser",
    "UserCreateSpec",
    "UserUpdateSpec",
    "UserSummary",
    "UserStatus",
    "UserSecurityInfo"
]