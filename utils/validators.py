from typing import Any, Sequence, Mapping, Iterable
from pathlib import Path
import re
from datetime import date, datetime

from utils.errors import (
    ValidationError, 
    GroupMembershipError, 
    InvalidUidError, 
    InvalidUsernameError, 
    InvalidSimulationError, 
    PathValidationError, 
    InvalidShellError, 
    DangerousImpactError,
    BackupCreationError,
    PermissionChangeError,
    WeakPasswordError,
    AccountExpirationError,
    InactivityPolicyError,
    LoginRestrictionError,
    AdvancedSecurityPolicyError,
    InvalidLimitError,
    LimitsConsistencyError,
    BackupVersioningError,
    InvalidTemplateError
)

ALLOWED_EXPORT_FORMATS = {"json", "csv"}
ALLOWED_LOGIN_RESTRICTIONS = {
  "none",
  "ssh_only",
  "local_only",
  "no_interactive",
  "deny_all"
}
ALLOWED_SHELLS = {
  "/bin/bash",
  "/bin/sh",
  "/bin/dash",
  "/bin/zsh",
  "/usr/bin/bash",
  "/usr/bin/sh",
  "/usr/bin/zsh",
  "/usr/bin/fish",
  "/sbin/nologin",
  "/usr/sbin/nologin",
  "/bin/false",
  "/usr/bin/false"
}
ALLOWED_TEMPLATE_ROLES = {"dev", "admin", "support"}
GID_MAX = 60000
GID_MIN = 0
UID_MAX = 60000
UID_MIN = 0
RESERVED_ID_MAX = 999
USERNAME_MIN_LENGTH = 1
USERNAME_MAX_LENGTH = 32
GROUPNAME_MIN_LENGTH = 1
GROUPNAME_MAX_LENGTH = 32
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 512
BACKUP_NAME_MAX_LENGTH = 128
REPORT_FILENAME_MAX_LENGTH = 128
PASSWORD_MAX_DAYS_MIN = 1
PASSWORD_MAX_DAYS_MAX = 99999
INTERNAL_NAME_MIN_LENGTH = 2
INTERNAL_NAME_MAX_LENGTH = 64
TEMPLATE_NAME_MIN_LENGTH = 2
TEMPLATE_NAME_MAX_LENGTH = 64
INACTIVITY_DAYS_MIN = 0
INACTIVITY_DAYS_MAX = 36500
MAX_PROCESSES_MIN = 1
MAX_PROCESSES_MAX = 2_000_000
MEMORY_LIMIT_MB_MIN = 4
MEMORY_LIMIT_MB_MAX = 16 * 1024 * 1024
OPEN_FILE_MIN = 16
OPEN_FILE_MAX = 10_000_000
USERNAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]*[$]?$")
GROUPNAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]*[$]?$")
INTERNAL_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
OCTAL_MODE_PATTERN = re.compile(r"^[0-7]{3,4}$")
EXPORT_FILENAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
SYMBOLIC_MODE_PATTERN = re.compile(r"^[ugoa]*[+=-][rwxXstugo]+(?:,[ugoa]*[+=-][rwxXstugo]+)*$")
PROTECTED_SYSTEM_PATHS = {
  "/",
  "/bin",
  "/boot",
  "/dev",
  "/etc",
  "/lib",
  "/lib64",
  "/proc",
  "/root",
  "/run",
  "/sbin",
  "/sys",
  "/usr",
  "/var"
}
RESERVED_GROUPNAMES = {
    "root",
    "daemon",
    "adm",
    "wheel",
    "sudo"
}

RESERVED_USERNAMES = {
    "root",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "nobody"
}

RESERVED_BACKUP_TARGETS = {"/", "/etc", "/bin", "/usr", "/root", "/boot"}

def validate_bool_flag(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ValidationError(f"{field_name} must be boolean.", details={"field": field_name})

def validate_in_set(value: str, field_name: str, allowed: set[str]) -> str:
    if value not in allowed:
        raise ValidationError(
            f"{field_name} must be one of: {', '.join(sorted(allowed))}.",
            details={"field": field_name, "value": value}
        )
    return value

def validate_int(value: Any, field_name: str) -> int:
    normalized = _safe_int(value, field_name)
    return normalized

def validate_length(value: str, field_name: str, *, min_len: int, max_len: int) -> str:
    if len(value) < min_len or len(value) > max_len:
        raise ValidationError(
            f"{field_name} length must be between {min_len} and {max_len}.",
            details={"field": field_name, "min_len": min_len, "max_len": max_len},           
        )
    return value

def validate_non_empty_list(values: Any, field_name: str) -> list[Any]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ValidationError(f"{field_name} must be a list.", details={"field": field_name})
    normalized = [v for v in values]
    if not normalized:
        raise ValidationError(f"{field_name} cannot be empty.", details={"field": field_name})
    return normalized

def validate_non_empty_string(value: Any, field_name: str) -> str:
    normalized = _normalize_text(value)
    if not normalized:
        raise ValidationError(
            f"{field_name} is required and cannot be empty.",
            details={"field": field_name}
        )
    return normalized

def validate_positive_int(value: Any, field_name: str, *, allow_zero: bool = False) -> int:
    normalized = validate_int(value, field_name)
    if allow_zero and normalized < 0:
        raise ValidationError(f"{field_name} must be >= 0.", details={"field": field_name})
    if not allow_zero and normalized <= 0:
        raise ValidationError(f"{field_name} must be > 0.", details={"field": field_name})
    return normalized

def validate_gid(gid: Any, *, allow_system_gid: bool = False) -> int:
    value = validate_int(gid, "gid")
    if value < GID_MIN or value > GID_MAX:
        raise  GroupMembershipError(f"GID must be between {GID_MIN} and {GID_MAX}.", details={"gid": value})
    if not allow_system_gid and value <= RESERVED_ID_MAX:
        raise GroupMembershipError("System-reserved GID range is not allowed.", details={"gid": value})
    return value

def validate_uid(uid: Any, *, allow_system_uid: bool = False) -> int:
    value = validate_int(uid, "uid")
    if value < UID_MIN or value > UID_MAX:
        raise  InvalidUidError(f"UID must be between {UID_MIN} and {UID_MAX}.", details={"uid": value})
    if not allow_system_uid and value <= RESERVED_ID_MAX:
        raise InvalidUidError("System-reserved UID range is not allowed.", details={"uid": value})
    return value

def validate_username(username: Any, *, allow_reserved: bool = False) -> str:
    value = validate_non_empty_string(username, "username").lower()
    validate_length(
        value,
        "username",
        min_len=USERNAME_MIN_LENGTH,
        max_len=USERNAME_MAX_LENGTH
    )
    if not USERNAME_PATTERN.match(value):
        raise InvalidUsernameError(
            "Username format is invalid.",
            details={"username": value, "pattern": USERNAME_PATTERN.pattern}
        )
    if not allow_reserved and value in RESERVED_USERNAMES:
        raise InvalidUsernameError("Reserved username is not allowed.", details={"username": value})
    return value

def validate_groupname(groupname: Any, *, allow_reserved: bool = False) -> str:
    value = validate_non_empty_string(groupname, "groupname").lower()
    validate_length(
        value,
        "groupname",
        min_len=GROUPNAME_MIN_LENGTH,
        max_len=GROUPNAME_MAX_LENGTH
    )
    if not GROUPNAME_PATTERN.match(value):
        raise GroupMembershipError(
            "Group name format is invalid.",
            details={"groupname": value, "pattern": GROUPNAME_PATTERN.pattern}
        )
    if not allow_reserved and value in RESERVED_GROUPNAMES:
        raise GroupMembershipError("Reserved group name is not allowed.", details={"groupname": value})
    return value

def validate_internal_name(name: Any, *, field_name: str = "name") -> str:
    value = validate_non_empty_string(name, field_name)
    value = _normalize_internal_name(value)
    validate_length(
        value,
        field_name,
        min_len=INTERNAL_NAME_MIN_LENGTH,
        max_len=INTERNAL_NAME_MAX_LENGTH
    )
    if not INTERNAL_NAME_PATTERN.match(value):
        raise ValidationError(
            f"{field_name} contains invalid characters.",
            details={"field": field_name, "value": value}
        )
    return value

def validate_account_lock_operation(*, username: Any, lock: bool, unlock: bool) -> dict[str, Any]:
    user = validate_username(username)
    lock = validate_bool_flag(lock, "lock")
    unlock = validate_bool_flag(unlock, "unlock")
    if lock and unlock:
        raise InvalidSimulationError("Cannot lock and unlock at the same time.", details={"username": user})
    if not lock and not unlock:
        raise InvalidSimulationError("Either lock or unlock must be selected.", details={"username": user})
    return {"username": user, "lock": lock, "unlock": unlock}

def validate_assignable_groups(groups: Sequence[Any]) -> list[str]:
    normalized = validate_groups_list(groups)
    return normalized

def validate_home_directory(home: Any, *, must_exist: bool = False) -> str:
    value = validate_absolute_path(home, field_name="home", must_exist=must_exist)
    validate_safe_home_path(value)
    return value 

def validate_shell(shell: Any) -> str:
    value = validate_absolute_path(shell, field_name="shell", must_exist=False)
    if any(x in value for x in (" ", ";", "|", "&", "`", "$", "\n", "\t")):
        raise InvalidShellError("Shell contains unsafe characters.", details={"shell": value})
    if value not in ALLOWED_SHELLS:
        raise InvalidShellError("Shell is not in the allowed list.", details={"shell": value})
    return value

def validate_user_creation_params(
    *,
    username: Any,
    uid: Any | None,
    home: Any | None,
    shell: Any | None,
    groups: Sequence[Any] | None,
    create_home: bool = True
) -> dict[str, Any]:
    result: dict[str, Any] = {"username": validate_username(username)}
    if uid is not None:
        result["uid"] = validate_uid(uid)
    if home is not None:
        result["home"] = validate_home_directory(home, must_exist=False)
    if shell is not None:
        result["shell"] = validate_shell(shell)
    result["create_home"] = validate_bool_flag(create_home, "create_home")
    if groups is not None:
        result["groups"] = validate_assignable_groups(groups)
    else:
        result["groups"] = []
    return result

def validate_user_delete_operation(
    *,
    username: Any,
    remove_home: bool,
    backup_before_delete: bool,
    account_only: bool = False
) -> dict[str, Any]:
    user = validate_username(username)
    remove_home = validate_bool_flag(remove_home, "remove_home")
    backup_before_delete = validate_bool_flag(backup_before_delete, "backup_before_delete")
    account_only = validate_bool_flag(account_only, "account_only")

    if account_only and remove_home:
        raise ValidationError(
            "Account_only and remove_home cannot both be true,",
            details={"username": user}
        )
    if remove_home and not backup_before_delete:
        raise DangerousImpactError("Deleting home without backup is blocked by defalut.", details={"username": user})
    return {
        "username": user,
        "remove_home": remove_home,
        "backup_before_delete": backup_before_delete,
        "account_only": account_only
    }
        
def validate_group_creation(groupname: Any, gid: Any | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {"groupname": validate_groupname(groupname)}
    if gid is not None:
        data["gid"] = validate_gid(gid)
    return data

def validate_group_membership(*, username: Any, groupname: Any) -> dict[str, str]:
    return{
        "username": validate_username(username),
        "groupname": validate_groupname(groupname)
    }

def validate_group_operation(operation: Any) -> str:
    op = validate_non_empty_string(operation, "operation").lower()
    return validate_in_set(op, "operation", {"create", "delete", "add", "remove", "list"})

def validate_members_list(members: Sequence[Any]) -> list[str]:
    names = [validate_username(m, allow_reserved=True) for m in validate_non_empty_list(members, "members")]
    return _dedupe_preserve_order(names)


def validate_groups_list(groups: Sequence[Any]) -> list[str]:
    names = [validate_groupname(g, allow_reserved=True) for g in validate_non_empty_list(groups, "groups")]
    deduped = _dedupe_preserve_order(names)
    return deduped

def validate_path(path_value: Any, *, field_name: str = "path", must_exist: bool = False) -> str:
    path_str = validate_non_empty_string(path_value, field_name)
    if any(c in path_str for c in ("\x00", "\n", "\r")):
        raise PathValidationError("Path contains invalid control characters.", details={"field": field_name})
    normalized = _normalize_path(path_str)
    if must_exist and not Path(normalized).exists():
        raise PathValidationError("Path does not exist.", details={"field": field_name, "path": normalized})
    return normalized

def validate_absolute_path(path_value: Any, *, field_name: str = "path", must_exist: bool = False) -> str:
    normalized = validate_path(path_value, field_name=field_name, must_exist=must_exist)
    if not Path(normalized).is_absolute():
        raise PathValidationError("Path must be absolute.", details={"field": field_name, "path": normalized})
    return normalized

def validate_safe_home_path(path_value: Any) -> str:
    normalized = validate_absolute_path(path_value, field_name="home")
    if _is_protected_path(normalized):
        raise PathValidationError("Home path cannot be a protected system path.", details={"home": normalized})
    if not normalized.startswith("/home/") and not normalized.startswith("/srv/home"):
        raise PathValidationError("Home path must be under /home or /srv/home.", details={"home": normalized})
    return normalized

def validate_backup_destination(path_value: Any, *, must_exist: bool = False) -> str:
    normalized = validate_absolute_path(path_value, field_name="backup_path", must_exist=must_exist)
    if normalized in RESERVED_BACKUP_TARGETS:
        raise BackupCreationError("Backup destination cannot be a critical system root.", details={"backup_path": normalized})
    return normalized

def validate_recursive_target(path_value: Any) -> str:
    normalized = validate_sensitive_path(path_value, allow_protected=False)
    return normalized

def validate_sensitive_path(path_value: Any, *, allow_protected: bool = False) -> str:
    normalized = validate_absolute_path(path_value)
    if not allow_protected and _is_protected_path(normalized):
        raise PathValidationError("Operation against protected system path is not allowed.", details={"path": normalized})
    return normalized

def validate_permission_mode(mode: Any) -> str:
    value = validate_non_empty_string(mode, "mode")
    if OCTAL_MODE_PATTERN.match(value) or SYMBOLIC_MODE_PATTERN.match(value):
        return value
    raise PermissionChangeError("Invalid permission mode format.", details={"mode": value})

def validate_chmod_operation(*, mode: Any, path: Any, recursive: bool = False) -> dict[str, Any]:
    mode_value = validate_permission_mode(mode)
    path_value = validate_sensitive_path(path)
    recursive_value = validate_bool_flag(recursive, "recursive")
    if recursive_value and _is_protected_path(path_value):
        raise DangerousImpactError("Recursive chmod on protected path is blocked.", details={"path": path_value})
    return {"mode": mode_value, "path": path_value, "recursive": recursive_value}

def validate_chown_operation(
    *,
    owner: Any,
    group: Any | None,
    path: Any,
    recursive: bool = False
) -> dict[str, Any]:
    owner_value = validate_username(owner, allow_reserved=True)
    group_value = validate_groupname(group, allow_reserved=True) if group is not None else None
    path_value = validate_sensitive_path(path)
    recursive_value = validate_bool_flag(recursive, "recursive")
    if recursive_value and _is_protected_path(path_value):
        raise DangerousImpactError("Recursive chown on protected path is blocked.", details={"path": path_value})
    return {
        "owner": owner_value,
        "group": group_value,
        "path": path_value,
        "recursive": recursive_value
    }

def validate_pre_execution_impact(*, path: Any, recursive: bool, dry_run: bool) -> dict[str, Any]:
    path_value = validate_sensitive_path(path)
    recursive_value = validate_bool_flag(recursive, "recursive")    
    dry_run_value = validate_bool_flag(dry_run, "dry_run")
    if recursive_value and not dry_run_value and _is_protected_path(path_value):
        raise  DangerousImpactError("Critical path + recursive + non dry-run is blocked.", details={"path": path_value})
    return {"path": path_value, "recursive": recursive_value, "dry_run": dry_run_value}

def validate_recursive_operation(recursive: Any, path: Any) -> tuple[bool, str]:
    path_value = validate_sensitive_path(path)
    recursive_value = validate_bool_flag(recursive, "recursive")        
    if recursive_value and _is_protected_path(path_value):
        raise DangerousImpactError("Unsafe recursive operation blocked.", details={"path": path_value})
    return recursive_value, path_value

def validate_password_change_flags(
    *,
    manual_password: bool,
    generate_password: bool,
    force_change_next_login: bool,
) -> dict[str, bool]:
    manual_password = validate_bool_flag(manual_password, "manual_password")
    generate_password = validate_bool_flag(generate_password, "generate_password")
    force_change_next_login = validate_bool_flag(force_change_next_login, "force_change_next_login")

    if manual_password and generate_password:
        raise ValidationError("Cannot provide manual and generated password simultaneously.")
    if not manual_password and not generate_password:
        raise ValidationError("A password source must be selected.")
    return {
        "manual_password": manual_password,
        "generate_password": generate_password,
        "force_change_next_login": force_change_next_login
    }

def validate_password_min_length(password: Any, *, min_len: int = MIN_PASSWORD_LENGTH) -> str:
    value = validate_password_not_empty(password)
    if len(value) < min_len or len(value) > MAX_PASSWORD_LENGTH:
        raise WeakPasswordError(f"Password length must be between {min_len} and {MAX_PASSWORD_LENGTH}", details={"length": len(value)})
    return value


def validate_password_not_empty(password: Any) -> str:
    value = validate_non_empty_string(password, "password")
    if len(value.strip()) == 0:
        raise WeakPasswordError("Password cannot be blank.")
    return value

def validate_password_option_compatibility(*, password: str | None, generate: bool) -> None:
    if generate and password:
        raise ValidationError("Password text is incompatible with generate option.")
    if not generate and not password:
        raise ValidationError("Password text is required when generate is false.")
    
def validate_secret_input(secret: Any, *, field_name: str = "secret") -> str:
    value = validate_non_empty_string(secret, field_name)
    if value.lower() in {"password", "123456", "admin", "qwerty"}:
        raise WeakPasswordError("Secret is too predectible.", details={"field": field_name})
    if any(c in value for c in ("\x00", "\n", "\r")):
        raise WeakPasswordError("Secret contains invalid control characters.", details={"field": field_name})
    return value

def validate_expiration_date(value: Any, *, allow_today: bool = True) -> date:
    parsed = _parse_date(value, field_name="expiration_date")
    today = date.today()
    if allow_today and parsed < today:
        raise AccountExpirationError("Expiration date cannot be in the past.", details={"date": parsed.isoformat()})
    if not allow_today and parsed <= today:
        raise AccountExpirationError("Expiration date must be in the future.", details={"date": parsed.isoformat()})
    return parsed

def validate_inactivity_days(value: Any) -> int:
    parsed = validate_int(value, "inactivity_days")
    if parsed < INACTIVITY_DAYS_MIN or parsed > INACTIVITY_DAYS_MAX:
        raise InactivityPolicyError(f"inactivity_days must be between {INACTIVITY_DAYS_MIN} and {INACTIVITY_DAYS_MAX}", details={"inactivity_days": parsed})
    return parsed

def validate_login_restriction(value: Any) -> str:
    policy = validate_non_empty_string(value, "login_restriction").lower()
    if policy not in ALLOWED_LOGIN_RESTRICTIONS:
        raise LoginRestrictionError("Unsupported login restriction policy.", details={"value": policy, "allowed": sorted(ALLOWED_LOGIN_RESTRICTIONS)})
    return policy

def validate_password_max_days(value: Any) -> int:
    parsed = validate_int(value, "password_max_days")
    if parsed < PASSWORD_MAX_DAYS_MIN or parsed > PASSWORD_MAX_DAYS_MAX:
        raise AdvancedSecurityPolicyError(f"password_max_day must be between {PASSWORD_MAX_DAYS_MIN} and {PASSWORD_MAX_DAYS_MAX}", details={"password_max_days": parsed})
    return parsed

def validate_policy_combination(
    *,
    expiration_date_value: Any | None,
    password_max_days: Any | None,
    inactivity_days: Any | None,
    login_restrictions: Any | None
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if expiration_date_value is not None:
        result["expiration_date"] = validate_expiration_date(expiration_date_value)
    if password_max_days is not None:
        result["password_max_days"] = validate_password_max_days(password_max_days)
    if inactivity_days is not None:
        result["inactivity_days"] = validate_inactivity_days(inactivity_days)
    if login_restrictions is not None:
        result["login_restrictions"] = validate_login_restriction(login_restrictions)
    
    if result.get("inactivity_days", 0) and result.get("password_max_days", 99999) < result["inactivity_days"]:
        raise AdvancedSecurityPolicyError("inactivity_days cannot exceed password_max_days.", details=result)
    return result

def validate_limits_profile(*, subject: Any, limits: Mapping[str, Any]) -> dict[str, Any]:
    subject_name = validate_internal_name(subject, field_name="subject")
    if not isinstance(limits, Mapping):
        raise InvalidLimitError("limits profle must ve  mapping.")
    
    normalized: dict[str, Any] = {"subject": subject_name}
    if "max_processes" in limits:
        normalized["max_processes"] = validate_max_processes(limits["max_processes"])
    if "memory_limit_mb" in limits:
        normalized["memory_limit_mb"] = validate_memory_limit_mb(limits["memory_limit_mb"])
    if "open_files" in limits:
        normalized["open_files"] = validate_open_files_limit(limits["open_files"])
    
    if not any(k in normalized for k in ("max_processes", "memory_limit_mb", "open_files")):
        raise LimitsConsistencyError("At least one limit must be set.", details={"subject": subject_name})
    return normalized


def validate_max_processes(value: Any) -> int:
    parsed = validate_positive_int(value, "max_processes")
    if parsed < MAX_PROCESSES_MIN or parsed > MAX_PROCESSES_MAX:
        raise InvalidLimitError(f"max_processes must be between {MAX_PROCESSES_MIN} and {MAX_PROCESSES_MAX}", details={"max_processes": parsed})
    return parsed

def validate_memory_limit_mb(value: Any) -> int:
    parsed = validate_positive_int(value, "memory_limit_mb")
    if parsed < MEMORY_LIMIT_MB_MIN or parsed > MEMORY_LIMIT_MB_MAX:
        raise InvalidLimitError(f"memory_limit_mb must be between {MEMORY_LIMIT_MB_MIN} and {MEMORY_LIMIT_MB_MAX}.", details={"memory_limit_mb": parsed})
    return parsed

def validate_open_files_limit(value: Any) -> int:
    parsed = validate_positive_int(value, "open_files")
    if parsed < OPEN_FILE_MIN or parsed > OPEN_FILE_MAX:
        raise InvalidLimitError(f"open_files must be between {OPEN_FILE_MIN} and {OPEN_FILE_MAX}.", details={"open_files": parsed})
    return parsed

def validate_limits_rule(rule: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(rule, Mapping):
        raise InvalidLimitError("limits rule must be a mapping")
    required = {"domain", "type", "item", "value"}
    missing = required.difference(rule.keys())
    if missing:
        raise InvalidLimitError("limits rule is missing required keys.", details={"missing": sorted(missing)})

    domain = validate_non_empty_string(rule["domain"], "domain")
    limit_type = validate_in_set(validate_non_empty_string(rule["type"], "type"), "type", {"soft", "hard", "-"})
    item = validate_in_set(
        validate_non_empty_string(rule["item"], "item"),
        "item",
        {"noproc", "nofile", "rss", "memlock", "cpu", "as"}
    )

    value = validate_positive_int(rule["value"], "value")
    return  {"domain": domain, "type": limit_type, "item": item, "value": value}

def validate_backup_name(value: Any) -> str:
    name = validate_internal_name(value, field_name="backup_name")
    validate_length(name, "backup_name", min_len=3, max_len=BACKUP_NAME_MAX_LENGTH)
    return name

def validate_backup_path(path_value: Any) -> str:
    return validate_backup_destination(path_value, must_exist=False)

def validate_backup_version(value: Any) -> str:
    version = validate_non_empty_string(value, "backup_version")
    if not re.match(r"^v?\d{1,6}$", version):
        raise BackupVersioningError("Invalid backup version format.", details={"backup_version": version})
    return version


def  validate_backup_restore_coherence(*, backup_name: Any, version: Any, destination: Any) -> dict[str, Any]:
    return {
        "backup_name": validate_backup_name(backup_name),
        "version": validate_backup_version(version),
        "destination": validate_backup_destination(destination)
    }

def validate_restore_critical_overwrite(*, target_path: Any, overwrite: bool) -> dict[str, Any]:
    target = validate_absolute_path(target_path, field_name="target_path")
    overwrite_flag = validate_bool_flag(overwrite, "overwrite")
    if _is_protected_path(target) and not overwrite_flag:
        raise DangerousImpactError("Critical restore blocked without overwrite confirmation.", details={"target": target})
    return {"target_path": target, "overwrite": overwrite_flag}

def validate_restore_params(
    *,
    backup_name: Any,
    version: Any,
    target_path: Any,
    overwrite: bool
) -> dict[str, Any]:
    data = {
        "backup_name": validate_backup_name(backup_name),
        "version": validate_backup_version(version),
        "target_path": validate_absolute_path(target_path, field_name="target_path"),
        "overwrite": validate_bool_flag(overwrite, "overwrite")
    }
    if _is_protected_path(data["target_path"]) and not data["overwrite"]:
        raise DangerousImpactError("Protected target restore requires explicit overwrite flag.", details={"target_path": data["target_path"]})
    return data

def validate_export_coherence(*, export_format: Any, export_path: Any, filename: Any) -> dict[str, str]:
    fmt = validate_export_format(export_format)
    path = validate_export_path(export_path)
    filename_value = validate_report_filename(filename)
    extension = Path(filename_value).suffix.lower().lstrip(".")
    if extension and extension != fmt:
        raise ValidationError("Report filename extension does not match selected format.", details={"filename": filename_value,  "format": fmt})
    return {"format": fmt, "export_path": path, "filename": filename_value}


def validate_export_format(value: Any) -> str:
    fmt = validate_non_empty_string(value, "format").lower()
    return validate_in_set(fmt, "format", ALLOWED_EXPORT_FORMATS)

def validate_export_path(path_value: Any) -> str:
    return validate_absolute_path(path_value, field_name="export_path", must_exist=False)

def validate_report_filename(value: Any) -> str:
    name = validate_non_empty_string(value, "filename")
    validate_length(name, "filename", min_len=3, max_len=REPORT_FILENAME_MAX_LENGTH)
    if not EXPORT_FILENAME_PATTERN.match(name):
        raise ValidationError("Invalid report filename.", details={"filename": name})
    return name

def validate_report_filters(filters: Mapping[str, Any] | None) -> dict[str, Any]:
    if filters is None:
        return {}
    if not isinstance(filters, Mapping):
        raise ValidationError("filters must be a mapping.")
    allowed_keys = {"active_only", "sudo_only", "group", "username"}
    unknown = set(filters.keys()) - allowed_keys
    if unknown:
        raise ValidationError("Unsupported report filters.", details={"unknown": sorted(unknown)})
    
    normalized: dict[str, Any] = {}
    if "active_only" in filters:
        normalized["active_only"] = validate_bool_flag(filters["active_only"], "active_only")
    if "sudo_only" in filters:
        normalized["sudo_only"] = validate_bool_flag(filters["sudo_only"], "sudo_only")
    if "group" in filters:
        normalized["group"] = validate_groupname(filters["group"], allow_reserved=True)
    if "username" in filters:
        normalized["username"] = validate_username(filters["username"], allow_reserved=True)
    return normalized
    
def validate_template_base_files(files: Sequence[Any]) -> list[str]:
    paths = validate_paths_list(files, must_exist=False)
    for p in paths:
        if Path(p).name.startswith(".") is False:
            raise InvalidTemplateError("Template basse file should be dotfile-style.", details={"file": p})
    return paths
    
def validate_template_groups(groups: Sequence[Any]) -> list[str]:
    return validate_groups_list(groups)

def validate_template_limits(limits: Mapping[str, Any], *, subject: Any = "template") -> dict[str, Any]:
    return validate_limits_profile(subject=subject, limits=limits)

def validate_template_name(value: Any) -> str:
    name = validate_internal_name(value, field_name="template_name")
    validate_length(name, "template_name", min_len=TEMPLATE_NAME_MIN_LENGTH, max_len=TEMPLATE_NAME_MAX_LENGTH)
    return name

def validate_template_permissions(permissions: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(permissions, Mapping) or not permissions:
        raise InvalidTemplateError("template permissions must be a non-empty string.")
    normalized: dict[str, str] = {}
    for target, mode in permissions.items():
        target_name = validate_internal_name(target, field_name="permissions_target")
        normalized[target_name] = validate_permission_mode(mode)
    return normalized

def validate_template_role(value: Any) -> str:
    role = validate_non_empty_string(value, "role").lower()
    return validate_in_set(role, "role", ALLOWED_TEMPLATE_ROLES)

def validate_composite_config(config: Mapping[str, Any], *, required_keys: Iterable[str] = ()) -> dict[str, Any]:
    if not isinstance(config, Mapping):
        raise ValidationError("config must be a mapping.")
    required = set(required_keys)
    missing = [k for k in required if k not in config]
    if missing:
        raise ValidationError("config is missing required keys.", details={"missing": sorted(missing)})
    return dict(config)

def validate_dry_run_security_flags(*, dry_run: Any, require_confirmation: Any) -> dict[str, bool]:
    dry_run_value = validate_bool_flag(dry_run, "dry_run")
    require_confirmation_value = validate_bool_flag(require_confirmation, "require_confirmation")
    if not dry_run_value and not require_confirmation_value:
        raise InvalidSimulationError("Unsafe operation requires dry_run or explicit confirmation gate.")
    return {"dry_run": dry_run_value, "requires_confirmation": require_confirmation_value}

def validate_mutually_exclusive_params(params: Mapping[str, Any], *, fields: Sequence[str]) -> None:
    present = [f for f in fields if params.get(f) not in (None, False, "", [])]
    if len(present) > 1:
        raise ValidationError("Mutually exclusive parameters were provided", details={"fields": present})

def validate_no_duplicates(values: Sequence[Any], *, field_name: str) -> list[Any]:
    normalized = validate_non_empty_list(values, field_name)
    return _dedupe_preserve_order(normalized)


def validate_paths_list(paths: Sequence[Any], *, must_exist: bool = False) -> list[str]:
    normalized = [validate_absolute_path(p, field_name="path", must_exist=must_exist) for p in validate_non_empty_list(paths, "paths")]
    return _dedupe_preserve_order(normalized)

def validate_required_together(params: Mapping[str, Any], *, fields: Sequence):
    present = [f for f in fields if params.get(f) not in (None, False, "", [])]
    if present and len(present) != len(fields):
        raise ValidationError("These parameters must be provided together.", details={"fields": list(fields)})



def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _safe_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValidationError(f"{field_name} must be an integer, not boolean.", details={"field": field_name})
    if isinstance(value, int):
        return value
    
    text = _normalize_text(value)
    
    if text == "":
        raise ValidationError(f"{field_name} is required.", details={"field": field_name})
    if not re.match(r"^-?\d+$", text):
        raise ValidationError(f"{field_name} must be an integer.", details={"field": field_name, "value": text})
    return int(text)

def _normalize_internal_name(name: str) -> str:
    return name.strip().lower().replace(" ", "-")

def _dedupe_preserve_order(values: Sequence[Any]) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result

def _normalize_path(path_value: str) -> str:
    expanded = str(Path(path_value).expanduser())
    normalized = str(Path(expanded))
    return normalized.rstrip("/") or "/"

def _is_protected_path(path_value: str) -> bool:
    path_obj = Path(path_value)
    for protected in PROTECTED_SYSTEM_PATHS:
        protected_obj = Path(protected)
        if path_obj == protected_obj:
            return True
        if protected_obj in path_obj.parents:
            return True
    return False
    
def _parse_date(value: Any, *, field_name: str) -> date:
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    text = validate_non_empty_string(value, field_name)
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError as exc:
        raise AccountExpirationError(f"{field_name} must use YYYY-MM-DD format.", details={"field": field_name, "value": text}, cause=exc) from exc


__all__ = [
    "ALLOWED_EXPORT_FORMATS",
    "ALLOWED_LOGIN_RESTRICTIONS",
    "ALLOWED_SHELLS",
    "ALLOWED_TEMPLATE_ROLES",
    "GID_MAX",
    "GID_MIN",
    "UID_MAX",
    "UID_MIN",
    "GROUPNAME_MAX_LENGTH",
    "GROUPNAME_MIN_LENGTH",
    "USERNAME_MAX_LENGTH",
    "USERNAME_MIN_LENGTH",
    "MIN_PASSWORD_LENGTH",
    "MAX_PASSWORD_LENGTH",
    "PROTECTED_SYSTEM_PATHS",
    "validate_bool_flag",
    "validate_in_set",
    "validate_int",
    "validate_length",
    "validate_non_empty_list",
    "validate_non_empty_string",
    "validate_positive_int",
    "validate_gid",
    "validate_groupname",
    "validate_internal_name",
    "validate_uid",
    "validate_username",
    "validate_account_lock_operation",
    "validate_assignable_groups",
    "validate_home_directory",
    "validate_shell",
    "validate_user_creation_params",
    "validate_user_delete_operation",
    "validate_group_creation",
    "validate_group_membership",
    "validate_group_operation",
    "validate_members_list",
    "validate_absolute_path",
    "validate_backup_destination",
    "validate_path",
    "validate_recursive_target",
    "validate_safe_home_path",
    "validate_sensitive_path",
    "validate_chmod_operation",
    "validate_chown_operation",
    "validate_permission_mode",
    "validate_pre_execution_impact",
    "validate_recursive_operation",
    "validate_password_change_flags",
    "validate_password_min_length",
    "validate_password_not_empty",
    "validate_password_option_compatibility",
    "validate_secret_input",
    "validate_expiration_date",
    "validate_inactivity_days",
    "validate_login_restriction",
    "validate_password_max_days",
    "validate_policy_combination",
    "validate_limits_profile",
    "validate_max_processes",
    "validate_memory_limit_mb",
    "validate_open_files_limit",
    "validate_limits_rule",
    "validate_backup_name",
    "validate_backup_path",
    "validate_backup_version",
    "validate_restore_critical_overwrite",
    "validate_backup_restore_coherence",
    "validate_restore_params",
    "validate_export_coherence",
    "validate_export_format",
    "validate_export_path",
    "validate_report_filters",
    "validate_template_base_files",
    "validate_template_groups",
    "validate_template_limits",
    "validate_template_name",
    "validate_template_permissions",
    "validate_template_role",
    "validate_dry_run_security_flags",
    "validate_groups_list",
    "validate_mutually_exclusive_params",
    "validate_no_duplicates",
    "validate_paths_list",
    "validate_required_together"

]