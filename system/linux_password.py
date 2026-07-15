from dataclasses import dataclass, field
from enum import StrEnum
from getpass import getuser
from pathlib import Path
from typing import Any, Mapping, Sequence

from system.executor import CommandExecutor, ExecutorConfig

from models.policy import PasswordPolicy, PolicyStatus, PolicyOrigin
from system.result import ImpactLevel, ImpactMetadata, ResultStatus, SystemResult
from utils.errors import (
    CommandExecutionError,
    ForcePasswordChangeError,
    InsufficientPermissionsError,
    PasswordChangeError,
    PolicyError,
    ResourceNotFoundError,
    UserNotFoundError,
    ValidationError,
    WeakPasswordError,

)
from utils.validators import validate_username

CMD_PASSWD = "passwd"
CMD_CHPASSWD = "chpasswd"
CMD_GETENT = "getent"
CMD_CHAGE = "chage"
CMD_USERMOD = "usermod"
CMD_ID = "id"

SHADOW_PATH = Path("/etc/shadow")

ACTION_CHANGE_PASSWORD = "change_password"
ACTION_APPLY_GENERATED_PASSWORD = "apply_generated_password"
ACTION_EXPIRE_PASSWORD = "expire_password"
ACTION_FORCE_PASSWORD_CHANGE = "force_password_change"
ACTION_CLEAR_PASSWORD_EXPIRATION = "clear_password_expiration"
ACTION_LOCK_PASSWORD = "lock_password"
ACTION_UNLOCK_PASSWORD = "unlock_password"
ACTION_QUERY_PASSWORD_STATUS = "query_password_status"
ACTION_SET_PASSWORD_POLICY = "set_password_policy"
ACTION_SET_PASSWORD_MAX_DAYS = "set_password_max_days"
ACTION_SET_PASSWORD_MIN_DAYS = "set_password_min_days"
ACTION_SET_PASSWORD_WARNING_DAYS = "set_password_warning_days"
ACTION_SET_PASSWORD_INACTIVE_DAYS = "set_password_inactive_days"

STATUS_ACTIVE = "active"
STATUS_LOCKED = "locked"
STATUS_UNKNOWN = "unknown"
STATUS_EXPIRED = "expired"
STATUS_REQUIRES_CHANGE = "requires_change"

CHAGE_LAST_CHANGE = "last_password_change"
CHAGE_PASSWORD_EXPIRES = "password_expires"
CHAGE_PASSWORD_INACTIVE = "password_inactive"
CHAGE_ACCOUNT_EXPIRES = "account_expires"
CHAGE_MIN_DAYS = "minimum_days_between_password_change"
CHAGE_MAX_DAYS = "maximum_days_between_password_change"
CHAGE_WARNING_DAYS = "warning_days_before_password_expires"
CHAGE_EXPECTED_FIELDS = (
    CHAGE_LAST_CHANGE,
    CHAGE_PASSWORD_EXPIRES,
    CHAGE_PASSWORD_INACTIVE,
    CHAGE_ACCOUNT_EXPIRES,
    CHAGE_MIN_DAYS,
    CHAGE_MAX_DAYS,
    CHAGE_WARNING_DAYS,
)


EXPIRE_IMMEDIATELY_VALUE = "0"
REDACTED_SECRET = "[REDACTED]"
REQUIRED_COMMANDS = (CMD_PASSWD, CMD_CHPASSWD, CMD_CHAGE, CMD_USERMOD, CMD_GETENT, CMD_ID)
SENSITIVE_DETAIL_KEYS = frozenset({"password", "secret", "hash", "credential", "stdin", "stdin_data"})
ADMIN_USER_NAMES = frozenset({"root"})

@dataclass(slots=True)
class PasswordApplySpec:
    username: str
    password: str | None = None
    force_change: bool = False
    generated: bool = False
    dry_run: bool | None = None

    def __post_init__(self) -> None:
        self.username = _normalize_username(self.username)
        self.force_change = _coerce_bool(
            self.force_change,
            field_name="force_change",
            default=False,
        )
        self.generated = _coerce_bool(
            self.generated,
            field_name="generated",
            default=False,
        )
        self.dry_run = (
            None
            if self.dry_run is None
            else _coerce_bool(self.dry_run, field_name="dry_run", default=False)
        )

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "password": REDACTED_SECRET if self.password else None,
            "force_change": self.force_change,
            "generated": self.generated,
            "dry_run": self.dry_run,
        }

@dataclass(slots=True)
class PasswordStatusInfo:
    username: str
    status: str = STATUS_UNKNOWN
    locked: bool = False
    expired: bool = False
    requires_change: bool = False
    last_changed: str | None = None
    password_expires: str | None = None
    password_inactive: str | None = None
    account_expires: str | None = None
    minimum_days: int | None = None
    maximum_days: int | None = None
    warning_days: int | None = None
    inactive_days: int | None = None
    raw_fields: dict[str, Any] = field(default_factory=dict)

    def to_policy_dict(self) -> dict[str, Any]:
        return {
            "target": self.username,
            "last_changed_at": self.last_changed,
            "min_password_age_days": self.minimum_days,
            "max_password_age_days": self.maximum_days,
            "warning_days": self.warning_days,
            "inactive_days": self.inactive_days,
            "password_expired": self.expired,
            "force_password_change": self.requires_change,
            "password_status": self.status,
        }
    
class PasswordCommandStrategy(StrEnum):
    PASSWD = "passwd"
    USERMOD = "usermod"


def _normalize_username(username: str) -> str:
    text = str(username).strip()
    if not text:
        raise ValidationError("Username cannot be empty.", details={"field": "username"})
    return validate_username(text, allow_reserved=True)

def _coerce_bool(value: Any, *, field_name: str, default: bool = False) -> bool:
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        if value in (0, 1):
            return bool(value)
        raise ValidationError(
            f"{field_name} must be a boolean-like value.",
            details={"field": field_name, "value": value},
        )

    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in {"true", "yes", "y", "1"}:
            return True

        if normalized in {"false", "no", "n", "0"}:
            return False

        raise ValidationError(
            f"{field_name} must be one of: true/false, yes/no, 1/0.",
            details={"field": field_name, "value": value},
        )

    raise ValidationError(
        f"{field_name} must be a boolean-like value.",
        details={"field": field_name, "value": value},
    )

def _normalize_password_state(value: str | None) -> str:
    text = (value or "").strip()
    if not text:
        return STATUS_UNKNOWN

    parts = text.split()
    status_token = parts[1].lower() if len(parts) > 1 else parts[0].lower()

    if status_token in {"p", "ps"}:
        return STATUS_ACTIVE

    if status_token == "np":
        return STATUS_UNKNOWN

    if status_token in {"e", "expired"}:
        return STATUS_EXPIRED

    return STATUS_UNKNOWN


def _normalize_chage_date(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text or text.lower() in {"never", "none"}:
        return None
    if text.lower() in {"password must be changed", "must be changed"}:
        return EXPIRE_IMMEDIATELY_VALUE
    return text

def _normalize_policy_days(value: Any, *, field_name: str, allow_never: bool = True) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise PolicyError(f"{field_name} must be a day count, not a boolean.", details={"field": field_name})
    try:
        days = int(value)
    except (TypeError, ValueError) as exc:
        raise PolicyError(f"{field_name} must be an integer day count.", details={"field": field_name, "value": value}, cause=exc) from exc
    if days < 0 and not (allow_never and days == -1):
        raise PolicyError(f"{field_name} cannot be negative.", details={"field": field_name, "value": days})
    return days

def _normalize_password_policy_field(value: Any, *, field_name: str) -> int | None:
    allow_never = field_name in {"maximum_days", "inactive_days"}
    return _normalize_policy_days(
        value,
        field_name=field_name,
        allow_never=allow_never,
    )


def _validate_password_strength(username: str, password: str | None) -> None:
    if password is None:
        raise WeakPasswordError(
            "Password value is required.",
            details={"username": username, "password": REDACTED_SECRET},
        )

    if len(password) < 12:
        raise WeakPasswordError(
            "Password must be at least 12 characters long.",
            details={"username": username, "password": REDACTED_SECRET},
        )

    if username.lower() in password.lower():
        raise WeakPasswordError(
            "Password cannot contain the username.",
            details={"username": username, "password": REDACTED_SECRET},
        )

    checks = {
        "uppercase": any(char.isupper() for char in password),
        "lowercase": any(char.islower() for char in password),
        "digit": any(char.isdigit() for char in password),
        "symbol": any(not char.isalnum() for char in password),
    }

    if not all(checks.values()):
        raise WeakPasswordError(
            "Password must include uppercase, lowercase, digit, and symbol.",
            details={
                "username": username,
                "password": REDACTED_SECRET,
                "checks": checks,
            },
        )


def _sanitize_command(command: Sequence[str]) -> list[str]:
    redacted: list[str] = []
    for index, token in enumerate(command):
        previous = command[index - 1].lower() if index else ""
        lowered = str(token).lower()
        if previous in {"-p", "--password", "--secret"} or any(key in lowered for key in SENSITIVE_DETAIL_KEYS):
            redacted.append(REDACTED_SECRET)
        else:
            redacted.append(str(token))
    return redacted

def _sanitize_text(value: str | None) -> str:
    if not value:
        return ""
    sanitized_lines: list[str] = []
    for line in str(value).splitlines():
        lowered = line.lower()
        if any(key in lowered for key in SENSITIVE_DETAIL_KEYS) or str(SHADOW_PATH) in line:
            sanitized_lines.append(REDACTED_SECRET)
        else:
            sanitized_lines.append(line)
    return "\n".join(sanitized_lines)


def _sanitize_details(details: Mapping[str, Any] | None) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in dict(details or {}).items():
        lowered = str(key).lower()
        if any(secret_key in lowered for secret_key in SENSITIVE_DETAIL_KEYS):
            clean[key] = REDACTED_SECRET
        elif isinstance(value, Mapping):
            clean[key] = _sanitize_details(value)
        elif isinstance(value, list):
            clean[key] = [REDACTED_SECRET if any(k in str(item).lower() for k in SENSITIVE_DETAIL_KEYS) else item for item in value]
        elif isinstance(value, str):
            clean[key] = _sanitize_text(value)
        else:
            clean[key] = value
    return clean

def _parse_chage_output(username: str, output: str) -> PasswordStatusInfo:
    fields: dict[str, Any] = {}
    name_map = {
        "last password change": CHAGE_LAST_CHANGE,
        "password expires": CHAGE_PASSWORD_EXPIRES,
        "password inactive": CHAGE_PASSWORD_INACTIVE,
        "account expires": CHAGE_ACCOUNT_EXPIRES,
        "minimum number of days between password change": CHAGE_MIN_DAYS,
        "maximum number of days between password change": CHAGE_MAX_DAYS,
        "number of days of warning before password expires": CHAGE_WARNING_DAYS,
    }
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        normalized_key = name_map.get(key.strip().lower())
        if not normalized_key:
            continue
        fields[normalized_key] = raw_value.strip()

    minimum_days = _normalize_policy_days(fields.get(CHAGE_MIN_DAYS), field_name=CHAGE_MIN_DAYS) if CHAGE_MIN_DAYS in fields else None
    maximum_days = _normalize_policy_days(fields.get(CHAGE_MAX_DAYS), field_name=CHAGE_MAX_DAYS) if CHAGE_MAX_DAYS in fields else None
    warning_days = _normalize_policy_days(fields.get(CHAGE_WARNING_DAYS), field_name=CHAGE_WARNING_DAYS) if CHAGE_WARNING_DAYS in fields else None
    inactive_days = _normalize_policy_days(fields.get(CHAGE_PASSWORD_INACTIVE), field_name=CHAGE_PASSWORD_INACTIVE) if str(fields.get(CHAGE_PASSWORD_INACTIVE, "")).strip().lower() not in {"", "never"} else None
    expires = _normalize_chage_date(fields.get(CHAGE_PASSWORD_EXPIRES))
    last_changed = _normalize_chage_date(fields.get(CHAGE_LAST_CHANGE))
    expired = expires == EXPIRE_IMMEDIATELY_VALUE or str(fields.get(CHAGE_LAST_CHANGE, "")).strip().lower() == "password must be changed"
    return PasswordStatusInfo(
        username=username,
        status=STATUS_EXPIRED if expired else STATUS_ACTIVE,
        expired=expired,
        requires_change=expired,
        last_changed=last_changed,
        password_expires=expires,
        password_inactive=_normalize_chage_date(fields.get(CHAGE_PASSWORD_INACTIVE)),
        account_expires=_normalize_chage_date(fields.get(CHAGE_ACCOUNT_EXPIRES)),
        minimum_days=minimum_days,
        maximum_days=maximum_days,
        warning_days=warning_days,
        inactive_days=inactive_days,
        raw_fields=_sanitize_details(fields),
    )

def _build_change_password_command() -> list[str]:
    return [CMD_CHPASSWD]

def _build_lock_password_command(username: str, strategy: PasswordCommandStrategy = PasswordCommandStrategy.PASSWD) -> list[str]:
    return [CMD_USERMOD, "-L", username] if strategy == PasswordCommandStrategy.USERMOD else [CMD_PASSWD, "-l", username]

def _build_unlock_password_command(username: str, strategy: PasswordCommandStrategy = PasswordCommandStrategy.PASSWD) -> list[str]:
    return [CMD_USERMOD, "-U", username] if strategy == PasswordCommandStrategy.USERMOD else [CMD_PASSWD, "-u", username]

def _build_expire_password_command(username: str) -> list[str]:
    return [CMD_CHAGE, "-d", EXPIRE_IMMEDIATELY_VALUE, username]

def _build_clear_expiration_command(username: str) -> list[str]:
    return [CMD_CHAGE, "-d", "-1", username]

def _build_query_expiration_command(username: str) -> list[str]:
    return [CMD_CHAGE, "-l", username]

def _build_passwd_status_command(username: str) -> list[str]:
    return [CMD_PASSWD, "-S", username]

def _build_aging_command(
    username: str,
    *,
    minimum_days: int | None = None,
    maximum_days: int | None = None,
    warning_days: int | None = None,
    inactive_days: int | None = None,
) -> list[str]:
    command = [CMD_CHAGE]
    if minimum_days is not None:
        command.extend(["-m", str(minimum_days)])
    if maximum_days is not None:
        command.extend(["-M", str(maximum_days)])
    if warning_days is not None:
        command.extend(["-W", str(warning_days)])
    if inactive_days is not None:
        command.extend(["-I", str(inactive_days)])
    command.append(username)
    return command


def _build_user_exists_command(username: str) -> list[str]:
    return [CMD_GETENT, "passwd", username]

class LinuxPasswordManager:
    def __init__(self, executor: CommandExecutor | None = None, *, dry_run: bool = False) -> None:
        self.executor = executor or CommandExecutor(ExecutorConfig(dry_run=dry_run))
        self.dry_run = dry_run

    def change_password(
        self,
        username: str,
        password: str | None,
        *,
        force_change: bool = False,
        dry_run: bool | None = None,
        validate_user: bool = True,
        allow_admin: bool = False,
    ) -> SystemResult:
        username = _normalize_username(username)
        force_change = _coerce_bool(
            force_change,
            field_name="force_change",
            default=False,
        )
        allow_admin = _coerce_bool(
            allow_admin,
            field_name="allow_admin",
            default=False,
        )
        self.ensure_not_admin_password_target(
            username,
            operation=ACTION_CHANGE_PASSWORD,
            allow_admin=allow_admin,
        )
        effective_dry_run = self._effective_dry_run(dry_run)
        if validate_user:
            self.ensure_user_exists(username)
        if not effective_dry_run:
            _validate_password_strength(username, password)
        self.ensure_operation_does_not_expose_secrets(_build_change_password_command())
        stdin_data = "" if effective_dry_run else f"{username}:{password}\n"
        result = self.executor.execute_with_stdin(
            _build_change_password_command(),
            stdin_data=stdin_data,
            stdin_sensitive=True,
            action=ACTION_CHANGE_PASSWORD,
            target=username,
            dry_run=effective_dry_run,
            metadata=self._metadata(
                action=ACTION_CHANGE_PASSWORD,
                username=username,
                secret_used=not effective_dry_run,
                allow_admin=allow_admin,
            ),        )
        self._raise_if_failed(result, PasswordChangeError, "Unable to change password.")
        result = self._with_password_result_details(result, ACTION_CHANGE_PASSWORD, username, ["password_hash_updated"])
        if force_change and result.is_effectively_ok:
            forced = self.force_password_change(
                username,
                dry_run=effective_dry_run,
                validate_user=False,
                allow_admin=allow_admin,
            )
            return self._combine_results(result, forced, ACTION_CHANGE_PASSWORD, username)
        return result

    def apply_password(self, spec: PasswordApplySpec) -> SystemResult:
        return self.change_password(
            spec.username,
            spec.password,
            force_change=spec.force_change,
            dry_run=spec.dry_run,
            allow_admin=False,
        )
    
    def apply_generated_password(
        self,
        username: str,
        generated_password: str | None = None,
        *,
        force_change: bool = False,
        dry_run: bool | None = None,
        allow_admin: bool = False,
    ) -> SystemResult:
        username = _normalize_username(username)
        force_change = _coerce_bool(
            force_change,
            field_name="force_change",
            default=False,
        )
        effective_dry_run = self._effective_dry_run(dry_run)
        if not effective_dry_run and not generated_password:
            raise WeakPasswordError("Generated password is required outside dry-run.", details={"username": username, "password": REDACTED_SECRET})
        result = self.change_password(
            username,
            generated_password,
            force_change=force_change,
            dry_run=effective_dry_run,
            allow_admin=allow_admin,
        )
        result.action = ACTION_APPLY_GENERATED_PASSWORD
        result.details.update({"generated_password_applied": True, "secret": REDACTED_SECRET})
        return result
    
    def force_password_change(
        self,
        username: str,
        *,
        dry_run: bool | None = None,
        validate_user: bool = True,
        allow_admin: bool = False,
    ) -> SystemResult:
        return self.expire_password(
            username,
            action=ACTION_FORCE_PASSWORD_CHANGE,
            dry_run=dry_run,
            validate_user=validate_user,
            allow_admin=allow_admin,
        )
    
    def expire_password(
        self,
        username: str,
        *,
        action: str = ACTION_EXPIRE_PASSWORD,
        dry_run: bool | None = None,
        validate_user: bool = True,
        allow_admin: bool = False) -> SystemResult:
        username = _normalize_username(username)
        allow_admin = _coerce_bool(allow_admin, field_name="allow_admin", default=False)
        self.ensure_not_admin_password_target(username, operation=action, allow_admin=allow_admin)
        effective_dry_run = self._effective_dry_run(dry_run)
        self._ensure_real_mutation_allowed(dry_run=effective_dry_run)
        if validate_user:
            self.ensure_user_exists(username)
        command = _build_expire_password_command(username)
        result = self.executor.execute(
            command,
            action=action,
            target=username,
            dry_run=effective_dry_run,
            metadata=self._metadata(action=action, username=username, allow_admin=allow_admin))
        self._raise_if_failed(result, ForcePasswordChangeError, "Unable to expire password.")
        return self._with_password_result_details(result, action, username, ["password_expired", "change_required_next_login"])
    
    def clear_password_expiration(
        self,
        username: str,
        *,
        dry_run: bool | None = None,
        validate_user: bool = True,
        allow_admin: bool = False,
    ) -> SystemResult:
        username = _normalize_username(username)
        allow_admin = _coerce_bool(allow_admin, field_name="allow_admin", default=False)
        self.ensure_not_admin_password_target(username, operation=ACTION_CLEAR_PASSWORD_EXPIRATION, allow_admin=allow_admin)
        effective_dry_run = self._effective_dry_run(dry_run)
        self._ensure_real_mutation_allowed(dry_run=effective_dry_run)
        if validate_user:
            self.ensure_user_exists(username)
        command = _build_clear_expiration_command(username)
        result = self.executor.execute(
            command, 
            action=ACTION_CLEAR_PASSWORD_EXPIRATION, 
            target=username, 
            dry_run=self._effective_dry_run(dry_run), 
            metadata=self._metadata(action=ACTION_CLEAR_PASSWORD_EXPIRATION, username=username))
        self._raise_if_failed(result, ForcePasswordChangeError, "Unable to clear password expiration.")
        return self._with_password_result_details(result, ACTION_CLEAR_PASSWORD_EXPIRATION, username, ["password_expiration_reset"])
    
    def requires_password_change(self, username: str) -> bool:
        return self.get_password_status(username).requires_change
    
    def lock_password(
        self,
        username: str,
        *,
        dry_run: bool | None = None,
        validate_user: bool = True,
        allow_admin: bool = False,
    ) -> SystemResult:
        username = _normalize_username(username)
        allow_admin = _coerce_bool(allow_admin, field_name="allow_admin", default=False)
        self.ensure_not_admin_password_target(username, operation=ACTION_LOCK_PASSWORD, allow_admin=allow_admin)
        effective_dry_run = self._effective_dry_run(dry_run)
        self._ensure_real_mutation_allowed(dry_run=effective_dry_run)
        if validate_user:
            self.ensure_user_exists(username)
        command = _build_lock_password_command(username)
        result = self.executor.execute(
            command,
            action=ACTION_LOCK_PASSWORD,
            target=username,
            dry_run=effective_dry_run,
            metadata=self._metadata(action=ACTION_LOCK_PASSWORD, username=username, allow_admin=allow_admin)
        )
        self._raise_if_failed(result, PasswordChangeError, "Unable to lock password.")
        return self._with_password_result_details(result, ACTION_LOCK_PASSWORD, username, ["password_authentication_locked"])
    
    def unlock_password(
        self,
        username: str,
        *,
        dry_run: bool | None = None,
        validate_user: bool = True,
        allow_admin: bool = False,
    ) -> SystemResult:
        username = _normalize_username(username)
        allow_admin = _coerce_bool(allow_admin, field_name="allow_admin", default=False)
        self.ensure_not_admin_password_target(username, operation=ACTION_UNLOCK_PASSWORD, allow_admin=allow_admin)
        effective_dry_run = self._effective_dry_run(dry_run)
        self._ensure_real_mutation_allowed(dry_run=effective_dry_run)
        if validate_user:
            self.ensure_user_exists(username)
        command = _build_unlock_password_command(username)
        result = self.executor.execute(
            command,
            action=ACTION_UNLOCK_PASSWORD,
            target=username,
            dry_run=effective_dry_run,
            metadata=self._metadata(action=ACTION_UNLOCK_PASSWORD, username=username, allow_admin=allow_admin)
        )
        self._raise_if_failed(result, PasswordChangeError, "Unable to unlock password.")
        return self._with_password_result_details(
            result, 
            ACTION_UNLOCK_PASSWORD, 
            username, 
            ["password_authentication_unlocked"]
        )
    
    def is_password_locked(self, username: str) -> bool:
        return self.get_password_status(username).locked
    
    def get_password_status(self, username: str) -> PasswordStatusInfo:
        username = _normalize_username(username)
        self.ensure_user_exists(username)
        status_result = self.executor.execute(
            _build_passwd_status_command(username), 
            action=ACTION_QUERY_PASSWORD_STATUS, 
            target=username, 
            dry_run=False
        )
        self._raise_if_failed(status_result, CommandExecutionError, "Unable to query password status.")
        info = self.get_password_policy(username)
        technical_state = _normalize_password_state(status_result.execution.stdout if status_result.execution else "")
        info.locked = technical_state == STATUS_LOCKED
        if info.locked:
            info.status = STATUS_LOCKED
        elif info.expired:
            info.status = STATUS_EXPIRED
        elif technical_state != STATUS_UNKNOWN:
            info.status = technical_state
        return info
    
    def get_password_policy(self, username: str) -> PasswordStatusInfo:
        username = _normalize_username(username)
        self.ensure_user_exists(username)
        result = self.executor.execute(
            _build_query_expiration_command(username),
            action=ACTION_QUERY_PASSWORD_STATUS,
            target=username,
            dry_run=False,
            env={"LC_ALL": "C"},
        )
        self._raise_if_failed(result, CommandExecutionError, "Unable to query password aging information.")
        try:
            return _parse_chage_output(username, result.execution.stdout if result.execution else "")
        except Exception as exc:
            raise CommandExecutionError(
                "Unexpected chage output.", 
                details=_sanitize_details({"username": username, "stdout": result.execution.stdout if result.execution else ""}), 
                cause=exc
            ) from exc
        
    def get_last_password_change(self, username: str) -> str | None:
        return self.get_password_policy(username).last_changed
    
    def get_max_password_days(self, username: str) -> int | None:
        return self.get_password_policy(username).maximum_days
    
    def get_min_password_days(self, username: str) -> int | None:
        return self.get_password_policy(username).minimum_days
    
    def get_password_warning_days(self, username: str) -> int | None:
        return self.get_password_policy(username).warning_days
    
    def get_password_inactive_days(self, username: str) -> int | None:
        return self.get_password_policy(username).inactive_days
    
    def build_password_policy_model(self, username: str) -> PasswordPolicy:
        info = self.get_password_policy(username)
        return PasswordPolicy(
            min_password_age_days=info.minimum_days,
            max_password_age_days=info.maximum_days,
            warning_days=info.warning_days,
            last_changed_at=info.last_changed,
            force_password_change=info.requires_change,
            password_expired=info.expired,
            status=PolicyStatus.ACTIVE,
            target=username,
            origin=PolicyOrigin.SYSTEM,
        )
    
    def set_password_max_days(
        self,
        username: str,
        days: int | None,
        *,
        dry_run: bool | None = None,
        allow_admin: bool = False,
    ) -> SystemResult:
        return self.set_password_policy(
            username,
            maximum_days=_normalize_password_policy_field(days, field_name="maximum_days"),
            dry_run=dry_run,
            action=ACTION_SET_PASSWORD_MAX_DAYS,
            allow_admin=allow_admin,
        )
    
    def set_password_min_days(
            self,
            username: str,
            days: int | None,
            *,
            dry_run: bool | None = None,
            allow_admin: bool = False) -> SystemResult:
        return self.set_password_policy(
            username,
            minimum_days=_normalize_password_policy_field(days, field_name="minimum_days"),
            dry_run=dry_run,
            action=ACTION_SET_PASSWORD_MIN_DAYS,
            allow_admin=allow_admin,
        )

    def set_password_warning_days(
            self,
            username: str,
            days: int | None,
            *,
            dry_run: bool | None = None,
            allow_admin: bool = False,
        ) -> SystemResult:
        return self.set_password_policy(
            username,
            warning_days=_normalize_password_policy_field(days, field_name="warning_days"),
            dry_run=dry_run,
            action=ACTION_SET_PASSWORD_WARNING_DAYS,
            allow_admin=allow_admin,
        )
    
    def set_password_inactive_days(
        self,
        username: str,
        days: int | None,
        *,
        dry_run: bool | None = None,
        allow_admin: bool = False,
    ) -> SystemResult:
        return self.set_password_policy(
            username,
            inactive_days=_normalize_password_policy_field(days, field_name="inactive_days"),
            dry_run=dry_run,
            action=ACTION_SET_PASSWORD_INACTIVE_DAYS,
            allow_admin=allow_admin,
        )
    
    def set_password_policy(
        self,
        username: str,
        policy: PasswordPolicy | Mapping[str, Any] | None = None,
        *,
        minimum_days: int | None = None,
        maximum_days: int | None = None,
        warning_days: int | None = None,
        inactive_days: int | None = None,
        dry_run: bool | None = None,
        action: str = ACTION_SET_PASSWORD_POLICY,
        allow_admin: bool = False,
    ) -> SystemResult:
        username = _normalize_username(username)
        allow_admin = _coerce_bool(allow_admin, field_name="allow_admin", default=False)
        self.ensure_not_admin_password_target(username, operation=action, allow_admin=allow_admin)
        effective_dry_run = self._effective_dry_run(dry_run)
        self._ensure_real_mutation_allowed(dry_run=effective_dry_run)
        self.ensure_user_exists(username)
        values = self._policy_values(
            policy, 
            minimum_days=minimum_days, 
            maximum_days=maximum_days, 
            warning_days=warning_days, 
            inactive_days=inactive_days
        )
        if all(value is None for value in values.values()):
            return self._skipped_result(
                action,
                username,
                "No password policy changes requested.",
                dry_run=effective_dry_run,
            )
        self.validate_policy_values(**values)
        command = _build_aging_command(username, **values)
        result = self.executor.execute(
            command, 
            action=action, 
            target=username, 
            dry_run=effective_dry_run,
            metadata=self._metadata(
                action=action, 
                username=username, 
                policy=values
            )
        )
        self._raise_if_failed(result, PolicyError, "Unable to apply password policy.")
        return self._with_password_result_details(result, action, username, ["password_aging_policy_updated"])
    
    def check_required_commands(self, *, raise_on_missing: bool = True) -> dict[str, bool]:
        results: dict[str, bool] = {}
        for binary in REQUIRED_COMMANDS:
            result = self.executor.check_dependency(binary, raise_on_missing=False)
            results[binary] = result.ok
            if raise_on_missing and not result.ok:
                raise ResourceNotFoundError("Required password command is unavailable.", details={"binary": binary})
        return results


    def ensure_user_exists(self, username: str) -> None:
        username = _normalize_username(username)
        result = self.executor.execute(
            _build_user_exists_command(username), 
            action="validate_user_exists", 
            target=username, 
            dry_run=False
        )
        if not result.ok:
            raise UserNotFoundError("User does not exist.", details={"username": username})
        
    def check_permissions(self) -> bool:
        if getuser() == "root":
            return True
        raise InsufficientPermissionsError("Password operations usually require root privileges.")

    def ensure_not_admin_password_target(
        self,
        username: str,
        *,
        operation: str,
        allow_admin: bool = False,
    ) -> None:
        username = _normalize_username(username)
        allow_admin = _coerce_bool(
            allow_admin,
            field_name="allow_admin",
            default=False,
        )

        if username in ADMIN_USER_NAMES and not allow_admin:
            raise PasswordChangeError(
                "Operation is blocked for administrative account.",
                details={
                    "username": username,
                    "operation": operation,
                    "allow_admin_required": True,
                },
            )

    def _ensure_real_mutation_allowed(self, *, dry_run: bool) -> None:
        if not dry_run:
            self.check_permissions()

    
    def verify_mechanism_compatibility(self) -> dict[str, bool]:
        return self.check_required_commands(raise_on_missing=False)
    
    def validate_policy_values(
        self,
        *,
        minimum_days: int | None = None,
        maximum_days: int | None = None,
        warning_days: int | None = None,
        inactive_days: int | None = None,
    ) -> None:
        for field_name, value in {
            "minimum_days": minimum_days,
            "maximum_days": maximum_days,
            "warning_days": warning_days,
            "inactive_days": inactive_days,
        }.items():
            _normalize_password_policy_field(value, field_name=field_name)
        if minimum_days is not None and maximum_days is not None and maximum_days != -1 and minimum_days > maximum_days:
            raise PolicyError("minimum_days cannot be greater than maximum_days.", details={"minimum_days": minimum_days, "maximum_days": maximum_days})

        
    def ensure_operation_does_not_expose_secrets(self, command: Sequence[str]) -> None:
        lowered_command = [str(part).lower() for part in command]
        if any(part in {"-p", "--password", "--secret"} for part in lowered_command):
            raise PasswordChangeError("Unsafe password command strategy rejected.", details={"command": _sanitize_command(command)})

    def _raise_if_failed(
        self, 
        result: SystemResult, 
        error_cls: type[Exception], 
        message: str
    ) -> None:
        if result.ok:
            return
        result.details = _sanitize_details(result.details)
        details = _sanitize_details(result.details)
        if result.execution:
            result.execution.command = _sanitize_command(result.execution.command or [])
            result.execution.stdout = _sanitize_text(result.execution.stdout)
            result.execution.stderr = _sanitize_text(result.execution.stderr)
            details.update({
                "command": _sanitize_command(result.execution.command or []),
                "return_code": result.execution.return_code,
                "stdout": _sanitize_text(result.execution.stdout),
                "stderr": _sanitize_text(result.execution.stderr),
            })
        stderr = str(details.get("stderr", "")).lower()
        if "permission" in stderr or "denied" in stderr:
            raise InsufficientPermissionsError("Insufficient permissions for password operation.", details=details)
        if "does not exist" in stderr or "unknown user" in stderr or "not found" in stderr:
            raise UserNotFoundError("User was not found during password operation.", details=details)
        if error_cls is CommandExecutionError:
            raise CommandExecutionError(message, details=details)
        raise error_cls(message, details=details)  
    
    def _with_password_result_details(self, result: SystemResult, action: str, username: str, changes: list[str]) -> SystemResult:
        result.action = action
        result.target = username
        result.details = _sanitize_details({
            **result.details,
            "action": action,
            "target_user": username,
            "allow_admin": username in ADMIN_USER_NAMES,
            "changes_applied": changes if result.changed else [],
            "projected_changes": changes if result.dry_run else [],
            "secret": REDACTED_SECRET,
            "secret_redacted": True,
            "technical_layer": "system/linux_passwords.py",
        })
        if result.execution:
            result.execution.command = _sanitize_command(result.execution.command or [])
            result.execution.stdout = _sanitize_text(result.execution.stdout)
            result.execution.stderr = _sanitize_text(result.execution.stderr)
        if username in ADMIN_USER_NAMES and "High-impact password operation on an administrative user." not in result.warnings:
            result.warnings.append("High-impact password operation on an administrative user.")
            result.impact.level = ImpactLevel.HIGH if result.impact.level != ImpactLevel.CRITICAL else result.impact.level
        return result
    
    def _skipped_result(
        self,
        action: str,
        username: str,
        message: str,
        *,
        dry_run: bool,
    ) -> SystemResult:
        return SystemResult(
            ok=True,
            status=ResultStatus.SKIPPED,
            action=action,
            target=username,
            message=message,
            changed=False,
            dry_run=dry_run,
            details={
                "action": action,
                "target_user": username,
                "changes_applied": [],
                "projected_changes": [],
            },
            impact=ImpactMetadata(level=ImpactLevel.NONE),
        )

    def _combine_results(
        self, 
        first: SystemResult, 
        second: SystemResult, 
        action: str, 
        username: str
    ) -> SystemResult:
        details = _sanitize_details({
            "primary": first.to_dict(),
            "secondary": second.to_dict(),
            "secret": REDACTED_SECRET,
            "changes_applied": ["password_hash_updated", "change_required_next_login"] if not first.dry_run else [],
            "projected_changes": ["password_hash_updated", "change_required_next_login"] if first.dry_run else [],
        })
        return SystemResult(
            ok=first.is_effectively_ok and second.is_effectively_ok,
            status=ResultStatus.DRY_RUN if first.dry_run or second.dry_run else ResultStatus.SUCCESS,
            action=action,
            target=username,
            message="Password operation completed with forced change." if not first.dry_run else "Password operation simulated with forced change.",
            details=details,
            warnings=list(dict.fromkeys([*first.warnings, *second.warnings])),
            dry_run=first.dry_run or second.dry_run,
            changed=first.changed or second.changed,
            execution=first.execution,
            impact=ImpactMetadata(level=max((first.impact.level, second.impact.level), key=lambda level: list(ImpactLevel).index(level))),
            simulation=first.simulation or second.simulation,
        )

    def _policy_values(self, policy: PasswordPolicy | Mapping[str, Any] | None, **overrides: int | None) -> dict[str, int | None]:
        values = {
            "minimum_days": overrides.get("minimum_days"),
            "maximum_days": overrides.get("maximum_days"),
            "warning_days": overrides.get("warning_days"),
            "inactive_days": overrides.get("inactive_days"),
        }
        if policy is None:
            return values
        if isinstance(policy, PasswordPolicy):
            policy_values = {
                "minimum_days": policy.min_password_age_days,
                "maximum_days": policy.max_password_age_days,
                "warning_days": policy.warning_days,
                "inactive_days": None,
            }
        else:
            policy_values = {
                "minimum_days": policy.get("minimum_days", policy.get("min_password_age_days")),
                "maximum_days": policy.get("maximum_days", policy.get("max_password_age_days")),
                "warning_days": policy.get("warning_days"),
                "inactive_days": policy.get("inactive_days"),
            }
        for key, value in policy_values.items():
            if values[key] is None:
                values[key] = value
        return {
            key: _normalize_password_policy_field(value, field_name=key)
            for key, value in values.items()
        }
    def _metadata(
        self,
        *,
        action: str,
        username: str,
        secret_used: bool = False,
        policy: Mapping[str, Any] | None = None,
        allow_admin: bool = False,
    ) -> dict[str, Any]:
        warnings: list[str] = []
        impact = "medium"
        if username in ADMIN_USER_NAMES:
            impact = "high"
            warnings.append("Operation targets an administrative account.")
        metadata = {            "action": action,
            "username": username,
            "secret_used": secret_used,
            "secret": REDACTED_SECRET if secret_used else None,
            "policy": dict(policy or {}),
            "impact": impact,
            "warnings": warnings,
            "reads_shadow_directly": False,
            "writes_shadow_directly": False,
        }
        if allow_admin:
            metadata["allow_admin"] = True
        return _sanitize_details(metadata)


    def _effective_dry_run(self, dry_run: bool | None) -> bool:
        return _coerce_bool(
            dry_run,
            field_name="dry_run",
            default=self.dry_run,
        )   

__all__ = [
    "ACTION_CHANGE_PASSWORD",
    "ACTION_APPLY_GENERATED_PASSWORD",
    "ACTION_EXPIRE_PASSWORD",
    "ACTION_FORCE_PASSWORD_CHANGE",
    "ACTION_LOCK_PASSWORD",
    "ACTION_UNLOCK_PASSWORD",
    "ACTION_QUERY_PASSWORD_STATUS",
    "ACTION_SET_PASSWORD_POLICY",
    "LinuxPasswordManager",
    "PasswordApplySpec",
    "PasswordCommandStrategy",
    "PasswordStatusInfo",
    "REDACTED_SECRET",
    "REQUIRED_COMMANDS",
]