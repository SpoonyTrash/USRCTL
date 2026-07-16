import os
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .executor import CommandExecutor, ExecutorConfig
from ..config import PasswordStrengthConfig
from .result import ExecutionMetadata, ImpactLevel, ImpactMetadata, ResultStatus, SystemResult
from ..models.policy import PasswordPolicy, PolicyOrigin, PolicyStatus
from ..utils.errors import (
    AdministrativeAccountProtectionError,
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
from ..utils.validators import validate_username
from .password_security import (
    _normalize_password_strategy,
    _validate_password_strength,
    _validate_password_strength_config,
    _validate_password_transport,
)
from .password_parsers import (
    _normalize_password_state,
    _normalize_policy_days,
    _parse_chage_output,
)
from .password_commands import (
    _build_aging_command,
    _build_change_password_command,
    _build_chpasswd_input,
    _build_clear_expiration_command,
    _build_expire_password_command,
    _build_lock_password_command,
    _build_passwd_status_command,
    _build_query_expiration_command,
    _build_unlock_password_command,
    _build_user_exists_command,
)
from .password_sanitizer import (
    _sanitize_command,
    _sanitize_details,
    _sanitize_text,
    _split_sensitive_option,
)

from .password_constants import (
    ACTION_APPLY_GENERATED_PASSWORD,
    ACTION_CHANGE_PASSWORD,
    ACTION_CLEAR_PASSWORD_EXPIRATION,
    ACTION_EXPIRE_PASSWORD,
    ACTION_FORCE_PASSWORD_CHANGE,
    ACTION_LOCK_PASSWORD,
    ACTION_QUERY_PASSWORD_STATUS,
    ACTION_QUERY_USER_IDENTITY,
    ACTION_SET_PASSWORD_INACTIVE_DAYS,
    ACTION_SET_PASSWORD_MAX_DAYS,
    ACTION_SET_PASSWORD_MIN_DAYS,
    ACTION_SET_PASSWORD_POLICY,
    ACTION_SET_PASSWORD_WARNING_DAYS,
    ACTION_UNLOCK_PASSWORD,
    CMD_CHAGE,
    CMD_GETENT,
    REDACTED_SECRET,
    REQUIRED_COMMANDS,
    SENSITIVE_COMMAND_OPTIONS,
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_LOCKED,
    STATUS_NO_PASSWORD,
    STATUS_UNKNOWN,
)
from .password_types import (
    PasswordCommandStrategy,
    PasswordStatusInfo,
    UserIdentity,
)



@dataclass(slots=True)
class PasswordApplySpec:
    username: str
    password: str | None = field(
        default=None,
        repr=False,
    )
    force_change: bool = False
    generated: bool = False
    dry_run: bool | None = None
    allow_admin: bool = False

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
        self.allow_admin = _coerce_bool(
            self.allow_admin,
            field_name="allow_admin",
            default=False,
        )

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "password": REDACTED_SECRET if self.password else None,
            "force_change": self.force_change,
            "generated": self.generated,
            "dry_run": self.dry_run,
            "allow_admin": self.allow_admin,
        }


def _normalize_username(username: str) -> str:
    text = str(username).strip()
    if not text:
        raise ValidationError(
            "Username cannot be empty.", details={"field": "username"}
        )
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


def _normalize_password_policy_field(value: Any, *, field_name: str) -> int | None:
    allow_never = field_name in {"maximum_days", "inactive_days"}
    return _normalize_policy_days(
        value,
        field_name=field_name,
        allow_never=allow_never,
    )



def _stderr_reports_missing_user(
    stderr: str,
) -> bool:
    normalized = stderr.strip().lower()

    exact_prefixes = (
        "unknown user",
        "user not found",
    )

    if normalized.startswith(exact_prefixes):
        return True

    if (
        normalized.startswith("user ")
        and normalized.endswith(" does not exist")
    ):
        middle = normalized[
            len("user "):-len(" does not exist")
        ].strip(" '\"")
        return bool(middle) and " " not in middle

    if ": user " in normalized:
        return _stderr_reports_missing_user(
            f"user {normalized.split(': user ', 1)[1]}"
        )

    return (
        "does not exist in /etc/passwd" in normalized
        or "does not exist in the passwd database" in normalized
    )


class LinuxPasswordManager:
    def __init__(
        self,
        executor: CommandExecutor | None = None,
        *,
        dry_run: bool = False,
        password_strength: PasswordStrengthConfig | None = None,
    ) -> None:
        self.executor = executor or CommandExecutor(ExecutorConfig(dry_run=dry_run))
        self.dry_run = dry_run
        resolved_password_strength = (
            password_strength
            if password_strength is not None
            else PasswordStrengthConfig()
        )
        self.password_strength = _validate_password_strength_config(
            resolved_password_strength
        )

    def change_password(
        self,
        username: str,
        password: str | None,
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
        allow_admin = _coerce_bool(
            allow_admin,
            field_name="allow_admin",
            default=False,
        )
        sensitive_values = (password,) if password else ()
        effective_dry_run = self._effective_dry_run(dry_run)
        self._ensure_real_mutation_allowed(dry_run=effective_dry_run)
        administrative_target = self.ensure_not_admin_password_target(
            username,
            operation=ACTION_CHANGE_PASSWORD,
            allow_admin=allow_admin,
        )
        if password is None:
            if not effective_dry_run:
                raise WeakPasswordError(
                    "Password value is required.",
                    details={
                        "username": username,
                        "password": REDACTED_SECRET,
                    },
                )
        else:
            _validate_password_transport(password)
            _validate_password_strength(
                username,
                password,
                self.password_strength,
            )
        self.ensure_operation_does_not_expose_secrets(_build_change_password_command())
        if effective_dry_run:
            stdin_data = ""
        else:
            if password is None:
                raise WeakPasswordError(
                    "Password value is required.",
                    details={
                        "username": username,
                        "password": REDACTED_SECRET,
                    },
                )

            stdin_data = _build_chpasswd_input(
                username,
                password,
            )
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
                administrative_target=administrative_target,
            ),
        )
        self._raise_if_failed(
            result,
            PasswordChangeError,
            "Unable to change password.",
            sensitive_values=sensitive_values,
        )
        result = self._with_password_result_details(
            result,
            ACTION_CHANGE_PASSWORD,
            username,
            ["password_hash_updated"],
            allow_admin=allow_admin,
            administrative_target=administrative_target,
            sensitive_values=sensitive_values,
        )
        if force_change and result.is_effectively_ok:
            try:
                forced = self.force_password_change(
                    username,
                    dry_run=effective_dry_run,
                    allow_admin=allow_admin,
                )
            except (
                AdministrativeAccountProtectionError,
                ForcePasswordChangeError,
                InsufficientPermissionsError,
                CommandExecutionError,
                ResourceNotFoundError,
                UserNotFoundError,
            ) as exc:
                raise PasswordChangeError(
                    "Password changed, but forcing a change at next login failed.",
                    details=_sanitize_details(
                        {
                            "username": username,
                            "partial_success": True,
                            "password_changed": True,
                            "force_change_applied": False,
                            "manual_intervention_required": True,
                            "recommended_action": (
                                f"Run chage -d 0 {username} "
                                "after resolving the reported error."
                            ),
                            "primary_result": result.to_dict(),
                            "secondary_error_type": type(exc).__name__,
                            "secondary_error": getattr(exc, "details", {}),
                        },
                        sensitive_values=sensitive_values,
                    ),
                    cause=exc,
                ) from exc

            return self._combine_results(
                result, forced, ACTION_CHANGE_PASSWORD, username
            )
        return result

    def apply_password(self, spec: PasswordApplySpec) -> SystemResult:
        if spec.generated:
            return self.apply_generated_password(
                spec.username,
                spec.password,
                force_change=spec.force_change,
                dry_run=spec.dry_run,
                allow_admin=spec.allow_admin,
            )

        return self.change_password(
            spec.username,
            spec.password,
            force_change=spec.force_change,
            dry_run=spec.dry_run,
            allow_admin=spec.allow_admin,
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
            raise WeakPasswordError(
                "Generated password is required outside dry-run.",
                details={"username": username, "password": REDACTED_SECRET},
            )
        sensitive_values = (generated_password,) if generated_password else ()
        result = self.change_password(
            username,
            generated_password,
            force_change=force_change,
            dry_run=effective_dry_run,
            allow_admin=allow_admin,
        )

        result.action = ACTION_APPLY_GENERATED_PASSWORD
        result.message = (
            "Generated password application simulated."
            if result.dry_run
            else "Generated password applied."
        )

        result.details = _sanitize_details(
            {
                **result.details,
                "action": ACTION_APPLY_GENERATED_PASSWORD,
                "target_user": username,
                "generated_password_applied": (
                    result.changed
                    and not result.dry_run
                ),
                "generated_password_projected": (
                    result.dry_run
                    and result.is_effectively_ok
                ),
                "secret": REDACTED_SECRET,
                "secret_redacted": True,
            },
            sensitive_values=sensitive_values,
        )

        if result.execution:
            result.execution.command = _sanitize_command(result.execution.command or [])
            result.execution.stdout = _sanitize_text(
                result.execution.stdout,
                sensitive_values=sensitive_values,
            )
            result.execution.stderr = _sanitize_text(
                result.execution.stderr,
                sensitive_values=sensitive_values,
            )

        return result

    def force_password_change(
        self,
        username: str,
        *,
        dry_run: bool | None = None,
        allow_admin: bool = False,
    ) -> SystemResult:
        return self.expire_password(
            username,
            action=ACTION_FORCE_PASSWORD_CHANGE,
            dry_run=dry_run,
            allow_admin=allow_admin,
        )

    def expire_password(
        self,
        username: str,
        *,
        action: str = ACTION_EXPIRE_PASSWORD,
        dry_run: bool | None = None,
        allow_admin: bool = False,
    ) -> SystemResult:
        username = _normalize_username(username)
        allow_admin = _coerce_bool(allow_admin, field_name="allow_admin", default=False)
        effective_dry_run = self._effective_dry_run(dry_run)
        self._ensure_real_mutation_allowed(dry_run=effective_dry_run)
        administrative_target = self.ensure_not_admin_password_target(
            username,
            operation=action,
            allow_admin=allow_admin,
        )
        command = _build_expire_password_command(username)
        result = self.executor.execute(
            command,
            action=action,
            target=username,
            dry_run=effective_dry_run,
            metadata=self._metadata(
                action=action,
                username=username,
                allow_admin=allow_admin,
                administrative_target=administrative_target,
            ),
        )
        self._raise_if_failed(
            result, ForcePasswordChangeError, "Unable to expire password."
        )
        return self._with_password_result_details(
            result,
            action,
            username,
            ["password_expired", "change_required_next_login"],
            allow_admin=allow_admin,
            administrative_target=administrative_target,
        )

    def clear_password_expiration(
        self,
        username: str,
        *,
        dry_run: bool | None = None,
        allow_admin: bool = False,
    ) -> SystemResult:
        username = _normalize_username(username)
        allow_admin = _coerce_bool(allow_admin, field_name="allow_admin", default=False)
        effective_dry_run = self._effective_dry_run(dry_run)
        self._ensure_real_mutation_allowed(dry_run=effective_dry_run)
        administrative_target = self.ensure_not_admin_password_target(
            username,
            operation=ACTION_CLEAR_PASSWORD_EXPIRATION,
            allow_admin=allow_admin,
        )
        command = _build_clear_expiration_command(username)
        result = self.executor.execute(
            command,
            action=ACTION_CLEAR_PASSWORD_EXPIRATION,
            target=username,
            dry_run=effective_dry_run,
            metadata=self._metadata(
                action=ACTION_CLEAR_PASSWORD_EXPIRATION,
                username=username,
                allow_admin=allow_admin,
                administrative_target=administrative_target,
            ),
        )
        self._raise_if_failed(
            result, ForcePasswordChangeError, "Unable to clear password expiration."
        )
        return self._with_password_result_details(
            result,
            ACTION_CLEAR_PASSWORD_EXPIRATION,
            username,
            ["password_expiration_reset"],
            allow_admin=allow_admin,
            administrative_target=administrative_target,
        )

    def requires_password_change(self, username: str) -> bool:
        return self.get_password_status(username).requires_change

    def lock_password_authentication(
        self,
        username: str,
        *,
        dry_run: bool | None = None,
        allow_admin: bool = False,
        strategy: PasswordCommandStrategy | str = PasswordCommandStrategy.PASSWD,
    ) -> SystemResult:
        username = _normalize_username(username)
        allow_admin = _coerce_bool(allow_admin, field_name="allow_admin", default=False)
        strategy = _normalize_password_strategy(strategy)
        effective_dry_run = self._effective_dry_run(dry_run)
        self._ensure_real_mutation_allowed(dry_run=effective_dry_run)
        administrative_target = self.ensure_not_admin_password_target(
            username,
            operation=ACTION_LOCK_PASSWORD,
            allow_admin=allow_admin,
        )
        command = _build_lock_password_command(username, strategy)
        result = self.executor.execute(
            command,
            action=ACTION_LOCK_PASSWORD,
            target=username,
            dry_run=effective_dry_run,
            metadata=self._metadata(
                action=ACTION_LOCK_PASSWORD,
                username=username,
                allow_admin=allow_admin,
                administrative_target=administrative_target,
            ),
        )
        self._raise_if_failed(result, PasswordChangeError, "Unable to lock password.")
        return self._with_password_result_details(
            result,
            ACTION_LOCK_PASSWORD,
            username,
            ["password_authentication_locked"],
            allow_admin=allow_admin,
            administrative_target=administrative_target,
        )

    def unlock_password_authentication(
        self,
        username: str,
        *,
        dry_run: bool | None = None,
        allow_admin: bool = False,
        strategy: PasswordCommandStrategy | str = PasswordCommandStrategy.PASSWD,
    ) -> SystemResult:
        username = _normalize_username(username)
        allow_admin = _coerce_bool(allow_admin, field_name="allow_admin", default=False)
        strategy = _normalize_password_strategy(strategy)
        effective_dry_run = self._effective_dry_run(dry_run)
        self._ensure_real_mutation_allowed(dry_run=effective_dry_run)
        administrative_target = self.ensure_not_admin_password_target(
            username,
            operation=ACTION_UNLOCK_PASSWORD,
            allow_admin=allow_admin,
        )
        command = _build_unlock_password_command(username, strategy)
        result = self.executor.execute(
            command,
            action=ACTION_UNLOCK_PASSWORD,
            target=username,
            dry_run=effective_dry_run,
            metadata=self._metadata(
                action=ACTION_UNLOCK_PASSWORD,
                username=username,
                allow_admin=allow_admin,
                administrative_target=administrative_target,
            ),
        )
        self._raise_if_failed(result, PasswordChangeError, "Unable to unlock password.")
        return self._with_password_result_details(
            result,
            ACTION_UNLOCK_PASSWORD,
            username,
            ["password_authentication_unlocked"],
            allow_admin=allow_admin,
            administrative_target=administrative_target,
        )

    def lock_password(
        self,
        username: str,
        *,
        dry_run: bool | None = None,
        allow_admin: bool = False,
        strategy: PasswordCommandStrategy | str = PasswordCommandStrategy.PASSWD,
    ) -> SystemResult:
        result = self.lock_password_authentication(
            username,
            dry_run=dry_run,
            allow_admin=allow_admin,
            strategy=strategy,
        )
        warning = (
            "lock_password() only disables password authentication; "
            "it does not disable SSH keys or all login mechanisms."
        )

        if warning not in result.warnings:
            result.warnings.append(warning)

        return result

    def unlock_password(
        self,
        username: str,
        *,
        dry_run: bool | None = None,
        allow_admin: bool = False,
        strategy: PasswordCommandStrategy | str = PasswordCommandStrategy.PASSWD,
    ) -> SystemResult:
        result = self.unlock_password_authentication(
            username,
            dry_run=dry_run,
            allow_admin=allow_admin,
            strategy=strategy,
        )
        warning = (
            "unlock_password() only enables password authentication; "
            "it does not control SSH keys or other login mechanisms."
        )

        if warning not in result.warnings:
            result.warnings.append(warning)

        return result

    def is_password_locked(self, username: str) -> bool:
        return self.get_password_status(username).locked

    def get_password_status(self, username: str) -> PasswordStatusInfo:
        username = _normalize_username(username)
        self.ensure_user_exists(username)
        status_result = self.executor.execute(
            _build_passwd_status_command(username),
            action=ACTION_QUERY_PASSWORD_STATUS,
            target=username,
            dry_run=False,
        )
        self._raise_if_failed(
            status_result, CommandExecutionError, "Unable to query password status."
        )
        info = self._get_password_policy_for_existing_user(username)
        status_execution = self._require_execution(
            status_result,
            username=username,
            action=ACTION_QUERY_PASSWORD_STATUS,
            message=(
                "Password status command completed "
                "without execution data."
            ),
        )
        technical_state = _normalize_password_state(
            status_execution.stdout
        )
        info.locked = technical_state == STATUS_LOCKED
        if info.locked:
            info.status = STATUS_LOCKED
        elif info.expired:
            info.status = STATUS_EXPIRED
        elif technical_state == STATUS_NO_PASSWORD:
            info.status = STATUS_NO_PASSWORD
        elif technical_state == STATUS_ACTIVE:
            info.status = STATUS_ACTIVE
        else:
            info.status = STATUS_UNKNOWN
        return info

    def _get_password_policy_for_existing_user(
        self,
        username: str,
    ) -> PasswordStatusInfo:
        result = self.executor.execute(
            _build_query_expiration_command(username),
            action=ACTION_QUERY_PASSWORD_STATUS,
            target=username,
            dry_run=False,
            env={"LC_ALL": "C"},
        )
        self._raise_if_failed(
            result,
            CommandExecutionError,
            "Unable to query password aging information.",
        )
        execution = self._require_execution(
            result,
            username=username,
            action=ACTION_QUERY_PASSWORD_STATUS,
            message=(
                "Password aging command completed "
                "without execution data."
            ),
        )
        try:
            return _parse_chage_output(
                username,
                execution.stdout,
            )
        except CommandExecutionError:
            raise
        except Exception as exc:
            raise CommandExecutionError(
                "Unexpected chage output.",
                details={"username": username},
                cause=exc,
            ) from exc

    def get_password_policy(
        self,
        username: str,
    ) -> PasswordStatusInfo:
        username = _normalize_username(username)
        self.ensure_user_exists(username)

        return self._get_password_policy_for_existing_user(username)

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
            inactive_days=info.inactive_days,
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
            maximum_days=_normalize_password_policy_field(
                days, field_name="maximum_days"
            ),
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
        allow_admin: bool = False,
    ) -> SystemResult:
        return self.set_password_policy(
            username,
            minimum_days=_normalize_password_policy_field(
                days, field_name="minimum_days"
            ),
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
            warning_days=_normalize_password_policy_field(
                days, field_name="warning_days"
            ),
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
            inactive_days=_normalize_password_policy_field(
                days, field_name="inactive_days"
            ),
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
        allow_admin = _coerce_bool(
            allow_admin,
            field_name="allow_admin",
            default=False,
        )
        effective_dry_run = self._effective_dry_run(dry_run)
        self._ensure_real_mutation_allowed(dry_run=effective_dry_run)
        administrative_target = self.ensure_not_admin_password_target(
            username,
            operation=action,
            allow_admin=allow_admin,
        )

        values = self._policy_values(
            policy,
            minimum_days=minimum_days,
            maximum_days=maximum_days,
            warning_days=warning_days,
            inactive_days=inactive_days,
        )
        if all(value is None for value in values.values()):
            return self._skipped_result(
                action,
                username,
                "No password policy changes requested.",
                dry_run=effective_dry_run,
                allow_admin=allow_admin,
                administrative_target=administrative_target,
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
                policy=values,
                allow_admin=allow_admin,
                administrative_target=administrative_target,
            ),
        )
        self._raise_if_failed(result, PolicyError, "Unable to apply password policy.")
        return self._with_password_result_details(
            result,
            action,
            username,
            ["password_aging_policy_updated"],
            allow_admin=allow_admin,
            administrative_target=administrative_target,
        )

    def check_required_commands(
        self,
        *,
        raise_on_missing: bool = True,
    ) -> dict[str, bool]:
        results: dict[str, bool] = {}

        for binary in REQUIRED_COMMANDS:
            dependency_result = self.executor.check_dependency(
                binary,
                raise_on_missing=False,
            )
            results[binary] = dependency_result.ok

        missing = [binary for binary, available in results.items() if not available]

        if raise_on_missing and missing:
            raise ResourceNotFoundError(
                "Required password commands are unavailable.",
                details={
                    "missing_binaries": missing,
                    "dependency_status": results,
                },
            )

        return results

    def get_user_identity(self, username: str) -> UserIdentity:
        username = _normalize_username(username)

        result = self.executor.execute(
            _build_user_exists_command(username),
            action=ACTION_QUERY_USER_IDENTITY,
            target=username,
            dry_run=False,
            env={"LC_ALL": "C"},
        )

        self._raise_if_failed(
            result,
            CommandExecutionError,
            "Unable to query user identity.",
        )

        if result.execution is None:
            raise CommandExecutionError(
                "User identity command completed without execution data.",
                details={
                    "username": username,
                    "action": ACTION_QUERY_USER_IDENTITY,
                },
            )

        record = result.execution.stdout.strip()
        fields = record.split(":", 6)

        if len(fields) != 7:
            raise CommandExecutionError(
                "Invalid passwd database record.",
                details={
                    "username": username,
                    "field_count": len(fields),
                },
            )

        try:
            uid = int(fields[2])
        except ValueError as exc:
            raise CommandExecutionError(
                "Invalid UID in passwd database record.",
                details={
                    "username": username,
                    "uid_value": fields[2],
                },
                cause=exc,
            ) from exc

        if uid < 0:
            raise CommandExecutionError(
                "UID cannot be negative.",
                details={
                    "username": username,
                    "uid": uid,
                },
            )

        return UserIdentity(username=username, uid=uid)

    def get_user_uid(self, username: str) -> int:
        return self.get_user_identity(username).uid

    def ensure_user_exists(self, username: str) -> None:
        username = _normalize_username(username)

        result = self.executor.execute(
            _build_user_exists_command(username),
            action="ensure_user_exists",
            target=username,
            dry_run=False,
            env={"LC_ALL": "C"},
        )

        self._raise_if_failed(
            result,
            CommandExecutionError,
            "Unable to verify whether the user exists.",
        )

        if result.execution is None:
            raise CommandExecutionError(
                "User existence command completed without execution data.",
                details={
                    "username": username,
                    "action": "ensure_user_exists",
                },
            )

        if not result.execution.stdout.strip():
            raise UserNotFoundError(
                "User does not exist.",
                details={"username": username},
            )

    def check_permissions(self) -> bool:
        effective_uid = os.geteuid()

        if effective_uid == 0:
            return True

        raise InsufficientPermissionsError(
            "Password operations require root privileges.",
            details={"effective_uid": effective_uid},
        )

    def ensure_not_admin_password_target(
        self,
        username: str,
        *,
        operation: str,
        allow_admin: bool = False,
    ) -> bool:
        username = _normalize_username(username)
        allow_admin = _coerce_bool(
            allow_admin,
            field_name="allow_admin",
            default=False,
        )

        identity = self.get_user_identity(username)
        administrative_target = identity.is_administrative

        if administrative_target and not allow_admin:
            raise AdministrativeAccountProtectionError(
                "Operation is blocked for an administrative account.",
                details={
                    "username": username,
                    "uid": identity.uid,
                    "operation": operation,
                    "administrative_target": True,
                    "allow_admin_required": True,
                },
            )
        return administrative_target

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
        if (
            minimum_days is not None
            and maximum_days is not None
            and maximum_days != -1
            and minimum_days > maximum_days
        ):
            raise PolicyError(
                "minimum_days cannot be greater than maximum_days.",
                details={"minimum_days": minimum_days, "maximum_days": maximum_days},
            )

    def ensure_operation_does_not_expose_secrets(self, command: Sequence[str]) -> None:
        unsafe_options: list[str] = []

        for token in command:
            text = str(token)
            lowered = text.lower()

            if lowered in SENSITIVE_COMMAND_OPTIONS:
                unsafe_options.append(lowered)
                continue

            inline_sensitive = _split_sensitive_option(text)

            if inline_sensitive is not None:
                option, _ = inline_sensitive
                unsafe_options.append(option.lower())

        if unsafe_options:
            raise PasswordChangeError(
                "Unsafe password command strategy rejected.",
                details={
                    "command": _sanitize_command(command),
                    "unsafe_options": sorted(set(unsafe_options)),
                },
            )

    def _require_execution(
        self,
        result: SystemResult,
        *,
        username: str,
        action: str,
        message: str,
    ) -> ExecutionMetadata:
        if result.execution is None:
            raise CommandExecutionError(
                message,
                details={
                    "username": username,
                    "action": action,
                    "result_status": str(result.status),
                },
            )

        return result.execution

    def _raise_for_known_command_failure(
        self,
        *,
        command_name: str,
        return_code: int | None,
        details: dict[str, Any],
    ) -> None:
        if command_name != CMD_CHAGE:
            return

        if return_code == 15:
            raise ResourceNotFoundError(
                "Shadow password database is unavailable.",
                details={
                    **details,
                    "resource": "/etc/shadow",
                },
            )

    def _raise_if_failed(
        self,
        result: SystemResult,
        error_cls: type[Exception],
        message: str,
        *,
        sensitive_values: Sequence[str] = (),
    ) -> None:
        if result.ok:
            return
        details = _sanitize_details(
            result.details,
            sensitive_values=sensitive_values,
        )

        result.details = details
        if result.execution:
            result.execution.command = _sanitize_command(result.execution.command or [])
            result.execution.stdout = _sanitize_text(
                result.execution.stdout,
                sensitive_values=sensitive_values,
            )
            result.execution.stderr = _sanitize_text(
                result.execution.stderr,
                sensitive_values=sensitive_values,
            )
            details.update(
                {
                    "command": _sanitize_command(result.execution.command or []),
                    "return_code": result.execution.return_code,
                    "stdout": _sanitize_text(
                        result.execution.stdout,
                        sensitive_values=sensitive_values,
                    ),
                    "stderr": _sanitize_text(
                        result.execution.stderr,
                        sensitive_values=sensitive_values,
                    ),
                }
            )
        stderr = str(details.get("stderr", "")).lower()
        if "permission" in stderr or "denied" in stderr:
            raise InsufficientPermissionsError(
                "Insufficient permissions for password operation.", details=details
            )

        missing_command_markers = (
            "command not found",
            "executable file not found",
        )

        if any(marker in stderr for marker in missing_command_markers):
            raise ResourceNotFoundError(
                "Required command is unavailable.",
                details=details,
            )

        command = details.get("command", [])
        command_name = ""
        if isinstance(command, list) and command:
            command_name = str(command[0])
        elif isinstance(command, str):
            command_name = command.split(maxsplit=1)[0] if command else ""

        return_code = details.get("return_code")
        self._raise_for_known_command_failure(
            command_name=command_name,
            return_code=return_code if isinstance(return_code, int) else None,
            details=details,
        )

        if (
            _stderr_reports_missing_user(stderr)
            or (
                command_name == CMD_GETENT
                and result.execution is not None
                and result.execution.return_code not in (None, 0)
                and not stderr
            )
        ):
            raise UserNotFoundError(
                "User was not found during password operation.", details=details
            )
        if error_cls is CommandExecutionError:
            raise CommandExecutionError(message, details=details)
        raise error_cls(message, details=details)

    def _with_password_result_details(
        self,
        result: SystemResult,
        action: str,
        username: str,
        changes: list[str],
        *,
        allow_admin: bool,
        administrative_target: bool,
        sensitive_values: Sequence[str] = (),
    ) -> SystemResult:
        result.action = action
        result.target = username
        result.details = _sanitize_details(
            {
                **result.details,
                "action": action,
                "target_user": username,
                "administrative_target": administrative_target,
                "allow_admin": allow_admin,
                "changes_applied": (
                    changes if result.changed and not result.dry_run else []
                ),
                "projected_changes": (changes if result.dry_run else []),
                "secret": REDACTED_SECRET,
                "secret_redacted": True,
                "technical_layer": "system/linux_password.py",
            },
            sensitive_values=sensitive_values,
        )
        if result.execution:
            result.execution.command = _sanitize_command(result.execution.command or [])
            result.execution.stdout = _sanitize_text(
                result.execution.stdout,
                sensitive_values=sensitive_values,
            )
            result.execution.stderr = _sanitize_text(
                result.execution.stderr,
                sensitive_values=sensitive_values,
            )
        if (
            administrative_target
            and "High-impact password operation on an administrative user."
            not in result.warnings
        ):
            result.warnings.append(
                "High-impact password operation on an administrative user."
            )
            result.impact.level = (
                ImpactLevel.HIGH
                if result.impact.level != ImpactLevel.CRITICAL
                else result.impact.level
            )
        return result

    def _skipped_result(
        self,
        action: str,
        username: str,
        message: str,
        *,
        dry_run: bool,
        allow_admin: bool,
        administrative_target: bool,
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
                "administrative_target": administrative_target,
                "allow_admin": allow_admin,
                "changes_applied": [],
                "projected_changes": [],
            },
            impact=ImpactMetadata(
                level=(ImpactLevel.HIGH if administrative_target else ImpactLevel.NONE)
            ),
        )

    def _combine_results(
        self, first: SystemResult, second: SystemResult, action: str, username: str
    ) -> SystemResult:
        combined_dry_run = first.dry_run or second.dry_run
        combined_changed = first.changed or second.changed
        combined_changes = [
            "password_hash_updated",
            "change_required_next_login",
        ]
        details = _sanitize_details(
            {
                "primary": first.to_dict(),
                "secondary": second.to_dict(),
                "secret": REDACTED_SECRET,
                "changes_applied": (
                    combined_changes
                    if combined_changed and not combined_dry_run
                    else []
                ),
                "projected_changes": (combined_changes if combined_dry_run else []),
            }
        )
        return SystemResult(
            ok=first.is_effectively_ok and second.is_effectively_ok,
            status=ResultStatus.DRY_RUN if combined_dry_run else ResultStatus.SUCCESS,
            action=action,
            target=username,
            message="Password operation completed with forced change."
            if not combined_dry_run
            else "Password operation simulated with forced change.",
            details=details,
            warnings=list(dict.fromkeys([*first.warnings, *second.warnings])),
            dry_run=combined_dry_run,
            changed=combined_changed,
            execution=first.execution,
            impact=ImpactMetadata(
                level=max(
                    (first.impact.level, second.impact.level),
                    key=lambda level: list(ImpactLevel).index(level),
                )
            ),
            simulation=first.simulation or second.simulation,
        )

    def _policy_values(
        self, policy: PasswordPolicy | Mapping[str, Any] | None, **overrides: int | None
    ) -> dict[str, int | None]:
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
                "inactive_days": policy.inactive_days,
            }
        else:
            policy_values = {
                "minimum_days": policy.get(
                    "minimum_days", policy.get("min_password_age_days")
                ),
                "maximum_days": policy.get(
                    "maximum_days", policy.get("max_password_age_days")
                ),
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
        administrative_target: bool = False,
    ) -> dict[str, Any]:
        warnings: list[str] = []
        impact = "medium"
        if administrative_target:
            impact = "high"
            warnings.append("Operation targets an administrative account.")
        metadata = {
            "action": action,
            "username": username,
            "secret_used": secret_used,
            "secret": REDACTED_SECRET if secret_used else None,
            "policy": dict(policy or {}),
            "administrative_target": administrative_target,
            "allow_admin": allow_admin,
            "impact": impact,
            "warnings": warnings,
            "reads_shadow_directly": False,
            "writes_shadow_directly": False,
        }

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
    "ACTION_CLEAR_PASSWORD_EXPIRATION",
    "ACTION_LOCK_PASSWORD",
    "ACTION_UNLOCK_PASSWORD",
    "ACTION_QUERY_PASSWORD_STATUS",
    "ACTION_QUERY_USER_IDENTITY",
    "ACTION_SET_PASSWORD_POLICY",
    "ACTION_SET_PASSWORD_MAX_DAYS",
    "ACTION_SET_PASSWORD_MIN_DAYS",
    "ACTION_SET_PASSWORD_WARNING_DAYS",
    "ACTION_SET_PASSWORD_INACTIVE_DAYS",
    "STATUS_ACTIVE",
    "STATUS_LOCKED",
    "STATUS_UNKNOWN",
    "STATUS_EXPIRED",
    "STATUS_NO_PASSWORD",
    "LinuxPasswordManager",
    "PasswordApplySpec",
    "PasswordCommandStrategy",
    "PasswordStatusInfo",
    "UserIdentity",
    "REDACTED_SECRET",
    "REQUIRED_COMMANDS",
]
