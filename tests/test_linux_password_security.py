from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from USRCTL.system.executor import CommandExecutor, ExecutorConfig
from USRCTL.models.policy import PasswordPolicy
from USRCTL.system.linux_password import (
    ACTION_CHANGE_PASSWORD,
    ACTION_QUERY_USER_IDENTITY,
    LinuxPasswordManager,
    PasswordStatusInfo,
    _build_aging_command,
    _sanitize_details,
    _split_sensitive_option,
)
from USRCTL.system.result import (
    ExecutionMetadata,
    ImpactLevel,
    ImpactMetadata,
    ResultStatus,
    SystemResult,
)
from USRCTL.utils.errors import (
    PasswordChangeError,
    ResourceNotFoundError,
    UserNotFoundError,
    ValidationError,
)


class FakeExecutor:
    def __init__(self, *, user_exists: bool = True, uid: int = 1000) -> None:
        self.user_exists = user_exists
        self.uid = uid
        self.execute_with_stdin = Mock()

    def execute(self, command, **kwargs):
        action = kwargs.get("action")
        target = kwargs.get("target")
        if action == ACTION_QUERY_USER_IDENTITY:
            if not self.user_exists:
                return SystemResult(
                    ok=False,
                    status=ResultStatus.FAILURE,
                    action=action,
                    target=target,
                    message="missing",
                    execution=ExecutionMetadata(
                        command=list(command),
                        return_code=2,
                    ),
                )
            return SystemResult(
                ok=True,
                status=ResultStatus.SUCCESS,
                action=action,
                target=target,
                execution=ExecutionMetadata(
                    command=list(command),
                    return_code=0,
                    stdout=f"{target}:x:{self.uid}:1000::/home/{target}:/bin/bash\n",
                ),
            )

        return SystemResult(
            ok=True,
            status=ResultStatus.SUCCESS,
            action=action or "test",
            target=target,
            changed=False,
        )


def test_chpasswd_record_injection_passwords_are_rejected_before_executor_call() -> None:
    executor = FakeExecutor()
    manager = LinuxPasswordManager(executor=executor, dry_run=True)

    for password in (
        "StrongPassword1!\nroot:OtherPassword2!",
        "StrongPassword1!\rroot:OtherPassword2!",
        "StrongPassword1!\x00suffix",
    ):
        with pytest.raises(ValidationError):
            manager.change_password("alice", password, dry_run=True)

        executor.execute_with_stdin.assert_not_called()


def test_set_password_policy_validates_missing_user_before_skipped() -> None:
    manager = LinuxPasswordManager(executor=FakeExecutor(user_exists=False), dry_run=True)

    with pytest.raises(UserNotFoundError):
        manager.set_password_policy("missing-user", dry_run=True)


def test_set_password_policy_skips_valid_user_without_requested_changes() -> None:
    manager = LinuxPasswordManager(executor=FakeExecutor(), dry_run=True)

    result = manager.set_password_policy("alice", dry_run=True)

    assert result.status is ResultStatus.SKIPPED
    assert result.details["allow_admin"] is False
    assert result.details["administrative_target"] is False


def test_raise_if_failed_classifies_missing_command_before_missing_user() -> None:
    manager = LinuxPasswordManager(executor=FakeExecutor(), dry_run=True)
    result = SystemResult(
        ok=False,
        status=ResultStatus.FAILURE,
        action="set_password_policy",
        target="alice",
        execution=ExecutionMetadata(
            command=["chage", "alice"],
            return_code=127,
            stderr="chage: command not found",
        ),
    )

    with pytest.raises(ResourceNotFoundError):
        manager._raise_if_failed(result, RuntimeError, "failed")


def test_raise_if_failed_classifies_missing_user() -> None:
    manager = LinuxPasswordManager(executor=FakeExecutor(), dry_run=True)
    result = SystemResult(
        ok=False,
        status=ResultStatus.FAILURE,
        action="set_password_policy",
        target="alice",
        execution=ExecutionMetadata(
            command=["chage", "alice"],
            return_code=1,
            stderr="chage: user 'alice' does not exist",
        ),
    )

    with pytest.raises(UserNotFoundError):
        manager._raise_if_failed(result, RuntimeError, "failed")


def test_raise_if_failed_does_not_classify_generic_does_not_exist_as_missing_user() -> None:
    manager = LinuxPasswordManager(executor=FakeExecutor(), dry_run=True)
    result = SystemResult(
        ok=False,
        status=ResultStatus.FAILURE,
        action="set_password_policy",
        target="alice",
        execution=ExecutionMetadata(
            command=["chage", "alice"],
            return_code=1,
            stderr="configuration file does not exist",
        ),
    )

    with pytest.raises(PasswordChangeError):
        manager._raise_if_failed(result, PasswordChangeError, "failed")


def test_password_policy_preserves_inactive_days_in_model_and_command() -> None:
    manager = LinuxPasswordManager(executor=FakeExecutor(), dry_run=True)
    manager.get_password_policy = Mock(
        return_value=PasswordStatusInfo(
            username="alice",
            minimum_days=0,
            maximum_days=90,
            warning_days=7,
            inactive_days=30,
        )
    )

    model = manager.build_password_policy_model("alice")

    assert model.inactive_days == 30
    assert _build_aging_command("alice", **manager._policy_values(model)) == [
        "chage",
        "-m",
        "0",
        "-M",
        "90",
        "-W",
        "7",
        "-I",
        "30",
        "alice",
    ]
    assert PasswordPolicy(inactive_days=30).inactive_days == 30


def test_split_sensitive_option_preserves_option_case_and_value_after_equals() -> None:
    assert _split_sensitive_option("--Password=AbC=123") == ("--Password", "AbC=123")


def test_execution_metadata_is_mutable_for_safe_sanitization() -> None:
    execution = ExecutionMetadata(command=["echo", "secret"], stdout="a", stderr="b")
    execution.command = ["echo", "[REDACTED]"]
    execution.stdout = "[REDACTED]"
    execution.stderr = "[REDACTED]"

    assert execution.command == ["echo", "[REDACTED]"]
    assert execution.stdout == "[REDACTED]"
    assert execution.stderr == "[REDACTED]"


def test_system_result_and_impact_metadata_are_mutable_for_safe_sanitization() -> None:
    result = SystemResult(
        ok=True,
        status=ResultStatus.SUCCESS,
        action="original",
        message="before",
        details={"before": True},
        impact=ImpactMetadata(level=ImpactLevel.LOW),
    )

    result.action = "updated"
    result.message = "after"
    result.details = {"after": True}
    result.impact.level = ImpactLevel.HIGH

    assert result.action == "updated"
    assert result.message == "after"
    assert result.details == {"after": True}
    assert result.impact.level is ImpactLevel.HIGH


def test_sanitize_details_converts_sets_to_sorted_lists() -> None:
    sanitized = _sanitize_details({"values": {"b", "a"}})

    assert json.dumps(sanitized, default=str)
    assert sanitized["values"] == ["a", "b"]


def test_sanitize_details_limits_deep_recursion() -> None:
    details = current = {}
    for index in range(25):
        next_value = {}
        current[f"level_{index}"] = next_value
        current = next_value

    sanitized = _sanitize_details(details)

    serialized = json.dumps(sanitized, default=str)
    assert "[MAX_DEPTH_REACHED]" in serialized


def test_execute_with_stdin_contract_does_not_serialize_secret() -> None:
    executor = CommandExecutor(ExecutorConfig(dry_run=True))

    result = executor.execute_with_stdin(
        ["chpasswd"],
        stdin_data="alice:UniqueSecret-ABC123!\n",
        stdin_sensitive=True,
        action=ACTION_CHANGE_PASSWORD,
        target="alice",
    )

    serialized = json.dumps(result.to_dict(), default=str)
    assert "UniqueSecret-ABC123" not in serialized
    assert result.details["stdin_supplied"] is True
    assert result.details["stdin_sensitive"] is True


def test_change_password_secret_strategy_validation_has_no_name_error() -> None:
    executor = FakeExecutor()
    executor.execute_with_stdin.return_value = SystemResult(
        ok=True,
        status=ResultStatus.DRY_RUN,
        action=ACTION_CHANGE_PASSWORD,
        target="alice",
        dry_run=True,
        changed=False,
        execution=ExecutionMetadata(command=["chpasswd"], return_code=0),
    )
    manager = LinuxPasswordManager(executor=executor, dry_run=True)

    result = manager.change_password(
        "alice",
        "UniqueSecret-ABC123!",
        dry_run=True,
    )

    assert result.dry_run is True


def test_raise_if_failed_missing_user_classifier_is_precise() -> None:
    manager = LinuxPasswordManager(executor=FakeExecutor(), dry_run=True)

    for stderr in (
        "unknown user: alice",
        "user alice does not exist",
    ):
        result = SystemResult(
            ok=False,
            status=ResultStatus.FAILURE,
            action="set_password_policy",
            target="alice",
            execution=ExecutionMetadata(
                command=["chage", "alice"],
                return_code=1,
                stderr=stderr,
            ),
        )
        with pytest.raises(UserNotFoundError):
            manager._raise_if_failed(result, PasswordChangeError, "failed")

    for stderr in (
        "user configuration file does not exist",
        "configuration file does not exist",
    ):
        result = SystemResult(
            ok=False,
            status=ResultStatus.FAILURE,
            action="set_password_policy",
            target="alice",
            execution=ExecutionMetadata(
                command=["chage", "alice"],
                return_code=1,
                stderr=stderr,
            ),
        )
        with pytest.raises(PasswordChangeError):
            manager._raise_if_failed(result, PasswordChangeError, "failed")


def test_password_policy_serializes_inactive_days() -> None:
    policy = PasswordPolicy(inactive_days=30)

    assert policy.inactive_days == 30
    assert policy.to_dict()["inactive_days"] == 30


def test_system_result_contract_is_mutable() -> None:
    result = SystemResult(
        ok=True,
        status=ResultStatus.SUCCESS,
        action="original",
        message="original",
        target="bob",
        details={"original": True},
        impact=ImpactMetadata(level=ImpactLevel.LOW),
    )

    result.action = "updated"
    result.message = "updated"
    result.target = "alice"
    result.details = {"updated": True}
    result.impact.level = ImpactLevel.HIGH

    assert result.action == "updated"
    assert result.impact.level is ImpactLevel.HIGH


def test_execution_metadata_contract_is_mutable() -> None:
    result = SystemResult(
        ok=True,
        status=ResultStatus.SUCCESS,
        action="test",
        execution=ExecutionMetadata(command=["before"], stdout="before", stderr="before"),
    )

    assert result.execution is not None
    result.execution.command = ["after"]
    result.execution.stdout = "after"
    result.execution.stderr = "after"

    assert result.execution.command == ["after"]
    assert result.execution.stdout == "after"
    assert result.execution.stderr == "after"


def test_every_public_export_exists() -> None:
    import USRCTL.system.linux_password as module

    for exported_name in module.__all__:
        assert hasattr(module, exported_name)
