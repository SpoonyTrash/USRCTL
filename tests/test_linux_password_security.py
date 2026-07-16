from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from USRCTL.system.executor import CommandExecutor, ExecutorConfig
from USRCTL.system.linux_password import (
    ACTION_CHANGE_PASSWORD,
    ACTION_QUERY_USER_IDENTITY,
    LinuxPasswordManager,
    _split_sensitive_option,
)
from USRCTL.system.result import ExecutionMetadata, ResultStatus, SystemResult
from USRCTL.utils.errors import ResourceNotFoundError, UserNotFoundError, ValidationError


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
