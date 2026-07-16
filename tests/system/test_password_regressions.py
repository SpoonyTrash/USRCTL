from datetime import date
from unittest.mock import Mock

import pytest

from USRCTL.system.linux_password import (
    LinuxPasswordManager,
    _stderr_reports_missing_user,
)
from USRCTL.system.password_parsers import _is_password_expired
from USRCTL.system.result import ExecutionMetadata, ResultStatus, SystemResult
from USRCTL.utils.errors import (
    CommandExecutionError,
    UserNotFoundError,
    WeakPasswordError,
)


@pytest.mark.parametrize(
    ("expiration", "expected"),
    [
        (None, False),
        ("0", True),
        ("2026-07-15", True),
        ("2026-07-16", False),
        ("2026-07-17", False),
    ],
)
def test_password_expiration_uses_explicit_reference_date(expiration, expected) -> None:
    assert _is_password_expired(expiration, today=date(2026, 7, 16)) is expected


@pytest.mark.parametrize(
    "message",
    [
        "unknown user: alice",
        "unknown user alice",
        "passwd: user 'alice' does not exist",
        "user not found: alice",
        "alice does not exist in /etc/passwd",
    ],
)
def test_strict_missing_user_messages_are_recognized(message: str) -> None:
    assert _stderr_reports_missing_user(message)


@pytest.mark.parametrize(
    "message",
    [
        "unknown user namespace option",
        "user configuration file does not exist",
        "configuration file does not exist",
        "unknown user",
        "user not found",
    ],
)
def test_unrelated_missing_user_messages_are_rejected(message: str) -> None:
    assert not _stderr_reports_missing_user(message)


@pytest.mark.parametrize(
    ("return_code", "error"),
    [(1, CommandExecutionError), (2, UserNotFoundError), (3, CommandExecutionError)],
)
def test_getent_exit_codes_have_precise_meanings(return_code, error) -> None:
    manager = LinuxPasswordManager(executor=Mock(), dry_run=True)
    result = SystemResult(
        ok=False,
        status=ResultStatus.FAILURE,
        action="query",
        execution=ExecutionMetadata(command=["getent", "passwd", "alice"], return_code=return_code),
    )
    with pytest.raises(error):
        manager._raise_if_failed(result, CommandExecutionError, "failed")


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize("password", [None, ""])
def test_generated_password_is_required_before_delegating(password, dry_run: bool) -> None:
    manager = LinuxPasswordManager(executor=Mock(), dry_run=True)
    manager.change_password = Mock()
    with pytest.raises(WeakPasswordError):
        manager.apply_generated_password("alice", password, dry_run=dry_run)
    manager.change_password.assert_not_called()
