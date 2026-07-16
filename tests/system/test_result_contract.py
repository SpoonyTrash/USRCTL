from USRCTL.system.result import (
    ExecutionMetadata,
    ImpactLevel,
    ImpactMetadata,
    ResultStatus,
    SystemResult,
)
from USRCTL.system.linux_password import LinuxPasswordManager


def test_password_manager_result_fields_are_mutable() -> None:
    result = SystemResult(
        ok=True,
        status=ResultStatus.SUCCESS,
        action="old_action",
        execution=ExecutionMetadata(command=["old"], stdout="old", stderr="old"),
        impact=ImpactMetadata(),
    )

    result.action = "new_action"
    result.message = "new message"
    result.target = "alice"
    result.details = {"safe": True}
    assert result.execution is not None
    result.execution.command = ["new"]
    result.execution.stdout = "new stdout"
    result.execution.stderr = "new stderr"
    result.impact.level = ImpactLevel.HIGH

    assert result.action == "new_action"
    assert result.message == "new message"
    assert result.target == "alice"
    assert result.details == {"safe": True}
    assert result.execution.command == ["new"]
    assert result.execution.stdout == "new stdout"
    assert result.execution.stderr == "new stderr"
    assert result.impact.level == ImpactLevel.HIGH


def test_require_execution_returns_execution_type() -> None:
    manager = LinuxPasswordManager(dry_run=True)
    successful_result = SystemResult(
        ok=True,
        status=ResultStatus.SUCCESS,
        action="test",
        execution=ExecutionMetadata(command=["getent"]),
    )

    execution = manager._require_execution(
        successful_result,
        username="alice",
        action="test",
        message="Missing execution.",
    )

    assert execution is successful_result.execution
