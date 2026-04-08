import subprocess
import shlex
import os
import shutil
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Any, Sequence
from time import perf_counter

from system.result import (
  CommandResult,
  DryRunResult,
  ImpactLevel,
  ResultStatus,
  ExecutionMetadata,
  ImpactMetadata, 
  SimulationMetadata,
)

from utils.errors import (
  CommandExecutionError, 
  ResourceNotFoundError,
  InsufficientPermissionsError,
  ValidationError,
  PreventiveSecurityError
)


DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_ENCODING = "utf-8"
DEFAULT_CAPTURE_OUTPUT = True
DEFAULT_USE_SHELL = False
DEFAULT_VALIDATE_BEFORE_EXECUTE = True
DEFAULT_ALLOW_ARBITRARY_COMMANDS = False

SENSITIVE_PATTERNS = (
  "password",
  "passwd",
  "pwd",
  "token",
  "secret",
  "shadow",
  "chpasswd"
)

HIGH_IMPACT_BINARIES = {
  "userdel": ImpactLevel.HIGH,
  "usermod": ImpactLevel.MEDIUM,
  "chpasswd": ImpactLevel.HIGH,
  "chage": ImpactLevel.MEDIUM,
  "chmod": ImpactLevel.MEDIUM,
  "chown": ImpactLevel.MEDIUM,
  "tar": ImpactLevel.MEDIUM,
  "rsync": ImpactLevel.MEDIUM
}

READ_ONLY_BINARIES = {
  "command",
  "id",
  "getent"
}

MUTATING_BINARIES = {
  "useradd",
  "usermod",
  "userdel",
  "passwd",
  "chpasswd",
  "chage",
  "groupadd",
  "groupdel",
  "groupmod",
  "gpasswd",
  "chmod",
  "chown",
  "tar",
  "cp",
  "mv",
  "rm",
}

POLICY_BINARIES = frozenset(READ_ONLY_BINARIES | MUTATING_BINARIES)

CRITICAL_KEYWORDS = (
  "/etc/shadow",
  "--remove-home",
  "-r",
  "restore",
  "recursive",
  "--recursive"
)

SENSITIVE_RECURSIVE_PATHS = (
  Path("/"),
  Path("/etc"),
  Path("/var"),
  Path("/usr"),
  Path("/bin"),
  Path("/sbin"),
  Path("/lib")
)

SENSITIVE_SYSTEM_PATHS = (
  Path("/etc"),
  Path("/usr"),
  Path("/bin"),
  Path("/sbin")
)

REDACTION_REGEX_PATTERNS = (
  r"(?i)\b(password|passwd|pwd|token|secret)\b\s*[:=]\s*([^\s,;]+)",
  r"(?i)\b(chpasswd)\b[^\n]*",
  r"(?i)\b(/etc/shadow)\b[^\s]*",
)

@dataclass(slots=True)
class ExecutorConfig:
  dry_run: bool = False
  timeout: int = DEFAULT_TIMEOUT_SECONDS
  encoding: str = DEFAULT_ENCODING
  capture_output: bool = DEFAULT_CAPTURE_OUTPUT
  use_shell: bool =  DEFAULT_USE_SHELL
  validate_before_execute: bool = DEFAULT_VALIDATE_BEFORE_EXECUTE
  allow_arbitrary_commands: bool = DEFAULT_ALLOW_ARBITRARY_COMMANDS
  default_env: dict[str, str] = field(default_factory=dict)
  default_cwd: Path | None = None
  allowed_binaries: set[str] = field(
    default_factory=lambda: set(POLICY_BINARIES)
  )

def __post_init__(self) -> None:
  expected_allowed_binaries = set(POLICY_BINARIES)
  if self.allowed_binaries != expected_allowed_binaries:
    raise ValidationError(
      "allowed_binaries must match the explicit binary policy union.",
      details={
        "expected": sorted(expected_allowed_binaries),
        "received": sorted(self.allowed_binaries)
      }
    )

def _normalize_command(command: Sequence[str] | str) -> list[str]:
  if isinstance(command, str):
    tokens = shlex.split(command.strip())
  else:
    tokens = [str(token).strip() for token in  command if token is not None]
  return [token for token in tokens if token]

def _sanitize_arguments(command: list[str]) -> None:
  if not command:
    raise ValidationError("The command cannot be empty.")
  raw_binnary = command[0]
  if not raw_binnary:
    raise ValidationError("Invalid command binary.")
  
  if "\x00" in raw_binnary:
    raise ValidationError("Invalid command binary.")

  if not raw_binnary.strip():
    raise ValidationError("Invalid command binary.")

  binary_for_validation = Path(raw_binnary).name if raw_binnary.startswith(("/", ".")) else raw_binnary.strip()   
  
  if not binary_for_validation or binary_for_validation.startswith("-"):
    raise ValidationError("Invalid command binary.")


def _redact_value(value: str) -> str:
  lowered = value.lower()
  if any(pattern in lowered for pattern in SENSITIVE_PATTERNS):
    return "[REDACTED]"
  if value.count(":") >= 1 and len(value) > 8:
    return "[REDACTED]"
  return value
  
def _safe_command_repr(command: Sequence[str]) -> list[str]:
  redacted: list[str] = []
  for index, token in enumerate(command):
    if token.startswith("--") and "=" in token:
      key, raw = token.split("=", 1)
      if any(pattern in key.lower() for pattern in SENSITIVE_PATTERNS):
        redacted.append(f"{key}=[REDACTED]")
      else:
        redacted.append(f"{key}={_redact_value(raw)}")
      continue

    previous = command[index - 1].lower() if index > 0 else ""
    if previous in {"-p", "--password", "--token", "--secret"}:
      redacted.append("[REDACTED]")
    else:
      redacted.append(_redact_value(token))

  return redacted
  
def _minimum_viability_check(command: Sequence[str]) -> None:
  _sanitize_arguments(list(command))

def _is_sensitive_path(path: Path, roots: Sequence[Path]) -> bool:
  for root in roots:
    if path == root or root in path.parents:
      return True
  return False

def _is_mutating_command(command: Sequence[str]) -> bool:
  binary = Path(command[0]).name
  return binary is MUTATING_BINARIES

def _estimate_impact(command: Sequence[str]) -> tuple[ImpactLevel, list[str], list[str]]:
  warnings: list[str] = []
  resources: list[str] = []
  binary = Path(command[0]).name
  impact = HIGH_IMPACT_BINARIES.get(binary, ImpactLevel.LOW)

  joined = " ".join(command)
  if any(keyword in joined for keyword in CRITICAL_KEYWORDS):
    impact = ImpactLevel.CRITICAL
    warnings.append("Operation flagged as critical due to sensitive arguments.")

  if binary == "userdel":
    warnings.append("Deleting users is a high-impact operation.")
    if "--remove-home" in command:
      impact = ImpactLevel.CRITICAL
      warnings.append("Using --remove-home with userdel is critical.")
  
  if binary == "rm" and any(arg in {"-r", "-rf", "-fr", "--recursive"} for arg in command):
    resources.append("recursive delete")
    for token in command:
      if not token.startswith("/"):
        continue
      token_path = Path(token)
      if _is_sensitive_path(token_path, SENSITIVE_RECURSIVE_PATHS):
        impact = ImpactLevel.CRITICAL
        warnings.append("Recursive deletion on a sensitive path detected.")
        break
  
  if binary in {"mv", "cp"}:
    destination = next((token for token in reversed(command[1:])  if token.startswith("/")), None)
    if destination is not None:
      destination_path = Path(destination)
      if _is_sensitive_path(destination_path, SENSITIVE_SYSTEM_PATHS):
        impact = ImpactLevel.HIGH if impact != ImpactLevel.CRITICAL else impact
        warnings.append("Move/copy destination targets a sensitive system directory.")
  
  if binary == "tar":
    has_extract_flag = any(
      arg in {"-x", "-xf", "--extract"} or (arg.startswith("-") and "x" in arg[1:])
      for arg in command[1:]
    )
    extract_destination = None
    for index, token in enumerate(command[1:], start=1):
      if token in {"-C", "--directory"} and index + 1 < len(command):
        extract_destination = command[index + 1]
      elif token.startswith("--directory="):
        extract_destination = token.split("=", 1)[1]
    if has_extract_flag and extract_destination and extract_destination.startswith("/"):
      destination_path = Path(extract_destination)
      if _is_sensitive_path(destination_path, SENSITIVE_SYSTEM_PATHS):
        impact = ImpactLevel.CRITICAL if destination_path == Path("/etc") else ImpactLevel.HIGH
        warnings.append("Tar extraction into a sensitive system path detected.")

  
  if binary in {"chmod", "chown"} and any(arg in {"-R", "--recursive"} for arg in command):
    resources.append("recursive permissions")
    for token in command:
      if token.startswith("/"):
        token_path = Path(token)
        if token_path in SENSITIVE_RECURSIVE_PATHS:
          impact = ImpactLevel.CRITICAL
          warnings.append("Recursive operation on a sensitive path detected.")

  for token in command:
    if token.startswith("/"):
      resources.append(token)

  return impact, warnings, resources

class CommandExecutor:
  def __init__(self, config: ExecutorConfig | None = None) -> None:
    self.config = config or ExecutorConfig()
  
  def execute(
      self,
      command: Sequence[str] | str,
      *,
      action: str,
      target: str  | None = None,
      timeout: int | None = None,
      dry_run: bool | None = None,
      env: Mapping[str, str] | None = None,
      cwd: str | Path | None = None,
      metadata: Mapping[str, Any] | None = None,
      raise_on_failure: bool = False,
      stdin_data: str | None = None,
      stdin_sensitive: bool = False,
      capture_output: bool | None = None,
      use_shell: bool | None = None
  ) -> CommandResult | DryRunResult:
    prepared_command = self._prepare_command(command)
    exec_timeout, exec_env, exec_cwd, should_capture, shell_mode = self._prepare_execution_context(
      timeout=timeout,
      env=env,
      cwd=cwd,
      capture_output=capture_output,
      use_shell=use_shell
    )

    command_safe = _safe_command_repr(prepared_command)
    impact_level, impact_warnings, affected_resources = self._prepare_security_evaluation(prepared_command)
    
    should_dry_run = self.config.dry_run if dry_run is None else dry_run
    audit_details = self._prepare_audit_metadata(
      action=action,
      target=target,
      command_safe=command_safe,
      impact=impact_level,
      is_dry_run=should_dry_run,
      metadata=metadata
    )

    if self.config.validate_before_execute:
      self._validate_command_viability(prepared_command, shell_mode)

    if should_dry_run:
      result = self._simulate(
        prepared_command,
        action=action,
        target=target,
        timeout=exec_timeout,
        command_safe=command_safe,
        impact_level=impact_level,
        impact_warnings=impact_warnings,
        affected_resources=affected_resources,
        audit_details=audit_details
      )
      return result

    result = self._execute_real(
      prepared_command,
      action=action,
      target=target,
      timeout=exec_timeout,
      env= exec_env,
      cwd=exec_cwd,
      capture_output=should_capture,
      use_shell=shell_mode,
      stdin_data=stdin_data,
      stdin_sensitive=stdin_sensitive,
      command_safe=command_safe,
      impact_level=impact_level,
      impact_warnings=impact_warnings,
      affected_resources=affected_resources,
      audit_details=audit_details
    )

    if raise_on_failure and not result.ok:
      self._raise_for_result(result, timeout=exec_timeout)
    return result
  
  def simulate(
      self,
      command: Sequence[str] | str,
      *,
      action: str,
      target: str | None = None,
      timeout: int | None = None,
      metadata: Mapping[str, Any] | None = None
  ) -> DryRunResult:
    return self.execute(
      command,
      action=action,
      target=target,
      timeout=timeout,
      metadata=metadata,
      dry_run=True
    )

  def check_dependency(self, binary: str, *, raise_on_missing: bool = False) -> CommandResult:
    command = ["command", "-v", binary]
    exists = shutil.which(binary) is not None
    
    result = self._to_command_result(
      ok = exists,
      action="check_dependency",
      target=binary,
      message="Dependency available" if exists else "Dependency not found",
      return_code=0 if exists else 127,
      stdout=binary if exists else "",
      stderr="" if exists else f"Binary not found: {binary}",
      command_safe=command,
      impact_level=ImpactLevel.NONE,
      warnings=[] if exists else ["Missing system dependency."],
      affected_resources=[],
      details={
        "dependency": binary, 
        "checked_with": "shutil.which",
        "operation_kind": "dependency_check",
        "command_is_pseudo": True,
        "binary_classification": "read_only"
      },
      changed=False,
      duration_ms=0.0,
      binary=binary
    )
    if raise_on_missing and not exists:
      raise ResourceNotFoundError(
        message=f"Required dependency not found: {binary}",
        details={"binary": binary}
      )
    return result
  
  def execute_strict(self, command: Sequence[str] | str, **kwargs: Any) -> CommandResult:
    requested_dry_run = kwargs.get("dry_run")
    effective_dry_run = self.config.dry_run if requested_dry_run is None else bool(requested_dry_run)
    if effective_dry_run:
      raise ValidationError("execute_strict does not support dry_run=True")
    result = self.execute(command, raise_on_failure=True, **kwargs)
    if isinstance(result, DryRunResult):
      raise ValidationError("execute_strict does not support dry_run=True")
    return result
  
  def execute_with_stdin(
      self,
      command: Sequence[str] | str,
      *,
      stdin_data: str,
      stdin_sensitive: bool = True,
      **kwargs: Any,
  ) -> CommandResult | DryRunResult:
    return self.execute(
      command,
      stdin_data=stdin_data,
      stdin_sensitive=stdin_sensitive,
      **kwargs
    )
  
  def execute_quiet(self, command: Sequence[str] | str, **kwargs: Any) -> CommandResult | DryRunResult:
    return self.execute(command, capture_output=False, **kwargs)
  
  def _prepare_execution_context(
      self,
      *,
      timeout: int | None,
      env: Mapping[str, str] | None,
      cwd: str | Path | None,
      capture_output: bool | None,
      use_shell: bool | None,
  ) -> tuple[int, dict[str, str], Path | None, bool, bool]:
    exec_timeout = timeout if timeout is not None else self.config.timeout
    if exec_timeout <= 0:
      raise ValidationError("The timeout must be greater than zero.")
    
    base_env = dict(os.environ)
    base_env.update(self.config.default_env)
    if env:
      base_env.update({str(k): str(v) for k, v in env.items()})
    
    exec_cwd = Path(cwd) if cwd is not None else self.config.default_cwd
    if exec_cwd is not None and not exec_cwd.exists():
      raise ValidationError("The working directory (cwd) does not exist.", details={"cwd": str(exec_cwd)})
    
    should_capture = self.config.capture_output if capture_output is None else capture_output
    shell_mode = self.config.use_shell if use_shell is None else use_shell

    return exec_timeout, base_env, exec_cwd, should_capture, shell_mode

  def _prepare_audit_metadata(
      self,
      *,
      action: str,
      target: str | None,
      command_safe: Sequence[str],
      impact: ImpactLevel,
      is_dry_run: bool,
      metadata: Mapping[str, Any] | None
  ) -> dict[str, Any]:
    details: dict[str, Any] = {
      "action": action,
      "target": target,
      "command": list(command_safe),
      "impact": impact.value,
      "dry_run": is_dry_run
    }
    if metadata:
      details["metadata"] = dict(metadata)
    return details
  
  def _prepare_security_evaluation(self, command: Sequence[str]) -> tuple[ImpactLevel, list[str], list[str]]:
    impact, warnings, resources = _estimate_impact(command)
    return impact, warnings, resources

  def _validate_command_viability(self, command: Sequence[str], use_shell: bool) -> None:
    binary = Path(command[0]).name

    if use_shell:
      raise PreventiveSecurityError("The executor policy does not allow shell=True by default.")
    
    if not self.config.allow_arbitrary_commands and binary not in self.config.allowed_binaries:
      raise PreventiveSecurityError(
        message="Command blocked by security policy.",
        details={"binary": binary}
      )
    
    if binary not in POLICY_BINARIES:
      raise  PreventiveSecurityError(
        message="Binary without explicit mutability policy.",
        details={"binary": binary}
      )
    
  def _execute_real(
      self,
      command: Sequence[str],
      *,
      action: str,
      target: str | None,
      timeout: int,
      env: Mapping[str, str],
      cwd: Path | None,
      capture_output: bool,
      use_shell: bool,
      stdin_data: str | None,
      stdin_sensitive: bool,
      command_safe: Sequence[str],
      impact_level: ImpactLevel,
      impact_warnings: list[str],
      affected_resources: list[str],
      audit_details: Mapping[str, Any],
  ) -> CommandResult:
    started = perf_counter()
    try:
      completed = subprocess.run(
        list(command),
        input=stdin_data,
        capture_output=capture_output,
        text=True,
        encoding=self.config.encoding,
        errors="replace",
        timeout=timeout,
        env=dict(env),
        cwd=str(cwd) if cwd else None,
        check=False,
        shell=use_shell
      )
      duration_ms = (perf_counter() - started) * 1000
      stdout = completed.stdout or ""
      stderr = completed.stderr or ""
      
      if stdin_sensitive:
        stdout = self._redact_sensitive_text(stdout)
        stderr = self._redact_sensitive_text(stderr)

      ok = completed.returncode == 0
      changed = ok and _is_mutating_command(command)
      message = "Command completed successfully." if ok else "Command execution failed."
      return self._to_command_result(
        ok=ok,
        action=action,
        target=target,
        message=message,
        return_code=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        command_safe=command_safe,
        impact_level=impact_level,
        warnings=impact_warnings,
        affected_resources=affected_resources,
        details=dict(audit_details),
        changed=changed,
        duration_ms=duration_ms,
        binary=Path(command[0]).name,
      )
    except Exception as exc:
      duration_ms = (perf_counter() - started) * 1000
      handled = self._handle_runtime_exception(
        exc,
        action=action,
        target=target,
        command_safe=command_safe,
        timeout=timeout,
        duration_ms=duration_ms
      )
      return handled

  def _simulate(
      self,
      command: Sequence[str],
      *,
      action: str,
      target: str | None,
      timeout: int,
      command_safe: Sequence[str],
      impact_level: ImpactLevel,
      impact_warnings: list[str],
      affected_resources: list[str],
      audit_details: Mapping[str, Any]
  ) -> DryRunResult:
    binary = Path(command[0]).name
    dependency_ok = shutil.which(binary) is not None
    warnings = list(impact_warnings)

    if not dependency_ok:
      warnings.append(f"The '{binary}' dependency is not available in PATH.")

    details = dict(audit_details)
    details.update({"timeout": timeout, "dependency_ok": dependency_ok})

    return self._to_dry_run_result(
      action=action,
      target=target,
      message="Simulation completed without real changes.",
      command_safe=command_safe,
      impact_level=impact_level,
      warnings= warnings,
      affected_resources=affected_resources,
      details=details,
      dependencies_checked={binary: dependency_ok},
      risks=warnings,
      confirmation_required=impact_level in {ImpactLevel.HIGH, ImpactLevel.CRITICAL},
      precheck_viable=dependency_ok
    )

  def _handle_runtime_exception(
      self,
      exc: Exception,
      *,
      action: str,
      target: str | None,
      command_safe: Sequence[str],
      timeout: int,
      duration_ms: float
  ) -> CommandResult:
    details = {
      "action": action,
      "target": target,
      "command": list(command_safe),
      "timeout": timeout
    }

    if isinstance(exc, FileNotFoundError):
      error = ResourceNotFoundError(
        message= "The requested binary was not found.",
        details= details,
        cause=exc
      )
      return self._error_result(error, action, target, command_safe, duration_ms)
    
    if isinstance(exc, subprocess.TimeoutExpired):
      error = CommandExecutionError(
        message= "Command timed out.",
        details= {**details, "timeout": timeout, "reason": "timeout"},
        cause=exc
      )
      return self._error_result(error, action, target, command_safe, duration_ms)
    
    if isinstance(exc, PermissionError):
      error = InsufficientPermissionsError(
        message= "Insufficient permissions to execute the command.",
        details= details,
        cause=exc
      )
      return self._error_result(error, action, target, command_safe, duration_ms)

    error = CommandExecutionError(
      message="Technical error while executing the command.",
      details=details,
      cause=exc
    )

    return self._error_result(error, action, target, command_safe, duration_ms)

  def _raise_for_result(self, result: CommandResult, *, timeout: int) -> None:
    if result.ok:
      return
    
    details = {
      "action": result.action,
      "target": result.target,
      "status": result.status.value,
      "timeout": timeout
    }
    if result.execution:
      details["command"] = result.execution.command
      details["return_code"] = result.execution.return_code
      details["stderr"] = self._redact_sensitive_text(result.execution.stderr)
    
    raise CommandExecutionError(
      message=result.message or "Command execution failed.",
      details=details
    )
  
  def _to_command_result(
      self,
      *,
      ok: bool,
      action: str,
      target: str | None,
      message: str,
      return_code: int,
      stdout: str,
      stderr: str,
      command_safe: Sequence[str],
      impact_level: ImpactLevel,
      warnings: list[str],
      affected_resources: list[str],
      details: Mapping[str, Any],
      changed: bool,
      duration_ms: float,
      binary: str
  ) -> CommandResult:
    status = ResultStatus.SUCCESS if ok else ResultStatus.FAILURE
    execution = ExecutionMetadata(
      command=list(command_safe),
      binary=binary,
      return_code=return_code,
      stdout=self._redact_sensitive_text(stdout),
      stderr=self._redact_sensitive_text(stderr),
      duration_ms=duration_ms
    )
    impact = ImpactMetadata(
      level=impact_level,
      affected_resources=affected_resources,
      applied_resources=affected_resources if changed else [],
      skipped_changes=[] if changed else affected_resources
    )

    return CommandResult(
      ok=ok,
      status=status,
      action=action,
      target=target,
      message=message,
      details=dict(details),
      warnings=warnings,
      dry_run=False,
      changed=changed,
      execution=execution,
      impact=impact
    )

  def _to_dry_run_result(
      self,
      *,
      action: str,
      target: str | None,
      message: str,
      command_safe: Sequence[str],
      impact_level: ImpactLevel,
      warnings: list[str],
      affected_resources: list[str],
      details: Mapping[str, Any],
      dependencies_checked: dict[str, bool],
      risks: list[str],
      confirmation_required: bool,
      precheck_viable: bool
  ) -> DryRunResult:
    execution = ExecutionMetadata(
      command=list(command_safe),
      binary=Path(command_safe[0]).name if command_safe else None,
      return_code=0,
      stdout="",
      stderr="",
      duration_ms=0.0
    )
    impact = ImpactMetadata(
      level=impact_level,
      affected_resources=affected_resources,
      skipped_changes=affected_resources
    )
    simulation = SimulationMetadata(
      projected_command=list(command_safe),
      dependencies_checked=dependencies_checked,
      detected_risks=risks,
      confirmation_required=confirmation_required,
      precheck_viable=precheck_viable
    )

    return DryRunResult(
      action=action,
      target=target,
      message=message,
      details=dict(details),
      warnings=warnings,
      changed=False,
      execution=execution,
      impact=impact,
      simulation=simulation
    )
  
  def _error_result(
      self,
      error: Exception,
      action: str,
      target: str | None,
      command_safe: Sequence[str],
      duration_ms: float
  ) -> CommandResult:
    stderr = str(error)
    details = getattr(error, "details", {}) or {}
    
    impact_level, warnings = self._classify_error_impact(error, details)

    return self._to_command_result(
      ok=False,
      action=action,
      target=target,
      message=str(error),
      return_code=1,
      stdout="",
      stderr=stderr,
      command_safe=command_safe,
      impact_level=impact_level,
      warnings=warnings,
      affected_resources=[],
      details=details,
      changed=False,
      duration_ms=duration_ms,
      binary=Path(command_safe[0]).name if command_safe else "unknown"
    )
  
  def _classify_error_impact(
      self,
      error: Exception,
      details: Mapping[str, Any]
  ) -> tuple[ImpactLevel, list[str]]:
    impact_level = ImpactLevel.LOW
    warnings = ["The technical execution produced a controlled error."]

    if isinstance(error, InsufficientPermissionsError):
      impact_level = ImpactLevel.MEDIUM
      warnings = ["Execution blocked due to insufficient permissions."]
    elif isinstance(error, ResourceNotFoundError):
      impact_level = ImpactLevel.LOW
      warnings = ["Required resource was not found."]
    elif isinstance(error, PreventiveSecurityError):
      impact_level = ImpactLevel.HIGH
      warnings = ["Operation blocked by preventive security controlls."]
    elif isinstance(error, CommandExecutionError):
      is_timeout = details.get("reason") == "timeout" or isinstance(getattr(error, "cause", None), subprocess.TimeoutExpired)
      if is_timeout:
        impact_level = ImpactLevel.MEDIUM
        warnings = ["Command execution timed out before completion."]
    
    return impact_level, warnings
    

  def _redact_sensitive_text(self, value: str) -> str:
    if not value:
      return value
    redacted = value
    for pattern in REDACTION_REGEX_PATTERNS:
      redacted = re.sub(pattern, self._redaction_replacer, redacted)
    
    lines: list[str] = []
    for line in redacted.splitlines():
      lowered = line.lower()
      if self._requires_full_line_redaction(lowered):
        lines.append("[REDACTED]")
      else:
        lines.append(line)
    
    if redacted.endswith("\n"):
      return "\n".join(lines) + "\n"
    return "\n".join(lines)
  
  def _redaction_replacer(self, match: re.Match[str]) -> str:
    secret_key = match.group(1) if match.lastindex and match.lastindex >= 1 else None
    if secret_key:
      return f"{secret_key}=[REDACTED]"
    return "[REDACTED]" 
  
  def _requires_full_line_redaction(self, lowered_line: str) -> bool:
    return any(keyword in lowered_line for keyword in {"chpasswd", "/etc/shadow"})
  
  def _prepare_command(self, command: Sequence[str] | str) -> list[str]:
    normalized = _normalize_command(command)
    _minimum_viability_check(normalized)
    return normalized

__all__ = [
  "CommandExecutor",
  "ExecutorConfig",
  "DEFAULT_TIMEOUT_SECONDS",
  "DEFAULT_ENCODING"
]