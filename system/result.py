from dataclasses import dataclass, field, asdict
from enum import StrEnum
from uuid import uuid4
from typing import Any
from datetime import datetime, timezone

class ResultStatus(StrEnum):
  SUCCESS = "success"
  FAILURE = "failure"
  DRY_RUN = "dry_run"
  PARTIAL = "partial"
  SKIPPED = "skipped"

class ImpactLevel(StrEnum):
  NONE = "none"
  LOW = "low"
  MEDIUM = "medium"
  HIGH = "high"
  CRITICAL = "critical"

@dataclass(slots=True)
class ExecutionMetadata:
  command: list[str] | str | None = None
  binary: str | None = None
  return_code: int | None = None
  stdout: str = ""
  stderr: str = ""
  duration_ms: float | None = None
  operation_id: str = field(default_factory=lambda: str(uuid4()))

@dataclass(slots=True)
class ImpactMetadata:
  level: ImpactLevel = ImpactLevel.NONE
  affected_resources: list[str] = field(default_factory=list)
  applied_resources: list[str] = field(default_factory=list)
  skipped_changes: list[str] = field(default_factory=list)

@dataclass(slots=True)
class SimulationMetadata:
  projected_command: list[str] | str | None = None
  dependencies_checked: dict[str, bool] = field(default_factory=dict)
  detected_risks: list[str] = field(default_factory=list)
  confirmation_required: bool = False
  precheck_viable: bool = True

@dataclass(slots=True)
class SystemResult:
  ok: bool
  status: ResultStatus
  action: str
  target: str | None = None
  message: str = ""
  details: dict[str, Any] = field(default_factory=dict)
  warnings: list[str] = field(default_factory=list)
  timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
  dry_run: bool = False
  changed: bool = False
  execution: ExecutionMetadata | None = None
  impact: ImpactMetadata = field(default_factory=ImpactMetadata)
  simulation: SimulationMetadata | None = None

  def __post_init__(self) -> None:
    if self.status == ResultStatus.SUCCESS and not self.ok:
      raise ValueError("status=SUCCESS require ok=True")
    
    if self.status == ResultStatus.FAILURE and self.ok:
      raise ValueError("status=FAILURE require ok=False")
    
    if self.status == ResultStatus.DRY_RUN and not self.dry_run:
      raise ValueError("status=DRY_RUN require dry_run=True")
    
    if self.dry_run and self.changed:
      raise ValueError("dry_run=True require changed=False")
    
    if self.status == ResultStatus.SKIPPED and self.changed:
      raise ValueError("status=SKIPPED require changed=False")
    
    if self.status == ResultStatus.PARTIAL and self.ok and not (self.warnings or self.details):
      raise ValueError("status=PARTIAL con ok=True require warnings o details")


  @property
  def is_success(self) -> bool:
    return self.ok and self.status in {ResultStatus.SUCCESS, ResultStatus.DRY_RUN}
  
  @property
  def is_failure(self) -> bool:
    return not self.ok or self.status == ResultStatus.FAILURE
  
  @property
  def is_partial(self) -> bool:
    return self.status == ResultStatus.PARTIAL
  
  @property
  def is_simulated(self) -> bool:
    return self.dry_run or self.status == ResultStatus.DRY_RUN

  def summary(self) -> dict[str, Any]:
    return {
      "ok": self.ok,
      "status": self.status.value,
      "action": self.action,
      "target": self.target,
      "message": self.message,
      "dry_run": self.dry_run,
      "changed": self.changed,
      "impact": self.impact.level.value,
      "timestamp": self.timestamp
    }
  
  def to_dict(self) -> dict[str, Any]:
    data = asdict(self)
    data["status"] = self.status.value
    data["impact"]["level"] = self.impact.level.value

    return data
  
  def to_log_record(self) -> dict[str, Any]:
    record = self.summary()
    record["warnings"] = self.warnings
    record["details"] = self.details
    if self.execution:
      record["return_code"] = self.execution.return_code
      record["operation_id"] = self.execution.operation_id
    return record
  
  def full_details(self) -> dict[str, Any]:
    return self.to_dict()

@dataclass(slots=True)
class CommandResult(SystemResult):
  execution: ExecutionMetadata = field(default_factory=ExecutionMetadata)

@dataclass(slots=True)
class ValidationResult(SystemResult):
  validation_passed: bool = True
  blocking_reasons: list[str] = field(default_factory=list)
  should_continue: bool = True

@dataclass(slots=True)
class DryRunResult(SystemResult):
  dry_run: bool = True
  status: ResultStatus = ResultStatus.DRY_RUN
  simulation: SimulationMetadata = field(default_factory=SimulationMetadata)

@dataclass(slots=True)
class StateChangeResult(SystemResult):
  changed_entities: list[str] = field(default_factory=list)
  collateral_touched: list[str] = field(default_factory=list)

@dataclass(slots=True)
class BackupResult(SystemResult):
  operation_type: str = "backup"
  backup_location: str | None = None
  backup_version: str | None = None
  included_items: list[str] = field(default_factory=list)
  failed_items: list[str] = field(default_factory=list)
  integrity_ok: bool = True

@dataclass(slots=True)
class ExportResult(SystemResult):
  output_path: str | None = None
  export_format: str | None = None
  records_count: int = 0
  approx_size_bytes: int | None = None


__all__ = [
  "ResultStatus",
  "ImpactLevel",
  "ExecutionMetadata",
  "ImpactMetadata",
  "SimulationMetadata",
  "SystemResult",
  "CommandResult",
  "ValidationResult",
  "DryRunResult",
  "StateChangeResult",
  "BackupResult",
  "ExportResult"
]