import logging
import logging.handlers
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from datetime import datetime, timezone

from utils.errors import UsrCtlError
from system.result import SystemResult

AUDIT_LOGGER_NAME = "usrctl.audit"
DEFAULT_AUDIT_LOG_PATH = Path("/var/log/usrctl/audit.log")
FALLBACK_AUDIT_LOG_PATH = Path.home() / ".local" / "state" / "usrctl" / "audit.log"
SECURITY_LEVEL_NUM = 25
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
AUDIT_FIELDS = (
    "timestamp",
    "level",
    "event_type",
    "action",
    "actor",
    "target",
    "result",
    "message",
    "details",
    "impact",
    "dry_run",
    "error_code"
)

SENSITIVE_EVENTS = {
    "delete_user",
    "delete_user_home",
    "restore_backup",
    "recursive_chmod",
    "recursive_chown",
    "change_password",
    "modify_shadow_policy"
}

SENSITIVE_KEYS = {
    "password",
    "secret",
    "token",
    "stdin",
    "shadow",
    "hash",
    "credential",
    "passwd",
    "private_key"
}

LEVEL_SECURITY = "SECURITY"

VALUE_REDACTION_PATTERNS = (
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"(?i)authorization\s*:\s*bearer\s+[^\s,;]+"),
)


def _register_security_level() -> None:
    if logging.getLevelName(SECURITY_LEVEL_NUM) != LEVEL_SECURITY:
        logging.addLevelName(SECURITY_LEVEL_NUM, LEVEL_SECURITY)
    if not hasattr(logging, LEVEL_SECURITY):
        setattr(logging, LEVEL_SECURITY, SECURITY_LEVEL_NUM)

EVENT_OPERATION_STARTED = "operation_started"
EVENT_OPERATION_COMPLETED = "operation_completed"
EVENT_OPERATION_FAILED = "operation_failed"
EVENT_OPERATION_CANCELLED = "operation_cancelled"
EVENT_OPERATION_SIMULATED = "operation_simulated"
EVENT_BACKUP_CREATED = "backup_created"
EVENT_RESTORE_EXECUTED = "restore_executed"
EVENT_CHANGE_APPLIED = "change_applied"
EVENT_INTERNAL_ERROR = "internal_error"
EVENT_EXPORT_COMPLETED = "export_completed"


@dataclass(slots=True)
class AuditConfig:
    file_path: Path = DEFAULT_AUDIT_LOG_PATH
    enable_syslog: bool = True
    file_level: int = logging.INFO
    syslog_level: int = logging.WARNING
    file_mode: str = "a"
    create_dirs: bool = True
    strict_redaction: bool = True
    include_technical_details: bool = True
    debug_tracebacks: bool = False
    syslog_address: str = "/dev/log"

@dataclass(slots=True)
class AuditEvent:
    timestamp: str
    level: str
    event_type: str
    action: str
    actor: str
    target: str
    result: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    impact: str = "none"
    dry_run: bool = False
    error_code: str | None = None

class JsonLineFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        if isinstance(record.msg, dict):
            return json.dumps(record.msg, ensure_ascii=False, sort_keys=True)
        return json.dumps({"message": str(record.msg)}, ensure_ascii=False)

class AuditLogger:
    def __init__(self, config: AuditConfig | None = None) -> None:
        self.config = config or AuditConfig()
        self._logger = logging.getLogger(AUDIT_LOGGER_NAME)
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False
        _register_security_level()
        self._setup_handlers()

    def log_operation_started(self, action: str, actor: str, target: str, *, params: Mapping[str, Any] | None = None, dry_run: bool = False) -> None:
        self._emit("INFO", EVENT_OPERATION_STARTED, action, actor, target, "success", "Operation started.", details=dict(params or {}), dry_run=dry_run)

    def log_operation_completed(self, action: str, actor: str, target: str, *, details: Mapping[str, Any] | None = None, warnings: list[str] | None = None, duration_ms: float | None = None) -> None:
        payload = dict(details or {})
        if warnings:
            payload["warnings"] = warnings
        if duration_ms is not None:
            payload["duration_ms"] = duration_ms
        self._emit("INFO", EVENT_OPERATION_COMPLETED, action, actor, target, "success", "Operation completed.", details=payload)
    
    def log_operation_failed(self, action: str, actor: str, target: str, *, error: str, error_code: str | None = None, details: Mapping[str, Any] | None = None) -> None:
        self._emit("ERROR", EVENT_OPERATION_FAILED, action, actor, target, "failed", error, details=dict(details or {}), error_code=error_code)

    def log_operation_cancelled(self, action: str, actor: str, target: str, *, error: str, error_code: str | None = None, details: Mapping[str, Any] | None = None) -> None:
        self._emit("WARNING", EVENT_OPERATION_CANCELLED, action, actor, target, "failed", error, details=dict(details or {}), error_code=error_code)

    def log_operation_partial(self, action: str, actor: str, target: str, *, message: str, details: Mapping[str, Any] | None = None) -> None:
        self._emit("WARNING", EVENT_CHANGE_APPLIED, action, actor, target, "partial", message, details=dict(details or {}))
    
    def log_security_event(self, action: str, actor: str, target: str, *, message: str, details: Mapping[str, Any] | None = None, result: str = "success") -> None:
        self._emit(LEVEL_SECURITY, EVENT_CHANGE_APPLIED, action, actor, target, result, message, details=dict(details or {}), impact="high")

    def log_password_changed(self, actor: str, username: str, *, forced_next_login: bool = False) -> None:
        self.log_security_event("change_password", actor, f"user:{username}", message="Password changed.", details={"forced_next_login": forced_next_login})

    def log_account_lock_state(self, actor: str, username: str, *, locked: bool, reason: str | None = None) -> None:
        action = "lock_user" if locked else "unlock_user"
        self.log_security_event(action, actor, f"user={username}", message=f"Account {'locked' if locked else 'unlocked'}.", details={"reason": reason} if reason else None)
    
    def log_domain_error(self, action: str, actor: str, target: str, err: UsrCtlError) -> None:
        payload = err.to_dict()
        self._emit("ERROR", EVENT_INTERNAL_ERROR, action, actor, target, "failed", payload.get("message", "Domain error."), details=payload.get("details", {}), error_code=payload.get("error_code"))
    
    def log_technical_error(self, action: str, actor: str, target: str, *, message: str, details: Mapping[str, Any] | None) -> None:
        self._emit("ERROR", EVENT_INTERNAL_ERROR, action, actor, target, "failed", message, details=dict(details or {}))

    def log_command_result(self, actor: str, result: SystemResult, *, include_output: bool = False) -> None:
        event = self._event_from_result(actor, result, include_output=include_output)
        self._dispatch(event)
    
    def log_critical_error(self, action:str, actor:str, target: str, *, message: str, details: Mapping[str, Any] | None = None) -> None:
        self._emit("CRITICAL", EVENT_INTERNAL_ERROR, action, actor, target, "failed", message, details=dict(details or {}), impact="critical")
    
    def log_dry_run(self, action: str, actor: str, target: str, *, project_command: str | list[str] | None = None, impact: str = "low", warnings: list[str] | None = None, validations: Mapping[str, Any] | None = None, confirmation_required: bool = False) -> None:
        details: dict[str, Any] = {
            "projected_command": project_command,
            "warnings": warnings or [],
            "validations": dict(validations or {}),
            "confirmation_required": confirmation_required
        }
        self._emit("INFO", EVENT_OPERATION_SIMULATED, action, actor, target, "simulated", "Dry-run simulation executed.", details=details, impact=impact, dry_run=True)

    def log_backup_event(self, action: str, actor: str, backup_id: str, *, result: str, message: str, details: Mapping[str, Any] | None = None) -> None:
        event_type = EVENT_BACKUP_CREATED if result == "success" else EVENT_OPERATION_FAILED
        self._emit("INFO" if result == "success" else "ERROR", event_type, action, actor, f"backup:{backup_id}", result, message, details=dict(details or {}), impact="high")

    def log_restore_event(self, actor: str, backup_id: str, *, result: str, message: str, details: Mapping[str, Any] | None = None) -> None:
        level = "INFO" if result in {"success", "partial"} else "CRITICAL"
        self._emit(level, EVENT_RESTORE_EXECUTED, "restore_backup", actor, f"backup:{backup_id}", result, message, details=dict(details or {}), impact="critical" )

    def log_report_export(self, actor: str, report_type: str, fmt: str, *, output_path: str, records: int | None = None, filters: Mapping[str, Any] | None = None, result: str = "success", message: str = "Report exported.") -> None:
        details: dict[str, Any] = {"format": fmt, "output_path": output_path, "records": records, "filters": dict(filters or {})}
        level = "INFO" if result in {"success", "partial"} else "CRITICAL"
        self._emit(level, EVENT_EXPORT_COMPLETED, "export_report", actor, f"report:{report_type}", result, message, details=details, impact="medium")

    def _setup_handlers(self) -> None:        
        formatter = JsonLineFormatter()

        for handler in list(self._logger.handlers):
            handler.close()
            self._logger.removeHandler(handler)

        file_path = self._ensure_log_path(self.config.file_path)
        file_handler = logging.FileHandler(file_path, mode=self.config.file_mode, encoding="utf-8")
        file_handler.setLevel(self.config.file_level)
        file_handler.setFormatter(formatter)
        self._logger.addHandler(file_handler)

        if self.config.enable_syslog:
            try:
                sys_handler = logging.handlers.SysLogHandler(address=self.config.syslog_address)
                sys_handler.setLevel(self.config.syslog_level)
                sys_handler.setFormatter(formatter)
                self._logger.addHandler(sys_handler)
            except OSError:
                self._logger.warning({"message": "syslog_unavailable", "logger": AUDIT_LOGGER_NAME})
  
    def _ensure_log_path(self, path: Path) -> Path:
        def _harden_permissions(file_path: Path) -> None:
            os.chmod(file_path, 0o600)

        try:
            if self.config.create_dirs:
                path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                path.touch(exist_ok=True)
            _harden_permissions(path)
            return path
        except OSError:
            fallback = FALLBACK_AUDIT_LOG_PATH
            if self.config.create_dirs:
                fallback.parent.mkdir(parents=True, exist_ok=True)
            if not fallback.exists():
                fallback.touch(exist_ok=True)
            _harden_permissions(fallback)
            return fallback
    
    def _event_from_result(self, actor: str, result: SystemResult, *, include_output: bool = False) -> AuditEvent:
        summary = result.to_log_record()
        if not include_output:
            summary.pop("stdout", None)
            summary.pop("stderr", None)
        if result.execution and not include_output:
            summary.pop("command", None)
        return self._build_event(
            level="INFO" if result.is_effectively_ok else "ERROR",
            event_type=EVENT_OPERATION_SIMULATED if result.is_simulated else (EVENT_OPERATION_COMPLETED if result.ok else EVENT_OPERATION_FAILED),
            action=result.action,
            actor=actor,
            target=result.target or "unknown",
            result="simulated" if result.is_simulated else ("success" if result.ok else "failed"),
            message=result.message or "System operation result.",
            details=summary,
            impact=result.impact.level.value,
            dry_run=result.dry_run
        )
    
    def _build_event(self, *, level: str, event_type: str, action: str, actor: str, target: str, result: str, message: str, details: Mapping[str, Any] | None = None, impact: str = "none", dry_run: bool = False, error_code: str | None = None) -> AuditEvent:
        normalized_action = self._normalize_action(action)
        normalized_impact = impact
        if normalized_action in SENSITIVE_EVENTS and impact == "none":
            normalized_impact = "high"
        
        return AuditEvent(
            timestamp=self._normalize_timestamp(),
            level=level,
            event_type=event_type,
            action=normalized_action,
            actor=actor,
            target=self._normalize_target(target),
            result=self._normalize_result(result),
            message=message,
            details=self._normalize_details(details),
            impact=normalized_impact,
            dry_run=dry_run,
            error_code=error_code,
                )
    
    def _emit(self, level: str, event_type: str, action: str, actor: str, target: str, result: str, message: str, *, details: Mapping[str, Any] | None = None, impact: str = "none", dry_run: bool = False, error_code: str | None = None) -> None:
        event = self._build_event(
            level=level,
            event_type=event_type,
            action=action,
            actor=actor,
            target=target,
            result=result,
            message=message,
            details=details,
            impact=impact,
            dry_run=dry_run,
            error_code=error_code
        )
        self._dispatch(event)
    
    def _dispatch(self, event: AuditEvent) -> None:
        payload = {field: getattr(event, field) for field in AUDIT_FIELDS}
        log_level = logging.getLevelName(event.level)
        if isinstance(log_level, str):
            log_level = SECURITY_LEVEL_NUM if event.level == LEVEL_SECURITY else logging.INFO
        self._logger.log(log_level, payload)
  
    def _normalize_timestamp(self, value: datetime | None = None) -> str:
          return (value or datetime.now(timezone.utc)).strftime(TIMESTAMP_FORMAT)
  
    def _normalize_action(self, action: str) -> str:
          return action.strip().lower().replace("-", "_").replace(" ", "_")   
    
    def _normalize_target(self, target: str) -> str:
        return target.strip()
    
    def _normalize_result(self, result: str) -> str:
        mapping = {"ok": "success", "failure": "failed", "canceled": "cancelled", "dry_run": "simulated"}
        value = result.strip().lower()
        return mapping.get(value, value)
    
    def _normalize_details(self, details: Mapping[str, Any] | None) -> dict[str, Any]:
        if not self.config.include_technical_details:
            return {}
        
        payload = dict(details or {})
        if not self.config.debug_tracebacks:
            payload.pop("traceback", None)
            payload.pop("exception", None)
        
        return self._sanitize_data(payload)

    def _sanitize_data(self, value: Any) -> Any:
        if isinstance(value, Mapping):
            clean: dict[str, Any] = {}
            for key, val in value.items():
                key_lower = str(key).lower()
                if self.config.strict_redaction and any(token in key_lower for token in SENSITIVE_KEYS):
                    clean[str(key)] = "[REDACTED]"
                else:
                    clean[str(key)] = self._sanitize_data(val)
            return clean
        
        if isinstance(value, list):
            return [self._sanitize_data(v) for v in value]
        if isinstance(value, tuple):
            return tuple(self._sanitize_data(v) for v in value)
        if self.config.strict_redaction and isinstance(value, str):
            if "shadow" in value.lower() or self._contains_sensitive_value(value):
                return "[REDACTED]"
        return value
    
    def _contains_sensitive_value(self, value: str) -> bool:
        return any(pattern.search(value) for pattern in VALUE_REDACTION_PATTERNS)
    
DEFAULT_AUDIT_LOGGER: AuditLogger | None = None

def get_default_audit_logger() -> AuditLogger:
    global DEFAULT_AUDIT_LOGGER
    if DEFAULT_AUDIT_LOGGER is None:
        DEFAULT_AUDIT_LOGGER = AuditLogger()
    return DEFAULT_AUDIT_LOGGER

__all__ = [
  "AUDIT_LOGGER_NAME",
  "AUDIT_FIELDS",
  "SENSITIVE_EVENTS",
  "SENSITIVE_KEYS",
  "AuditConfig",
  "AuditLogger",
  "DEFAULT_AUDIT_LOGGER",
  "get_default_audit_logger"
]