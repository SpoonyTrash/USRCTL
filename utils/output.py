from __future__ import annotations

from dataclasses import dataclass
import json
import re
import sys
from typing import Any, Mapping, Sequence

from utils.errors import UsrCtlError
from system.result import ImpactLevel, ResultStatus, SystemResult

PREFIX_SUCCESS = "[+]"
PREFIX_ERROR = "[x]"
PREFIX_WARNING = "[!]"
PREFIX_INFO = "[i]"
PREFIX_DRY_RUN = "[~]"
PREFIX_NOTE = "[>]"
PREFIX_CRITICAL = "[!!]"

STATUS_OK = "OK"
STATUS_ERROR = "ERROR"
STATUS_WARNING = "WARNING"
STATUS_INFO = "INFO"
STATUS_DRY_RUN = "DRY-RUN"
STATUS_PARTIAL = "PARTIAL"
STATUS_SKIPPED = "SKIPPED"

SEPARATOR_HEADER = "="
SEPARATOR_SECTION = "-"
SEPARATOR_SUMMARY = "_"
BLOCK_WIDTH = 80
INDENT = "  "
BULLET = "-"

VERB_CREATED = "Created"
VERB_DELETED = "Deleted"
VERB_UPDATED = "Updated"
VERB_VALIDATED = "Validated"
VERB_SKIPPED = "Skipped"
VERB_SIMULATED = "Simulated"

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "token",
    "secret",
    "shadow",
    "stdin",
    "private_key",
}
SENSITIVE_PATTERNS = [
    re.compile(r"(?i)password\s*=\s*\S+"),
    re.compile(r"(?i)token\s*=\s*\S+"),
    re.compile(r"(?i)secret\s*=\s*\S+"),
]
MAX_TEXT_LENGTH = 600

@dataclass(slots=True)
class OutputConfig:
    quiet: bool = False
    verbose: bool = False
    debug: bool = False
    use_color: bool = False
    default_detail_level: str = "normal"
    out_stream: Any = sys.stdout
    err_stream: Any = sys.stderr

CLI_STYLE_GUIDE = {
    "tone": "clear, direct, technical, and unambiguous",
    "length": "brief main message + details in secondary blocks",
    "order": [
        "general status",
        "action",
        "affected resource",
        "brief detail",
        "warnings",
        "optional technical details",
    ],
    "security": "never expose secrets or sensitive data",
    "consistency": "same type of event => same visual format",
}

class CliOutput:
    def __init__(self, config: OutputConfig | None = None) -> None:
        self.config = config or OutputConfig()

    def info(self, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        self._emit(PREFIX_INFO, message, details=details)

    def success(self, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        self._emit(PREFIX_SUCCESS, message, details=details)

    def warning(self, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        self._emit(PREFIX_WARNING, message, details=details)

    def note(self, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        self._emit(PREFIX_NOTE, message, details=details)

    def error(self, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        self._emit(PREFIX_ERROR, message, details=details, is_error=True)

    def status_completed(self, action: str, target: str | None = None, message: str = "") -> None:
        self._print_status_line(STATUS_OK, action, target, message, PREFIX_SUCCESS)

    def status_partial(self, action: str, target: str | None = None, message: str = "") -> None:
        self._print_status_line(STATUS_PARTIAL, action, target, message, PREFIX_WARNING)

    def status_skipped(self, action: str, target: str | None = None, message: str = "") -> None:
        self._print_status_line(STATUS_SKIPPED, action, target, message, PREFIX_NOTE)

    def status_dry_run(self, action: str, target: str | None = None, message: str = "") -> None:
        self._print_status_line(STATUS_DRY_RUN, action, target, message, PREFIX_DRY_RUN)

    def status_critical(self, action: str, target: str | None = None, message: str = "") -> None:
        self._print_status_line(STATUS_WARNING, action, target, message, PREFIX_CRITICAL, is_error=True)

    def print_error_simple(self, message: str) -> None:
        self.error(message)

    def print_domain_error(self, err: UsrCtlError) -> None:
        payload = self._from_domain_error(err)
        header = f"{payload['message']} ({payload['error_code']})"
        self.error(header)

        if payload.get("hint"):
            self.note(f"Hint: {payload['hint']}")

        if self.config.verbose and payload.get("details"):
            self._emit(PREFIX_INFO, "Details:", details=payload["details"], is_error=True)

        if self.config.debug and payload.get("cause"):
            self._emit(PREFIX_INFO, f"Cause: {payload['cause']}", is_error=True)

    def print_exception(self, err: Exception, *, hint: str | None = None) -> None:
        self.error(str(err))
        if hint:
            self.note(f"Hint: {hint}")
        if self.config.debug and getattr(err, "__cause__", None):
            self._emit(PREFIX_INFO, f"Cause: {err.__cause__}", is_error=True)

    # Métodos públicos de impresión de resultados
    def print_result_summary(self, result: SystemResult) -> None:
        normalized = self._from_system_result(result)
        self._print_status_line(
            normalized["status_label"],
            normalized["action"],
            normalized.get("target"),
            normalized.get("message", ""),
            normalized["prefix"],
            is_error=normalized["is_error"],
        )

    def print_result_detailed(self, result: SystemResult) -> None:
        self.print_result_summary(result)
        self._print_result_complements(result)
    
    def _print_result_complements(self, result: SystemResult) -> None:


        if result.warnings:
            self.warning("Warnings", details={"items": result.warnings})

        if result.impact.affected_resources:
            self.info("Affected resources", details={"items": result.impact.affected_resources})

        if result.changed and result.impact.applied_resources:
            self.success("Applied resources", details={"items": result.impact.applied_resources})

        if self.config.verbose and result.details:
            self.info("Details", details=result.details)

        if self.config.debug and result.execution:
            execution_payload = {
                "command": result.execution.command,
                "return_code": result.execution.return_code,
                "duration_ms": result.execution.duration_ms,
                "operation_id": result.execution.operation_id,
            }
            self.info("Technical summary", details=execution_payload)

    def print_result_partial(self, result: SystemResult) -> None:
        self.status_partial(result.action, result.target, result.message)
        self._print_result_complements(result)

    def print_result_no_changes(self, result: SystemResult) -> None:
        msg = result.message or "Valid operation with no changes applied"
        self.status_skipped(result.action, result.target, msg)

    def print_technical_result(self, title: str, payload: Mapping[str, Any]) -> None:
        if not (self.config.verbose or self.config.debug):
            return
        self.info(title, details=dict(payload))

    # Métodos públicos de impresión tabular o listados
    def print_list(self, title: str, items: Sequence[Any]) -> None:
        self._print_header(title)
        if not items:
            self.print_empty_section("No results")
            return

        for item in items:
            line = self._stringify(item)
            self._write(f"{INDENT}{BULLET} {line}")

        self.print_collection_summary(count=len(items))

    def print_table(self, title: str, columns: Sequence[str], rows: Sequence[Sequence[Any]]) -> None:
        self._print_header(title)
        if not rows:
            self.print_empty_section("No results")
            return

        widths = [len(col) for col in columns]
        normalized_rows = [[self._stringify(cell) for cell in row] for row in rows]
        for row in normalized_rows:
            for idx, cell in enumerate(row):
                widths[idx] = max(widths[idx], len(cell))

        header = " | ".join(col.ljust(widths[idx]) for idx, col in enumerate(columns))
        separator = "-+-".join(SEPARATOR_SECTION * widths[idx] for idx in range(len(columns)))
        self._write(f"{INDENT}{header}")
        self._write(f"{INDENT}{separator}")
        for row in normalized_rows:
            self._write(f"{INDENT}" + " | ".join(cell.ljust(widths[idx]) for idx, cell in enumerate(row)))

        self.print_collection_summary(count=len(rows))

    def print_entity_detail(self, title: str, detail: Mapping[str, Any]) -> None:
        self._print_header(title)
        if not detail:
            self.print_empty_section("No details")
            return
        for key, value in detail.items():
            self._write(f"{INDENT}{key}: {self._stringify(value)}")

    def print_empty_section(self, message: str = "No data") -> None:
        self.note(message)

    def print_collection_summary(self, *, count: int, label: str = "elements") -> None:
        self._write(SEPARATOR_SUMMARY * BLOCK_WIDTH)
        self._write(f"{INDENT}Total {label}: {count}")

    def print_dry_run_message(self, action: str, target: str | None = None, message: str = "") -> None:
        base = message or "Simulation executed: no real changes were applied"
        self.status_dry_run(action, target, base)

    def print_projected_command(self, command: str | Sequence[str], *, safe: bool = True) -> None:
        if not safe:
            self.warning("Command projection hidden for security reasons")
            return
        rendered = command if isinstance(command, str) else " ".join(command)
        self._emit(PREFIX_DRY_RUN, f"Command projection: {self._sanitize_text(rendered)}")

    def print_expected_impact(self, level: ImpactLevel | str, resources: Sequence[str] | None = None) -> None:
        level_value = level.value if isinstance(level, ImpactLevel) else str(level)
        self._emit(PREFIX_DRY_RUN, f"Expected impact: {level_value.upper()}")
        if resources:
            self.info("Potentially affected resources", details={"items": list(resources)})

    def print_preventive_warnings(self, warnings: Sequence[str]) -> None:
        if not warnings:
            return
        self.warning("Preventive warnings", details={"items": list(warnings)})

    def print_confirmation_required(self, reason: str | None = None) -> None:
        msg = reason or "This operation requires explicit confirmation"
        self._emit(PREFIX_CRITICAL, msg)

    def print_export_success(
        self,
        *,
        file_path: str,
        fmt: str,
        records: int,
        warnings: Sequence[str] | None = None,
    ) -> None:
        self.success(
            "Export completed",
            details={
                "format": fmt,
                "path": file_path,
                "records": records,
            },
        )
        if warnings:
            self.warning("Export warnings", details={"items": list(warnings)})

    def print_export_error(self, message: str, *, fmt: str | None = None, file_path: str | None = None) -> None:
        details: dict[str, Any] = {}
        if fmt:
            details["format"] = fmt
        if file_path:
            details["path"] = file_path
        self.error(message, details=details or None)

    def print_export_partial(
        self,
        *,
        file_path: str,
        fmt: str,
        records: int,
        failed: int,
        warnings: Sequence[str] | None = None,
    ) -> None:
        self.status_partial(
            action="export",
            target=file_path,
            message=f"{records} records exported, {failed} failed",
        )
        self.info("Summary", details={"format": fmt, "records_ok": records, "records_error": failed})
        if warnings:
            self.warning("Warnings", details={"items": list(warnings)})

    # Métodos internos de normalización de mensajes
    def _normalize_message(self, message: str) -> str:
        normalized = " ".join((message or "").strip().split())
        return normalized

    def _build_block_header(self, title: str) -> str:
        safe_title = self._normalize_message(title)
        line = f" {safe_title} "
        return line.center(BLOCK_WIDTH, SEPARATOR_HEADER)

    def _format_details(self, details: Mapping[str, Any]) -> list[str]:
        lines: list[str] = []
        for key, value in details.items():
            if key == "items" and isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                lines.append(f"{INDENT}{key}:")
                for item in value:
                    lines.append(f"{INDENT}{INDENT}{BULLET} {self._stringify(item)}")
                continue
            lines.append(f"{INDENT}{key}: {self._stringify(value)}")
        return lines

    def _stringify(self, value: Any) -> str:
        if isinstance(value, (dict, list, tuple, set)):
            return self._truncate(self._sanitize_text(json.dumps(value, ensure_ascii=False, default=str)))
        return self._truncate(self._sanitize_text(str(value)))

    # Métodos internos de saneamiento de salida
    def _sanitize_mapping(self, data: Mapping[str, Any]) -> dict[str, Any]:
        safe: dict[str, Any] = {}
        for key, value in data.items():
            if key.lower() in SENSITIVE_KEYS:
                safe[key] = "***"
                continue
            if isinstance(value, Mapping):
                safe[key] = self._sanitize_mapping(value)
            elif isinstance(value, (list, tuple)):
                safe[key] = [self._sanitize_text(str(v)) for v in value]
            else:
                safe[key] = self._sanitize_text(str(value))
        return safe

    def _sanitize_text(self, text: str) -> str:
        result = text
        for pattern in SENSITIVE_PATTERNS:
            result = pattern.sub("***", result)
        return result.replace("\n", " ").strip()

    def _truncate(self, text: str, *, max_len: int = MAX_TEXT_LENGTH) -> str:
        if len(text) <= max_len:
            return text
        return f"{text[: max_len - 3]}..."

    # Conversión desde errores y resultados del dominio
    def _from_domain_error(self, err: UsrCtlError) -> dict[str, Any]:
        payload = err.to_dict()
        details = payload.get("details") or {}
        payload["details"] = self._sanitize_mapping(details)
        return payload

    def _from_system_result(self, result: SystemResult) -> dict[str, Any]:
        mapping: dict[ResultStatus, tuple[str, str, bool]] = {
            ResultStatus.SUCCESS: (STATUS_OK, PREFIX_SUCCESS, False),
            ResultStatus.FAILURE: (STATUS_ERROR, PREFIX_ERROR, True),
            ResultStatus.DRY_RUN: (STATUS_DRY_RUN, PREFIX_DRY_RUN, False),
            ResultStatus.PARTIAL: (STATUS_PARTIAL, PREFIX_WARNING, False),
            ResultStatus.SKIPPED: (STATUS_SKIPPED, PREFIX_NOTE, False),
        }
        status_label, prefix, is_error = mapping[result.status]
        return {
            "status_label": status_label,
            "prefix": prefix,
            "is_error": is_error,
            "action": result.action,
            "target": result.target,
            "message": result.message,
        }

    # Convenciones internas del módulo
    def _emit(
        self,
        prefix: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
        is_error: bool = False,
    ) -> None:
        if self.config.quiet and not is_error:
            return

        normalized_message = self._normalize_message(message)
        self._write(f"{prefix} {normalized_message}", is_error=is_error)

        if details and (self.config.verbose or self.config.debug):
            safe_details = self._sanitize_mapping(details)
            for line in self._format_details(safe_details):
                self._write(line, is_error=is_error)

    def _print_header(self, title: str) -> None:
        self._write(self._build_block_header(title))

    def _print_status_line(
        self,
        status: str,
        action: str,
        target: str | None,
        message: str,
        prefix: str,
        *,
        is_error: bool = False,
    ) -> None:
        pieces = [f"[{status}]", self._normalize_message(action)]
        if target:
            pieces.append(f"target={self._sanitize_text(target)}")
        if message:
            pieces.append(self._normalize_message(message))
        self._emit(prefix, " | ".join(pieces), is_error=is_error)

    def _write(self, text: str, *, is_error: bool = False) -> None:
        stream = self.config.err_stream if is_error else self.config.out_stream
        print(text, file=stream)


# Exportaciones públicas del módulo
DEFAULT_OUTPUT = CliOutput()

__all__ = [
    "CliOutput",
    "OutputConfig",
    "DEFAULT_OUTPUT",
    "CLI_STYLE_GUIDE",
    "PREFIX_SUCCESS",
    "PREFIX_ERROR",
    "PREFIX_WARNING",
    "PREFIX_INFO",
    "PREFIX_DRY_RUN",
    "PREFIX_NOTE",
    "PREFIX_CRITICAL",
]