from enum import Enum
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Mapping, Sequence
from uuid import uuid4

from utils.errors import ReportError, ValidationError

COMMON_REPORT_STATUSES = frozenset({"requested", "generated", "empty", "partial", "failed", "exported"})
COMMON_REPORT_COLUMNS = (
    "username",
    "uid",
    "gid",
    "groupname",
    "status",
    "shell",
    "home",
    "is_sudo",
    "expires_at",
    "created_at",
    "result",
)
DEFAULT_COLUMN_TYPE = "type"

SENSITIVE_FIELD_NAMES = frozenset(
    {"password", "passwd", "hash", "secret", "token", "credential", "credentials"}
)
SUPPORTED_REPORT_FORMATS = frozenset({"table", "json", "csv", "summary", "internal"})
SUPPORTED_REPORT_TYPES = frozenset(
    {
        "users",
        "user_detail",
        "groups",
        "group_members",
        "active_users",
        "locked_users",
        "sudo_users",
        "policies",
        "backups",
        "audit",
        "permissions",
        "limits",
        "security",
        "combined",
    }
)

class ReportType(str, Enum):
    USERS = "users"
    USER_DETAIL = "user_detail"
    GROUPS = "groups"
    GROUP_MEMBERS = "group_members"
    ACTIVE_USERS = "active_users"
    LOCKED_USERS = "locked_users"
    SUDO_USERS = "sudo_users"
    POLICIES = "policies"
    SECURITY = "security"
    BACKUPS = "backups"
    AUDIT = "audit"
    PERMISSIONS = "permissions"
    LIMITS = "limits"
    COMBINED = "combined"

class ReportFormat(str, Enum):
    TABLE = "table"
    JSON = "json"
    CSV = "csv"
    SUMMARY = "summary"
    INTERNAL = "internal"

class ReportStatus (str, Enum):
    REQUESTED = "requested"
    GENERATED = "generated"
    EMPTY = "empty"
    PARTIAL = "partial"
    FAILED = "failed"
    EXPORTED = "exported"

class SensitivityLevel(str, Enum):
    PUBLIC = "public_operational"
    ADMINISTRATIVE = "administrative"
    SENSITIVE = "sensitive"
    CRITICAL = "critical"

class SortDirection(str, Enum):
    NONE = "none"
    ASC = "asc"
    DESC = "desc"

class ReportOrigin(str, Enum):
    CURRENT_SYSTEM = "current_system"
    BACKUP = "backup"
    AUDIT = "audit"
    TEMPLATE = "template"
    INTERNAL_SERVICE = "internal_service"
    DRY_RUN = "dry_run"
    TEST = "test"

@dataclass(slots=True)
class ReportColumn:
    name: str
    label: str | None = None
    data_type: str = DEFAULT_COLUMN_TYPE
    sensitive: bool = False
    exportable: bool = True
    order: int = 0
    description: str | None = None

    def __post_init__(self) -> None:
        self.name = _require_text(self.name, "column name")
        self.label = self.label or self.name.replace("_", " ").title()
        self.sensitive = (
            _coerce_bool(self.sensitive, field_name="sensitive", default=False)
            or _is_sensitive_key(self.name)
        )
        self.exportable = _coerce_bool(
            self.exportable,
            field_name="exportable",
            default=True,
        )
        self.order = _coerce_non_negative_int(self.order, "column order")

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(
            {
                "name": self.name,
                "label": self.label,
                "data_type": self.data_type,
                "sensitive": self.sensitive,
                "exportable": self.exportable,
                "order": self.order,
                "description": self.description,
            }
        )

@dataclass(slots=True)
class ReportRow:
    data: dict[str, Any]
    resource_id: str | None = None
    resource_type: str | None = None
    sensitivity: SensitivityLevel | str = SensitivityLevel.PUBLIC
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.data = dict(self.data or {})
        self.sensitivity = _enum_value(SensitivityLevel, self.sensitivity, "sensitivity")
        self.warnings = _coerce_text_list(self.warnings, "row warnings")
        self.metadata = _safe_mapping(self.metadata, "row metadata")
    
    @property
    def contains_sensitive_data(self) -> bool:
        return self.sensitivity in {SensitivityLevel.SENSITIVE, SensitivityLevel.CRITICAL} or any(
            _is_sensitive_key(key) for key in self.data
        )
    
    def to_dict(self) -> dict[str, Any]:
        return _json_ready(
            {
                "data": self.data,
                "resource_id": self.resource_id,
                "resource_type": self.resource_type,
                "sensitivity": self.sensitivity,
                "warnings": self.warnings,
                "metadata": self.metadata,
            }
        )

    def safe_data(self, include_sensitive: bool = False) -> dict[str, Any]:
        if include_sensitive:
            return _json_ready(self.data)
        return {key: ("<redacted>" if _is_sensitive_key(key) else _json_ready(value)) for key, value in self.data.items()}

@dataclass(slots=True)
class ReportSection:
    title: str
    description: str | None = None
    columns: list[ReportColumn] = field(default_factory=list)
    rows: list[ReportRow] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.title = _require_text(self.title, "section title")
        self.columns = [_coerce_column(column) for column in self.columns]
        self.rows = [_coerce_row(row) for row in self.rows]
        self.summary = _safe_mapping(self.summary, "section summary")
        self.warnings = _coerce_text_list(self.warnings, "section warnings")
        _validate_row_columns(self.columns, self.rows, allow_extra=True)

    @property
    def is_empty(self) -> bool:
        return not self.rows

    @property
    def contains_sensitive_data(self) -> bool:
        return any(column.sensitive for column in self.columns) or any(row.contains_sensitive_data for row in self.rows)

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(
            {
                "title": self.title,
                "description": self.description,
                "columns": [column.to_dict() for column in self.columns],
                "rows": [row.to_dict() for row in self.rows],
                "summary": self.summary,
                "warnings": self.warnings,
            }
        )
    
    def to_export_dict(self, include_sensitive: bool = False) -> dict[str, Any]:
        exportable_columns = [column for column in self.columns if column.exportable]
        allowed = {column.name for column in exportable_columns}

        rows: list[dict[str, Any]] = []

        for row in self.rows:
            data = row.safe_data(include_sensitive=include_sensitive)
            rows.append(
                {
                    key: value
                    for key, value in data.items()
                    if not allowed or key in allowed
                }
            )

        return _json_ready(
            {
                "title": self.title,
                "description": self.description,
                "columns": [column.to_dict() for column in exportable_columns],
                "rows": rows,
                "summary": self.summary,
                "warnings": self.warnings,
            }
        )

@dataclass(slots=True)
class ReportFilters:
    resource_type: str | None = None
    status: str | None = None
    target_user: str | None = None
    target_group: str | None = None
    date_from: date | datetime | None = None
    date_to: date | datetime | None = None
    include_system: bool = False
    include_sensitive: bool = False
    selected_fields: list[str] = field(default_factory=list)
    sort_by: str | None = None
    sort_direction: SortDirection | str = SortDirection.NONE
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.sort_direction = _enum_value(SortDirection, self.sort_direction, "sort_direction")
        self.include_system = _coerce_bool(
            self.include_system,
            field_name="include_system",
            default=False,
        )
        self.include_sensitive = _coerce_bool(
            self.include_sensitive,
            field_name="include_sensitive",
            default=False,
        )
        self.selected_fields = _coerce_text_list(
            self.selected_fields,
            "selected_fields",
        )        
        self.metadata = _safe_mapping(self.metadata, "filter metadata")
        self.date_from = _coerce_date_or_datetime(self.date_from, "date_from")
        self.date_to = _coerce_date_or_datetime(self.date_to, "date_to")
        if self.date_from and self.date_to and self.date_from > self.date_to:
            raise ValidationError("Report filter date_from cannot be later than date_to.")

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(
            {
                "resource_type": self.resource_type,
                "status": self.status,
                "target_user": self.target_user,
                "target_group": self.target_group,
                "date_from": self.date_from,
                "date_to": self.date_to,
                "include_system": self.include_system,
                "include_sensitive": self.include_sensitive,
                "selected_fields": self.selected_fields,
                "sort_by": self.sort_by,
                "sort_direction": self.sort_direction,
                "metadata": self.metadata,
            }
        )

@dataclass(slots=True)
class ReportRequest:
    report_type: ReportType | str
    format: ReportFormat | str = ReportFormat.INTERNAL
    filters: ReportFilters = field(default_factory=ReportFilters)
    requested_fields: list[str] = field(default_factory=list)
    include_details: bool = False
    include_sensitive: bool = False
    export_path: str | None = None
    dry_run: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.report_type = _enum_value(ReportType, self.report_type, "report_type")
        self.format = _enum_value(ReportFormat, self.format, "format")
        self.filters = _coerce_filters(self.filters)
        self.include_details = _coerce_bool(
            self.include_details,
            field_name="include_details",
            default=False,
        )
        self.include_sensitive = _coerce_bool(
            self.include_sensitive,
            field_name="include_sensitive",
            default=False,
        )
        self.dry_run = _coerce_bool(
            self.dry_run,
            field_name="dry_run",
            default=False,
        )
        self.requested_fields = _coerce_text_list(
            self.requested_fields,
            "requested_fields",
        )        
        self.metadata = _safe_mapping(self.metadata, "request metadata")
        if self.include_sensitive:
            self.filters.include_sensitive = True
        if self.export_path is not None and not str(self.export_path).strip():
            raise ValidationError("Report export_path cannot be blank.")

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(
            {
                "report_type": self.report_type,
                "format": self.format,
                "filters": self.filters.to_dict(),
                "requested_fields": self.requested_fields,
                "include_details": self.include_details,
                "include_sensitive": self.include_sensitive,
                "export_path": self.export_path,
                "dry_run": self.dry_run,
                "metadata": self.metadata,
            }
        )

@dataclass(slots=True)
class Report:
    report_id: str = field(default_factory=lambda: f"report-{uuid4().hex}")
    name: str = "usrctl report"
    report_type: ReportType | str = ReportType.COMBINED
    status: ReportStatus | str = ReportStatus.GENERATED
    format: ReportFormat | str = ReportFormat.INTERNAL
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    columns: list[ReportColumn] = field(default_factory=list)
    rows: list[ReportRow] = field(default_factory=list)
    sections: list[ReportSection] = field(default_factory=list)
    filters: ReportFilters = field(default_factory=ReportFilters)
    summary: "ReportSummary | None" = None
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.report_id = _require_text(self.report_id, "report_id")
        self.name = _require_text(self.name, "report name")
        self.report_type = _enum_value(ReportType, self.report_type, "report_type")
        self.status = _enum_value(ReportStatus, self.status, "status")
        self.format = _enum_value(ReportFormat, self.format, "format")
        self.columns = [_coerce_column(column) for column in self.columns]
        self.rows = [_coerce_row(row) for row in self.rows]
        self.sections = [_coerce_section(section) for section in self.sections]
        self.filters = _coerce_filters(self.filters)
        self.summary = _coerce_summary(self.summary) if self.summary is not None else ReportSummary.from_report(self)
        self.warnings =  _coerce_text_list(self.warnings, "report warnings")
        self.metadata = _safe_mapping(self.metadata, "report metadata")
        _validate_row_columns(self.columns, self.rows, allow_extra=True)
        self.validate()

    @property
    def is_empty(self) -> bool:
        return not self.rows and all(section.is_empty for section in self.sections)

    @property
    def is_partial(self) -> bool:
        return self.status == ReportStatus.PARTIAL

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings or any(section.warnings for section in self.sections) or any(row.warnings for row in self.rows))

    @property
    def contains_sensitive_data(self) -> bool:
        return (
            self.filters.include_sensitive
            or any(column.sensitive for column in self.columns)
            or any(row.contains_sensitive_data for row in self.rows)
            or any(section.contains_sensitive_data for section in self.sections)
        )

    @property
    def is_exportable(self) -> bool:
        return self.format in {ReportFormat.CSV, ReportFormat.JSON, ReportFormat.TABLE, ReportFormat.INTERNAL} and bool(
            self.columns or self.sections or self.rows
        )

    @property
    def total_rows(self) -> int:
        return len(self.rows) + sum(len(section.rows) for section in self.sections)

    @property
    def requires_elevated_permissions(self) -> bool:
        return self.contains_sensitive_data or self.report_type in {
            ReportType.SUDO_USERS,
            ReportType.SECURITY,
            ReportType.AUDIT,
            ReportType.PERMISSIONS,
            ReportType.BACKUPS,
        }

    def validate(self) -> None:
        if self.report_type.value not in SUPPORTED_REPORT_TYPES:
            raise ReportError("Unsupported report type.", details={"report_type": self.report_type.value})
        if self.format.value not in SUPPORTED_REPORT_FORMATS:
            raise ReportError("Unsupported report format.", details={"format": self.format.value})
        if self.status.value not in COMMON_REPORT_STATUSES:
            raise ReportError("Unsupported report status.", details={"status": self.status.value})
        _json_ready(self.filters.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(
            {
                "report_id": self.report_id,
                "name": self.name,
                "report_type": self.report_type,
                "status": self.status,
                "format": self.format,
                "generated_at": self.generated_at,
                "columns": [column.to_dict() for column in self.columns],
                "rows": [row.to_dict() for row in self.rows],
                "sections": [section.to_dict() for section in self.sections],
                "filters": self.filters.to_dict(),
                "summary": self.summary.to_dict() if self.summary else None,
                "warnings": self.warnings,
                "metadata": self.metadata,
            }
        )

    def to_audit_dict(self, export_path: str | None = None) -> dict[str, Any]:
        return _json_ready(
            {
                "report_id": self.report_id,
                "name": self.name,
                "report_type": self.report_type,
                "status": self.status,
                "format": self.format,
                "filters": self.filters.to_dict(),
                "record_count": self.total_rows,
                "contains_sensitive_data": self.contains_sensitive_data,
                "export_path": export_path,
                "generated_at": self.generated_at,
            }
        )

    def to_export_payload(self, include_sensitive: bool = False) -> dict[str, Any]:
        exportable_columns = [column for column in self.columns if column.exportable]
        allowed = {column.name for column in exportable_columns}
        rows = []
        for row in self.rows:
            data = row.safe_data(include_sensitive=include_sensitive)
            rows.append({key: value for key, value in data.items() if not allowed or key in allowed})
        return _json_ready(
            {
                "columns": [column.to_dict() for column in exportable_columns],
                "rows": rows,
                "sections": [
                    section.to_export_dict(include_sensitive=include_sensitive)
                    for section in self.sections
                ],                "metadata": self.metadata,
                "summary": self.summary.to_dict() if self.summary else None,
            }
        )

    def to_summary_dict(self) -> dict[str, Any]:
        return _json_ready(
            {
                "name": self.name,
                "report_type": self.report_type,
                "total_records": self.total_rows,
                "status": self.status,
                "warnings": len(self.warnings),
                "format": self.format,
            }
        )


@dataclass(slots=True)
class ReportSummary:
    total_records: int = 0
    filtered_records: int = 0
    omitted_records: int = 0
    counts_by_status: dict[str, int] = field(default_factory=dict)
    counts_by_severity: dict[str, int] = field(default_factory=dict)
    warning_count: int = 0
    warning_summary: list[str] = field(default_factory=list)
    is_empty: bool = True

    def __post_init__(self) -> None:
        self.total_records = _coerce_non_negative_int(
            self.total_records,
            "total_records",
        )
        self.filtered_records = _coerce_non_negative_int(
            self.filtered_records,
            "filtered_records",
        )
        self.omitted_records = _coerce_non_negative_int(
            self.omitted_records,
            "omitted_records",
        )
        self.warning_count = _coerce_non_negative_int(
            self.warning_count,
            "warning_count",
        )

        self.counts_by_status = {
            str(key): _coerce_non_negative_int(value, f"counts_by_status[{key}]")
            for key, value in self.counts_by_status.items()
        }

        self.counts_by_severity = {
            str(key): _coerce_non_negative_int(value, f"counts_by_severity[{key}]")
            for key, value in self.counts_by_severity.items()
        }

        self.warning_summary = _coerce_text_list(
            self.warning_summary,
            "warning_summary",
        )

    @classmethod
    def from_report(cls, report: Report) -> "ReportSummary":
        warnings = list(report.warnings)
        for section in report.sections:
            warnings.extend(section.warnings)
        for row in report.rows:
            warnings.extend(row.warnings)
        return cls(
            total_records=report.total_rows,
            filtered_records=report.total_rows,
            warning_count=len(warnings),
            warning_summary=warnings[:10],
            is_empty=report.is_empty,
        )

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(
            {
                "total_records": self.total_records,
                "filtered_records": self.filtered_records,
                "omitted_records": self.omitted_records,
                "counts_by_status": self.counts_by_status,
                "counts_by_severity": self.counts_by_severity,
                "warning_count": self.warning_count,
                "warning_summary": self.warning_summary,
                "is_empty": self.is_empty,
            }
        )

@dataclass(slots=True)
class ReportExportSpec:
    format: ReportFormat | str
    destination_path: str
    include_headers: bool = True
    include_metadata: bool = True
    include_sensitive: bool = False
    overwrite: bool = False
    dry_run: bool = False

    def __post_init__(self) -> None:
        self.format = _enum_value(ReportFormat, self.format, "format")
        self.destination_path = _require_text(self.destination_path, "destination_path")
        self.include_headers = _coerce_bool(
            self.include_headers,
            field_name="include_headers",
            default=True,
        )
        self.include_metadata = _coerce_bool(
            self.include_metadata,
            field_name="include_metadata",
            default=True,
        )
        self.include_sensitive = _coerce_bool(
            self.include_sensitive,
            field_name="include_sensitive",
            default=False,
        )
        self.overwrite = _coerce_bool(
            self.overwrite,
            field_name="overwrite",
            default=False,
        )
        self.dry_run = _coerce_bool(
            self.dry_run,
            field_name="dry_run",
            default=False,
        )
        if self.format not in {ReportFormat.JSON, ReportFormat.CSV, ReportFormat.SUMMARY, ReportFormat.TABLE}:
            raise ValidationError("Export format must be JSON, CSV, summary or table.")

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(
            {
                "format": self.format,
                "destination_path": self.destination_path,
                "include_headers": self.include_headers,
                "include_metadata": self.include_metadata,
                "include_sensitive": self.include_sensitive,
                "overwrite": self.overwrite,
                "dry_run": self.dry_run,
            }
        )

@dataclass(slots=True)
class ReportExportResult:
    format: ReportFormat | str
    output_path: str | None = None
    record_count: int = 0
    status: ReportStatus | str = ReportStatus.EXPORTED
    warnings: list[str] = field(default_factory=list)
    approximate_size_bytes: int | None = None
    changes_applied: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.format = _enum_value(ReportFormat, self.format, "format")
        self.status = _enum_value(ReportStatus, self.status, "status")
        if self.record_count < 0:
            raise ValidationError("Export record_count cannot be negative.")
        self.changes_applied = _coerce_bool(
            self.changes_applied,
            field_name="changes_applied",
            default=False,
        )
        self.warnings = _coerce_text_list(self.warnings, "export result warnings")
        self.metadata = _safe_mapping(self.metadata, "export result metadata")

    def to_dict(self) -> dict[str, Any]:
        return _json_ready(
            {
                "format": self.format,
                "output_path": self.output_path,
                "record_count": self.record_count,
                "status": self.status,
                "warnings": self.warnings,
                "approximate_size_bytes": self.approximate_size_bytes,
                "changes_applied": self.changes_applied,
                "metadata": self.metadata,
            }
        )


def _enum_value(enum_type: type[Enum], value: Enum | str, field_name: str) -> Any:
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(str(value))
    except ValueError as exc:
        raise ValidationError(f"Invalid report {field_name}: {value!r}.") from exc
    
def _validate_row_columns(columns: Sequence[ReportColumn], rows: Sequence[ReportRow], *, allow_extra: bool) -> None:
    if not columns or allow_extra:
        return
    allowed = {column.name for column in columns}
    for row in rows:
        unknown = set(row.data) - allowed
        if unknown:
            raise ValidationError("Report row contains fields not declared as columns.", details={"unknown": sorted(unknown)})

def _json_ready(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_ready(item) for item in value]
    return value

def report_from_records(
    *,
    name: str,
    report_type: ReportType | str,
    records: Sequence[Mapping[str, Any] | Any],
    columns: Sequence[str | ReportColumn] | None = None,
    format: ReportFormat | str = ReportFormat.INTERNAL,
    filters: ReportFilters | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> Report:
    raw_rows = [_record_to_mapping(record) for record in records]
    report_columns = _columns_from_records(raw_rows, columns)
    rows = [ReportRow(data=dict(row), resource_id=_guess_resource_id(row), resource_type=str(report_type)) for row in raw_rows]
    status = ReportStatus.EMPTY if not rows else ReportStatus.GENERATED
    return Report(
        name=name,
        report_type=report_type,
        status=status,
        format=format,
        columns=report_columns,
        rows=rows,
        filters=filters or ReportFilters(resource_type=str(_json_ready(report_type))),
        metadata=dict(metadata or {}),
    )

def users_report(users: Sequence[Mapping[str, Any] | Any], **kwargs: Any) -> Report:
    return report_from_records(name=kwargs.pop("name", "Users report"), report_type=ReportType.USERS, records=users, **kwargs)

def groups_report(groups: Sequence[Mapping[str, Any] | Any], **kwargs: Any) -> Report:
    return report_from_records(name=kwargs.pop("name", "Groups report"), report_type=ReportType.GROUPS, records=groups, **kwargs)

def policies_report(policies: Sequence[Mapping[str, Any] | Any], **kwargs: Any) -> Report:
    return report_from_records(name=kwargs.pop("name", "Policies report"), report_type=ReportType.POLICIES, records=policies, **kwargs)

def backups_report(backups: Sequence[Mapping[str, Any] | Any], **kwargs: Any) -> Report:
    return report_from_records(name=kwargs.pop("name", "Backups report"), report_type=ReportType.BACKUPS, records=backups, **kwargs)

def audit_report(events: Sequence[Mapping[str, Any] | Any], **kwargs: Any) -> Report:
    return report_from_records(name=kwargs.pop("name", "Audit report"), report_type=ReportType.AUDIT, records=events, **kwargs)


def _require_text(value: str, field_name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValidationError(f"Report {field_name} cannot be blank.")
    return text

def _coerce_bool(
    value: Any,
    *,
    field_name: str,
    default: bool | None = None,
) -> bool:
    if value is None:
        if default is not None:
            return default
        raise ValidationError(
            f"Report {field_name} must be a boolean-like value."
        )

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        if value in (0, 1):
            return bool(value)
        raise ValidationError(
            f"Report {field_name} must be a boolean-like value."
        )

    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1"}:
            return True
        if normalized in {"false", "no", "n", "0"}:
            return False
        raise ValidationError(
            f"Report {field_name} must be one of: true/false, yes/no, 1/0."
        )

    raise ValidationError(
        f"Report {field_name} must be a boolean-like value."
    )

def _coerce_text_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []

    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []

    if isinstance(value, Sequence):
        result: list[str] = []
        seen: set[str] = set()

        for item in value:
            text = str(item).strip()
            if text and text not in seen:
                seen.add(text)
                result.append(text)

        return result

    raise ValidationError(
        f"Report {field_name} must be a string or sequence of strings."
    )

def _safe_mapping(value: Mapping[str, Any] | None, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}

    if not isinstance(value, Mapping):
        raise ValidationError(
            f"Report {field_name} must be a serializable mapping."
        )

    safe: dict[str, Any] = {}

    for key, item in value.items():
        normalized_key = str(key).strip()

        if not normalized_key:
            raise ValidationError(
                f"Report {field_name} keys cannot be blank."
            )

        if _is_sensitive_key(normalized_key):
            continue

        safe[normalized_key] = _json_ready_without_sensitive(item)

    return safe

def _json_ready_without_sensitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {
            str(key): _json_ready_without_sensitive(item)
            for key, item in value.items()
            if not _is_sensitive_key(str(key))
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_ready_without_sensitive(item) for item in value]
    return value

def _coerce_date_or_datetime(value: Any, field_name: str) -> date | datetime | None:
    if value is None:
        return None

    if isinstance(value, (date, datetime)):
        return value

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None

        try:
            if "T" in text or ":" in text:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

            return date.fromisoformat(text)
        except ValueError as exc:
            raise ValidationError(
                f"Report {field_name} must be an ISO date or datetime."
            ) from exc

    raise ValidationError(
        f"Report {field_name} must be a date, datetime or ISO string."
    )

def _coerce_non_negative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValidationError(
            f"Report {field_name} must be an integer, not boolean."
        )
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(
            f"Report {field_name} must be a non-negative integer."
        ) from exc

    if result < 0:
        raise ValidationError(
            f"Report {field_name} cannot be negative."
        )

    return result


def _is_sensitive_key(key: str) -> bool:
    lowered = str(key).lower()
    return any(marker in lowered for marker in SENSITIVE_FIELD_NAMES)

def _coerce_column(column: ReportColumn | Mapping[str, Any] | str) -> ReportColumn:
    if isinstance(column, ReportColumn):
        return column
    if isinstance(column, Mapping):
        return ReportColumn(**dict(column))
    return ReportColumn(name=str(column))

def _coerce_row(row: ReportRow | Mapping[str, Any]) -> ReportRow:
    if isinstance(row, ReportRow):
        return row
    if not isinstance(row, Mapping):
        raise ValidationError("Report row must be a ReportRow or mapping.")

    data = dict(row)

    if "data" in data:
        return ReportRow(**data)

    return ReportRow(data=data)
def _coerce_section(section: ReportSection | Mapping[str, Any]) -> ReportSection:
    if isinstance(section, ReportSection):
        return section
    return ReportSection(**dict(section))

def _coerce_filters(filters: ReportFilters | Mapping[str, Any]) -> ReportFilters:
    if isinstance(filters, ReportFilters):
        return filters
    return ReportFilters(**dict(filters))

def _coerce_summary(summary: "ReportSummary | Mapping[str, Any]") -> "ReportSummary":
    if isinstance(summary, ReportSummary):
        return summary
    return ReportSummary(**dict(summary))

def _record_to_mapping(record: Mapping[str, Any] | Any) -> dict[str, Any]:
    if isinstance(record, Mapping):
        return dict(record)
    if hasattr(record, "to_dict"):
        return dict(record.to_dict())
    if hasattr(record, "__dict__"):
        return {key: value for key, value in vars(record).items() if not key.startswith("_")}
    raise ValidationError("Report records must be mappings or domain models with serializable attributes.")   

def _columns_from_records(
    records: Sequence[Mapping[str, Any]], columns: Sequence[str | ReportColumn] | None
) -> list[ReportColumn]:
    if columns is not None:
        return [_coerce_column(column) for column in columns]
    names: list[str] = []
    for common in COMMON_REPORT_COLUMNS:
        if any(common in record for record in records):
            names.append(common)
    for record in records:
        for key in record:
            if key not in names:
                names.append(str(key))
    return [ReportColumn(name=name, order=index, sensitive=_is_sensitive_key(name)) for index, name in enumerate(names)]

def _guess_resource_id(record: Mapping[str, Any]) -> str | None:
    for key in ("username", "groupname", "name", "backup_id", "path", "event_id", "id"):
        if key in record and record[key] is not None:
            return str(record[key])
    return None


__all__ = [
    "ReportType",
    "ReportFormat",
    "ReportStatus",
    "SensitivityLevel",
    "SortDirection",
    "ReportOrigin",
    "ReportColumn",
    "ReportRow",
    "ReportSection",
    "ReportFilters",
    "ReportRequest",
    "Report",
    "ReportSummary",
    "ReportExportSpec",
    "ReportExportResult",
    "report_from_records",
    "users_report",
    "groups_report",
    "policies_report",
    "backups_report",
    "audit_report"
]