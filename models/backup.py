from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import PurePath
from typing import Any, Mapping, Sequence

from utils.errors import ValidationError
from utils.validators import validate_username

CONFIGURED_BACKUP_BASE_DIR_KEY = "backup_base_dir"

BACKUP_FORMAT_DIRECTORY = "directory"
BACKUP_FORMAT_COMPRESSED = "compressed"
BACKUP_FORMAT_TAR = "tar"
BACKUP_FORMAT_TAR_GZ = "tar.gz"
ALLOWED_BACKUP_FORMATS = frozenset(
    {
        BACKUP_FORMAT_DIRECTORY,
        BACKUP_FORMAT_COMPRESSED,
        BACKUP_FORMAT_TAR,
        BACKUP_FORMAT_TAR_GZ,
    }
)

BACKUP_NAME_PREFIX_SYSTEM = "adminusersrat-system"
BACKUP_NAME_PREFIX_USER = "adminusersrat-user"
BACKUP_NAME_PREFIX_HOME = "adminusersrat-home"
BACKUP_NAME_PREFIX_RESTORE_POINT = "adminusersrat-restore-point"
BACKUP_NAME_PREFIXES = frozenset(
    {
        BACKUP_NAME_PREFIX_SYSTEM,
        BACKUP_NAME_PREFIX_USER,
        BACKUP_NAME_PREFIX_HOME,
        BACKUP_NAME_PREFIX_RESTORE_POINT,
    }
)

CRITICAL_SYSTEM_FILES = frozenset(
    {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/security/limits.conf",
    }
)

DEFAULT_BACKUP_BASE_DIR = "/var/backups/adminusersrat"

SENSITIVE_BACKUP_RESOURCES = frozenset(
    {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/gshadow",
        "/home",
        "/etc/security/limits.conf",
        "/etc/security/access.conf",
        "/etc/login.defs",
    }
)


class BackupType(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    USER = "user"
    HOME = "home"
    CRITICAL_FILES = "critical_files"
    DRY_RUN = "dry_run"


class BackupStatus(str, Enum):
    PENDING = "pending"
    CREATED = "created"
    FAILED = "failed"
    PARTIAL = "partial"
    VERIFIED = "verified"
    CORRUPT = "corrupt"
    RESTORED = "restored"
    ARCHIVED = "archived"
    UNKNOWN = "unknown"
    SKIPPED = "skipped"


class BackupResourceType(str, Enum):
    SYSTEM_FILE = "system_file"
    HOME_DIRECTORY = "home_directory"
    CONFIG_FILE = "config_file"
    METADATA = "metadata"
    MANIFEST = "manifest"
    UNKNOWN = "unknown"


class IntegrityStatus(str, Enum):
    NOT_VERIFIED = "not_verified"
    VERIFIED = "verified"
    FAILED = "failed"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class RestoreType(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    USER = "user"
    HOME = "home"
    CRITICAL_FILES = "critical_files"
    DRY_RUN = "dry_run"


class BackupOrigin(str, Enum):
    MANUAL = "manual"
    USER_DELETE = "user_delete"
    POLICY_CHANGE = "policy_change"
    PERMISSIONS_CHANGE = "permissions_change"
    PRE_RESTORE = "pre_restore"
    MAINTENANCE = "maintenance"
    TEST = "test"
    UNKNOWN = "unknown"


class RestoreStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    SIMULATED = "simulated"
    UNKNOWN = "unknown"


class RestoreImpact(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class BackupResource:
    original_path: str
    backup_path: str | None = None
    resource_type: BackupResourceType = BackupResourceType.UNKNOWN
    size_bytes: int | None = None
    checksum: str | None = None
    is_sensitive: bool = False
    status: BackupStatus = BackupStatus.UNKNOWN
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        self.original_path = _clean_required_text(self.original_path, "original_path")
        self.backup_path = _clean_optional_text(self.backup_path)
        self.resource_type = _coerce_enum(
            self.resource_type, BackupResourceType, BackupResourceType.UNKNOWN
        )
        self.status = _coerce_enum(self.status, BackupStatus, BackupStatus.UNKNOWN)
        self.size_bytes = _validate_optional_non_negative_int(
            self.size_bytes, "size_bytes"
        )
        self.is_sensitive = _coerce_bool(
            self.is_sensitive,
            field_name="is_sensitive",
            default=False,
        ) or _is_sensitive_path(self.original_path)
        self.metadata = _safe_metadata(self.metadata)

    @property
    def is_verified(self) -> bool:
        return self.status == BackupStatus.VERIFIED

    @property
    def has_checksum(self) -> bool:
        return bool(self.checksum)

    @property
    def has_failed(self) -> bool:
        return self.status in {BackupStatus.FAILED, BackupStatus.CORRUPT}

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_path": self.original_path,
            "backup_path": self.backup_path,
            "resource_type": self.resource_type.value,
            "size_bytes": self.size_bytes,
            "checksum": self.checksum,
            "is_sensitive": self.is_sensitive,
            "status": self.status.value,
            "metadata": self.metadata,
        }

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "original_path": self.original_path,
            "backup_path": self.backup_path,
            "resource_type": self.resource_type.value,
            "size_bytes": self.size_bytes,
            "checksum": self.checksum,
            "is_sensitive": self.is_sensitive,
            "status": self.status.value,
            "has_checksum": bool(self.checksum),
        }

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "path": self.original_path,
            "type": self.resource_type.value,
            "sensitive": self.is_sensitive,
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BackupResource":
        return cls(
            original_path=str(data.get("original_path") or data.get("path") or ""),
            backup_path=data.get("backup_path"),
            resource_type=data.get("resource_type", BackupResourceType.UNKNOWN),
            size_bytes=data.get("size_bytes"),
            checksum=data.get("checksum"),
            is_sensitive=_coerce_bool(
                data.get("is_sensitive", False),
                field_name="is_sensitive",
                default=False,
            ),
            status=data.get("status", BackupStatus.UNKNOWN),
            metadata=data.get("metadata" or {}),
        )


@dataclass(slots=True)
class Backup:
    backup_id: str
    name: str
    backup_type: BackupType
    status: BackupStatus
    path: str
    created_at: datetime = field(default_factory=lambda: _utc_now())
    resources: list[BackupResource] = field(default_factory=list)
    target_user: str | None = None
    version: str | None = None
    integrity: IntegrityStatus = IntegrityStatus.NOT_VERIFIED
    metadata: dict[str, Any] = field(default_factory=dict)
    included_system_files: list[str] = field(default_factory=list)
    includes_home: bool = False
    pre_operation: str | None = None
    omitted_resources: list[str] = field(default_factory=list)
    failed_resources: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    origin: BackupOrigin = BackupOrigin.UNKNOWN

    def __post_init__(self) -> None:
        self._normalize_and_validate()

    @property
    def is_full_backup(self) -> bool:
        has_critical = CRITICAL_SYSTEM_FILES.issubset(set(self.included_system_files))
        return self.backup_type == BackupType.FULL or (
            has_critical and self.includes_home
        )

    @property
    def is_partial_backup(self) -> bool:
        return (
            self.backup_type == BackupType.PARTIAL
            or self.status == BackupStatus.PARTIAL
            or bool(self.omitted_resources or self.failed_resources)
        )

    @property
    def is_verified(self) -> bool:
        return (
            self.integrity == IntegrityStatus.VERIFIED
            or self.status == BackupStatus.VERIFIED
        )

    @property
    def is_corrupt(self) -> bool:
        return (
            self.integrity == IntegrityStatus.FAILED
            or self.status == BackupStatus.CORRUPT
        )

    @property
    def contains_sensitive_resources(self) -> bool:
        return any(resource.is_sensitive for resource in self.resources) or any(
            _is_sensitive_path(path) for path in self.included_system_files
        )

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)

    @property
    def is_safe_for_automatic_restore(self) -> bool:
        return (
            self.is_verified
            and not self.is_corrupt
            and not self.contains_sensitive_resources
            and not self.is_partial_backup
        )

    def _normalize_and_validate(self) -> None:
        self.backup_id = _clean_required_text(self.backup_id, "backup_id")
        self.name = _clean_required_text(self.name, "name")
        self.path = _validate_representable_path(self.path, "path")
        self.backup_type = _coerce_enum(
            self.backup_type, BackupType, BackupType.PARTIAL
        )
        self.status = _coerce_enum(self.status, BackupStatus, BackupStatus.UNKNOWN)
        self.integrity = _coerce_enum(
            self.integrity, IntegrityStatus, IntegrityStatus.UNKNOWN
        )
        self.origin = _coerce_enum(self.origin, BackupOrigin, BackupOrigin.UNKNOWN)
        self.target_user = _clean_optional_username(self.target_user)
        self.version = _clean_optional_text(self.version)
        self.pre_operation = _clean_optional_text(self.pre_operation)
        self.created_at = _coerce_datetime(self.created_at)
        self.resources = _dedupe_resources(self.resources)
        self.included_system_files = _dedupe_texts(self.included_system_files)
        self.omitted_resources = _dedupe_texts(self.omitted_resources)
        self.failed_resources = _dedupe_texts(self.failed_resources)
        self.warnings = _dedupe_texts(self.warnings)
        self.includes_home = _coerce_bool(
            self.includes_home,
            field_name="includes_home",
            default=False,
        )
        self.metadata = _safe_metadata(self.metadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "name": self.name,
            "backup_type": self.backup_type.value,
            "status": self.status.value,
            "path": self.path,
            "version": self.version,
            "resources": [resource.to_dict() for resource in self.resources],
            "integrity": self.integrity.value,
            "target_user": self.target_user,
            "created_at": _datetime_to_iso(self.created_at),
            "included_system_files": list(self.included_system_files),
            "includes_home": self.includes_home,
            "pre_operation": self.pre_operation,
            "omitted_resources": list(self.omitted_resources),
            "failed_resources": list(self.failed_resources),
            "warnings": list(self.warnings),
            "origin": self.origin.value,
            "metadata": dict(self.metadata),
        }

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "version": self.version,
            "backup_type": self.backup_type.value,
            "status": self.status.value,
            "target_user": self.target_user,
            "resource_count": len(self.resources),
            "resources": [resource.to_audit_dict() for resource in self.resources],
            "contains_sensitive_resources": self.contains_sensitive_resources,
            "integrity": self.integrity.value,
            "origin": self.origin.value,
        }

    def to_report_dict(self) -> dict[str, Any]:
        return {
            **self.to_summary_dict(),
            "path": self.path,
            "created_at": _datetime_to_iso(self.created_at),
            "resources": [resource.to_summary_dict() for resource in self.resources],
            "failed_resources": list(self.failed_resources),
            "omitted_resources": list(self.omitted_resources),
            "warnings": list(self.warnings),
            "is_full_backup": self.is_full_backup,
            "is_partial_backup": self.is_partial_backup,
            "is_verified": self.is_verified,
            "is_corrupt": self.is_corrupt,
        }

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "name": self.name,
            "backup_type": self.backup_type.value,
            "status": self.status.value,
            "version": self.version,
            "target_user": self.target_user,
            "integrity": self.integrity.value,
            "contains_sensitive_resources": self.contains_sensitive_resources,
            "has_warnings": self.has_warnings,
        }

    @classmethod
    def from_metadata(cls, data: Mapping[str, Any]) -> "Backup":
        resources = [
            BackupResource.from_dict(item) for item in data.get("resources", [])
        ]
        return cls(
            backup_id=str(data.get("backup_id") or data.get("id") or ""),
            name=str(data.get("name") or data.get("backup_id") or ""),
            backup_type=data.get("backup_type", data.get("type", BackupType.PARTIAL)),
            status=data.get("status", BackupStatus.UNKNOWN),
            path=str(data.get("path") or data.get("backup_path") or ""),
            created_at=data.get("created_at", _utc_now()),
            resources=resources,
            target_user=data.get("target_user"),
            version=data.get("version"),
            integrity=data.get("integrity", IntegrityStatus.UNKNOWN),
            metadata=dict(data.get("metadata") or {}),
            included_system_files=list(data.get("included_system_files") or []),
            includes_home=_coerce_bool(
                data.get("includes_home", False),
                field_name="includes_home",
                default=False,
            ),
            pre_operation=data.get("pre_operation"),
            omitted_resources=list(data.get("omitted_resources") or []),
            failed_resources=list(data.get("failed_resources") or []),
            warnings=list(data.get("warnings") or []),
            origin=data.get("origin", BackupOrigin.UNKNOWN),
        )

    @classmethod
    def from_detected_listing(cls, entry: Mapping[str, Any]) -> "Backup":
        return cls.from_metadata(
            {**entry, "status": entry.get("status", BackupStatus.UNKNOWN)}
        )

    @classmethod
    def from_operation_result(cls, result_data: Mapping[str, Any]) -> "Backup":
        metadata = dict(result_data.get("metadata") or result_data)
        status = (
            BackupStatus.CREATED
            if result_data.get("success") is True
            else BackupStatus.FAILED
        )
        if result_data.get("partial"):
            status = BackupStatus.PARTIAL
        return cls.from_metadata({**metadata, "status": metadata.get("status", status)})

    @classmethod
    def from_partial_data(cls, **data: Any) -> "Backup":
        data.setdefault("backup_type", BackupType.PARTIAL)
        data.setdefault("status", BackupStatus.UNKNOWN)
        data.setdefault("integrity", IntegrityStatus.UNKNOWN)
        return cls.from_metadata(data)


@dataclass(slots=True)
class BackupVersion:
    version_id: str
    label: str
    backup_id: str
    created_at: datetime = field(default_factory=lambda: _utc_now())
    path: str | None = None
    integrity: IntegrityStatus = IntegrityStatus.NOT_VERIFIED
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.version_id = _clean_required_text(self.version_id, "version_id")
        self.label = _clean_required_text(self.label, "label")
        self.backup_id = _clean_required_text(self.backup_id, "backup_id")
        self.path = _clean_optional_path(self.path, "path")
        self.created_at = _coerce_datetime(self.created_at)
        self.integrity = _coerce_enum(
            self.integrity, IntegrityStatus, IntegrityStatus.UNKNOWN
        )
        self.reason = _clean_optional_text(self.reason)
        self.metadata = _safe_metadata(self.metadata)

    @property
    def is_verified(self) -> bool:
        return self.integrity == IntegrityStatus.VERIFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "version_id": self.version_id,
            "label": self.label,
            "backup_id": self.backup_id,
            "created_at": _datetime_to_iso(self.created_at),
            "path": self.path,
            "integrity": self.integrity.value,
            "reason": self.reason,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "BackupVersion":
        return cls(
            version_id=str(data.get("version_id") or data.get("id") or ""),
            label=str(data.get("label") or data.get("version") or ""),
            backup_id=str(data.get("backup_id") or ""),
            created_at=data.get("created_at", _utc_now()),
            path=data.get("path"),
            integrity=data.get("integrity", IntegrityStatus.UNKNOWN),
            reason=data.get("reason"),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass(slots=True)
class BackupCreateSpec:
    backup_type: BackupType
    target_user: str | None = None
    include_system_files: bool = False
    include_home: bool = False
    additional_resources: list[str] = field(default_factory=list)
    destination: str | None = None
    reason: str | None = None
    dry_run: bool = False
    require_verification: bool = True
    backup_format: str = BACKUP_FORMAT_TAR_GZ
    origin: BackupOrigin = BackupOrigin.MANUAL
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.backup_type = _coerce_enum(
            self.backup_type, BackupType, BackupType.PARTIAL
        )
        self.target_user = _clean_optional_username(self.target_user)
        self.include_system_files = _coerce_bool(
            self.include_system_files,
            field_name="include_system_files",
            default=False,
        )
        self.include_home = _coerce_bool(
            self.include_home,
            field_name="include_home",
            default=False,
        )
        self.dry_run = _coerce_bool(
            self.dry_run,
            field_name="dry_run",
            default=False,
        )
        self.require_verification = _coerce_bool(
            self.require_verification,
            field_name="require_verification",
            default=True,
        )
        self.backup_format = _validate_backup_format(self.backup_format)
        self.additional_resources = _dedupe_texts(self.additional_resources)
        self.destination = _clean_optional_path(self.destination, "destination")
        self.reason = _clean_optional_text(self.reason)
        self.origin = _coerce_enum(self.origin, BackupOrigin, BackupOrigin.UNKNOWN)
        self.metadata = _safe_metadata(self.metadata)

    @property
    def contains_sensitive_resources(self) -> bool:
        return (
            self.include_home
            or self.include_system_files
            or any(_is_sensitive_path(path) for path in self.additional_resources)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_type": self.backup_type.value,
            "target_user": self.target_user,
            "include_system_files": self.include_system_files,
            "include_home": self.include_home,
            "additional_resources": list(self.additional_resources),
            "destination": self.destination,
            "reason": self.reason,
            "dry_run": self.dry_run,
            "require_verification": self.require_verification,
            "backup_format": self.backup_format,
            "origin": self.origin.value,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_cli_params(cls, **params: Any) -> "BackupCreateSpec":
        return cls(
            backup_type=params.get(
                "backup_type", params.get("type", BackupType.PARTIAL)
            ),
            target_user=params.get("user") or params.get("target_user"),
            include_system_files=_coerce_bool(
                params.get("include_system", params.get("include_system_files", False)),
                field_name="include_system_files",
                default=False,
            ),
            include_home=_coerce_bool(
                params.get("include_home", False),
                field_name="include_home",
                default=False,
            ),
            additional_resources=list(
                params.get("resources") or params.get("additional_resources") or []
            ),
            destination=params.get("destination"),
            reason=params.get("reason"),
            dry_run=_coerce_bool(
                params.get("dry_run", False),
                field_name="dry_run",
                default=False,
            ),
            require_verification=_coerce_bool(
                params.get("require_verification", True),
                field_name="require_verification",
                default=True,
            ),
            backup_format=params.get("backup_format", BACKUP_FORMAT_TAR_GZ),
            origin=params.get("origin", BackupOrigin.MANUAL),
            metadata=dict(params.get("metadata") or {}),
        )

    @classmethod
    def for_critical_operation(
        cls, operation: str, target_user: str | None = None, **options: Any
    ) -> "BackupCreateSpec":
        origin_map = {
            "delete_user": BackupOrigin.USER_DELETE,
            "restore": BackupOrigin.PRE_RESTORE,
            "policy_change": BackupOrigin.POLICY_CHANGE,
            "permissions_change": BackupOrigin.PERMISSIONS_CHANGE,
        }
        return cls(
            backup_type=options.get("backup_type", BackupType.FULL),
            target_user=target_user,
            include_system_files=_coerce_bool(
                options.get("include_system_files", True),
                field_name="include_system_files",
                default=True,
            ),
            include_home=_coerce_bool(
                options.get("include_home", target_user is not None),
                field_name="include_home",
                default=target_user is not None,
            ),
            additional_resources=list(options.get("additional_resources") or []),
            destination=options.get("destination"),
            reason=options.get("reason", f"before {operation}"),
            dry_run=_coerce_bool(
                options.get("dry_run", False),
                field_name="dry_run",
                default=False,
            ),
            require_verification=_coerce_bool(
                options.get("require_verification", True),
                field_name="require_verification",
                default=True,
            ),
            backup_format=options.get("backup_format", BACKUP_FORMAT_TAR_GZ),
            origin=origin_map.get(operation, BackupOrigin.MAINTENANCE),
            metadata={"operation": operation, **dict(options.get("metadata") or {})},
        )

    @classmethod
    def from_template(cls, template_data: Mapping[str, Any]) -> "BackupCreateSpec":
        return cls.from_cli_params(
            **dict(template_data),
            origin=template_data.get("origin", BackupOrigin.MAINTENANCE),
        )

    @classmethod
    def from_config_defaults(
        cls, defaults: Mapping[str, Any], **overrides: Any
    ) -> "BackupCreateSpec":
        data = {**dict(defaults), **overrides}
        return cls.from_cli_params(**data)


@dataclass(slots=True)
class RestorePlan:
    backup_id: str
    version: str | None
    restore_type: RestoreType
    resources_to_restore: list[BackupResource] = field(default_factory=list)
    resources_to_overwrite: list[str] = field(default_factory=list)
    resources_to_omit: list[str] = field(default_factory=list)
    impact: RestoreImpact = RestoreImpact.HIGH
    requires_confirmation: bool = True
    dry_run: bool = False
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.backup_id = _clean_required_text(self.backup_id, "backup_id")
        self.version = _clean_optional_text(self.version)
        self.restore_type = _coerce_enum(
            self.restore_type, RestoreType, RestoreType.PARTIAL
        )
        self.resources_to_restore = _dedupe_resources(self.resources_to_restore)
        self.resources_to_overwrite = _dedupe_texts(self.resources_to_overwrite)
        self.resources_to_omit = _dedupe_texts(self.resources_to_omit)
        self.impact = _coerce_enum(self.impact, RestoreImpact, RestoreImpact.HIGH)
        self.warnings = _dedupe_texts(self.warnings)
        self.metadata = _safe_metadata(self.metadata)
        self.dry_run = _coerce_bool(
            self.dry_run,
            field_name="dry_run",
            default=False,
        )
        self.requires_confirmation = (
            _coerce_bool(
                self.requires_confirmation,
                field_name="requires_confirmation",
                default=True,
            )
            or self.requires_confirmation_for_restore
        )

    @property
    def contains_sensitive_resources(self) -> bool:
        paths = [
            resource.original_path for resource in self.resources_to_restore
        ] + self.resources_to_overwrite
        return any(_is_sensitive_path(path) for path in paths) or any(
            resource.is_sensitive for resource in self.resources_to_restore
        )

    @property
    def requires_confirmation_for_restore(self) -> bool:
        return (
            self.impact in {RestoreImpact.HIGH, RestoreImpact.CRITICAL}
            or self.contains_sensitive_resources
            or self.restore_type in {RestoreType.FULL, RestoreType.CRITICAL_FILES}
        )

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)

    @property
    def is_safe_for_automatic_restore(self) -> bool:
        return self.dry_run or (
            not self.requires_confirmation_for_restore and not self.has_warnings
        )

    def validate_versioned_restore(self) -> None:
        if self.restore_type != RestoreType.DRY_RUN and not self.version:
            raise ValidationError(
                "Restore plan requires a version for non-simulated restores."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "version": self.version,
            "restore_type": self.restore_type.value,
            "resources_to_restore": [
                resource.to_dict() for resource in self.resources_to_restore
            ],
            "resources_to_overwrite": list(self.resources_to_overwrite),
            "resources_to_omit": list(self.resources_to_omit),
            "impact": self.impact.value,
            "requires_confirmation": self.requires_confirmation,
            "dry_run": self.dry_run,
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
        }

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "version": self.version,
            "restore_type": self.restore_type.value,
            "resource_count": len(self.resources_to_restore),
            "overwrite_count": len(self.resources_to_overwrite),
            "contains_sensitive_resources": self.contains_sensitive_resources,
            "impact": self.impact.value,
            "dry_run": self.dry_run,
        }

    @classmethod
    def from_backup(
        cls,
        backup: Backup,
        *,
        restore_type: RestoreType = RestoreType.PARTIAL,
        dry_run: bool = False,
    ) -> "RestorePlan":
        return cls(
            backup_id=backup.backup_id,
            version=backup.version,
            restore_type=restore_type,
            resources_to_restore=list(backup.resources),
            resources_to_overwrite=[
                resource.original_path for resource in backup.resources
            ],
            impact=RestoreImpact.CRITICAL
            if backup.contains_sensitive_resources
            else RestoreImpact.HIGH,
            dry_run=dry_run,
            warnings=list(backup.warnings),
        )


@dataclass(slots=True)
class RestoreSummary:
    backup_id: str
    version: str | None
    final_status: RestoreStatus
    restored_resources: list[str] = field(default_factory=list)
    failed_resources: list[str] = field(default_factory=list)
    omitted_resources: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    changes_applied: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.backup_id = _clean_required_text(self.backup_id, "backup_id")
        self.version = _clean_optional_text(self.version)
        self.final_status = _coerce_enum(
            self.final_status, RestoreStatus, RestoreStatus.UNKNOWN
        )
        self.restored_resources = _dedupe_texts(self.restored_resources)
        self.failed_resources = _dedupe_texts(self.failed_resources)
        self.omitted_resources = _dedupe_texts(self.omitted_resources)
        self.warnings = _dedupe_texts(self.warnings)
        self.changes_applied = _coerce_bool(
            self.changes_applied,
            field_name="changes_applied",
            default=False,
        )
        self.metadata = _safe_metadata(self.metadata)

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)

    @property
    def is_successful(self) -> bool:
        return self.final_status == RestoreStatus.SUCCESS

    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "version": self.version,
            "final_status": self.final_status.value,
            "restored_resources": list(self.restored_resources),
            "failed_resources": list(self.failed_resources),
            "omitted_resources": list(self.omitted_resources),
            "warnings": list(self.warnings),
            "changes_applied": self.changes_applied,
            "metadata": dict(self.metadata),
        }

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "version": self.version,
            "final_status": self.final_status.value,
            "restored_count": len(self.restored_resources),
            "failed_count": len(self.failed_resources),
            "omitted_count": len(self.omitted_resources),
            "changes_applied": self.changes_applied,
            "contains_sensitive_resources": any(
                _is_sensitive_path(path) for path in self.restored_resources
            ),
        }

    def to_report_dict(self) -> dict[str, Any]:
        return self.to_dict()

    @classmethod
    def from_restore_plan(
        cls,
        plan: RestorePlan,
        *,
        final_status: RestoreStatus,
        changes_applied: bool = False,
    ) -> "RestoreSummary":
        return cls(
            backup_id=plan.backup_id,
            version=plan.version,
            final_status=final_status,
            restored_resources=[]
            if plan.dry_run
            else [resource.original_path for resource in plan.resources_to_restore],
            omitted_resources=list(plan.resources_to_omit),
            warnings=list(plan.warnings),
            changes_applied=changes_applied and not plan.dry_run,
        )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _clean_required_text(value: Any, field_name: str) -> str:
    if value is None:
        raise ValidationError(f"{field_name} must not be empty.")
    text = str(value).strip()
    if not text:
        raise ValidationError(f"{field_name} must not be empty.")
    return text


def _clean_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _clean_optional_username(value: Any) -> str | None:
    text = _clean_optional_text(value)
    if text is None:
        return None
    return validate_username(text, allow_reserved=True)


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
            f"{field_name} must be a boolean-like value.",
        )

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        if value in (0, 1):
            return bool(value)
        raise ValidationError(
            f"{field_name} must be a boolean-like value.",
        )

    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1"}:
            return True
        if normalized in {"false", "no", "n", "0"}:
            return False
        raise ValidationError(
            f"{field_name} must be one of: true/false, yes/no, 1/0.",
        )

    raise ValidationError(
        f"{field_name} must be a boolean-like value.",
    )


def _validate_backup_format(value: Any) -> str:
    text = _clean_required_text(value, "backup_format")
    if text not in ALLOWED_BACKUP_FORMATS:
        allowed = ", ".join(sorted(ALLOWED_BACKUP_FORMATS))
        raise ValidationError(f"backup_format must be one of: {allowed}.")
    return text


def _validate_representable_path(value: Any, field_name: str) -> str:
    text = _clean_required_text(value, field_name)
    try:
        PurePath(text)
    except Exception as exc:
        raise ValidationError(f"{field_name} must be representable as a path.") from exc
    return text


def _datetime_to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _coerce_datetime(value).isoformat()


def _coerce_datetime(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValidationError(
                "datetime value must be ISO-8601 compatible."
            ) from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    raise ValidationError("datetime value must be a datetime or ISO string.")


def _coerce_enum(value: Any, enum_cls: type[Enum], default: Enum) -> Any:
    if isinstance(value, enum_cls):
        return value
    if value is None:
        return default
    try:
        return enum_cls(str(value))
    except ValueError as exc:
        allowed = ", ".join(item.value for item in enum_cls)
        raise ValidationError(
            f"Invalid {enum_cls.__name__}: {value!r}. Allowed values: {allowed}."
        ) from exc


def _clean_optional_path(value: Any, field_name: str) -> str | None:
    text = _clean_optional_text(value)
    if text is None:
        return None
    return _validate_representable_path(text, field_name)


def _validate_optional_non_negative_int(value: Any, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationError(
            f"{field_name} must be a non-negative integer when provided."
        )
    return value


def _dedupe_texts(values: Sequence[Any]) -> list[str]:
    seen: set[str] = set()
    cleaned: list[str] = []
    for value in values:
        text = _clean_optional_text(value)
        if text and text not in seen:
            seen.add(text)
            cleaned.append(text)
    return cleaned


def _dedupe_resources(
    resources: Sequence[BackupResource | Mapping[str, Any]],
) -> list[BackupResource]:
    seen: set[tuple[str, str | None]] = set()
    result: list[BackupResource] = []
    for item in resources:
        resource = (
            item if isinstance(item, BackupResource) else BackupResource.from_dict(item)
        )
        key = (resource.original_path, resource.backup_path)
        if key not in seen:
            seen.add(key)
            result.append(resource)
    return result


def _is_sensitive_path(path: str | None) -> bool:
    if not path:
        return False
    normalized = str(PurePath(str(path)))
    return (
        normalized in SENSITIVE_BACKUP_RESOURCES
        or normalized in CRITICAL_SYSTEM_FILES
        or normalized.startswith("/home/")
    )


SENSITIVE_METADATA_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "hash",
        "shadow",
        "credential",
        "credentials",
    }
)


def _looks_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in SENSITIVE_METADATA_KEYS)


def _json_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return _datetime_to_iso(value)
    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(item)
            for key, item in value.items()
            if not _looks_sensitive_key(str(key))
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    return value


def _safe_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    if metadata is None:
        return {}
    if not isinstance(metadata, Mapping):
        raise ValidationError("metadata must be a mapping.")

    safe: dict[str, Any] = {}
    for key, value in metadata.items():
        normalized_key = str(key).strip()
        if not normalized_key:
            raise ValidationError("metadata keys cannot be empty.")
        if _looks_sensitive_key(normalized_key):
            continue
        safe[normalized_key] = _json_safe(value)
    return safe


__all__ = [
    "ALLOWED_BACKUP_FORMATS",
    "BACKUP_NAME_PREFIXES",
    "CONFIGURED_BACKUP_BASE_DIR_KEY",
    "DEFAULT_BACKUP_BASE_DIR",
    "CRITICAL_SYSTEM_FILES",
    "SENSITIVE_BACKUP_RESOURCES",
    "Backup",
    "BackupCreateSpec",
    "BackupOrigin",
    "BackupResource",
    "BackupResourceType",
    "BackupStatus",
    "BackupType",
    "BackupVersion",
    "IntegrityStatus",
    "RestorePlan",
    "RestoreSummary",
    "RestoreStatus",
    "RestoreImpact",
    "RestoreType",
]
