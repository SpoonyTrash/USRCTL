
from __future__ import annotations

from dataclasses import field
from typing import Any, Mapping, ClassVar


EXIT_CODE_GENERAL = 1
EXIT_CODE_VALIDATION = 2
EXIT_CODE_PERMISSIONS = 3
EXIT_CODE_NOT_FOUND = 4
EXIT_CODE_CONFLICT = 5
EXIT_CODE_SECURITY = 6
EXIT_CODE_COMMAND = 7

class UsrCtlError(Exception):
    message: ClassVar[str] = "Se produjo un error en usrctl."
    error_code: ClassVar[str] = "USRCTL_ERROR"
    exit_code: ClassVar[int] = EXIT_CODE_GENERAL
    

    def __init__(
        self,
        message: str | None = None,
        *,
        error_code: str | None = None,
        hint: str | None = None,
        details: Mapping[str, Any] = field(default_factory=dict),
        exit_code: int | None = None,
        cause: Exception | None = None
    ) -> None:
        self.message = message or self.__class__.message
        self.error_code = error_code or self.__class__.error_code
        self.hint = hint
        self.details = details or {}
        self.exit_code = exit_code if exit_code is not None else self.__class__.exit_code
        self.cause = cause

        super().__init__(self.message)
        if self.cause is not None and self.__cause__ is None:
            self.__cause__ = self.cause

class ValidationError(UsrCtlError):
    message = "Invalid or inconsistent entry."
    error_code = "VALIDATION_ERROR"
    exit_code = EXIT_CODE_VALIDATION

class InsufficientPermissionsError(UsrCtlError):
    message = "Insufficient permissions to perform the operation."
    error_code = "INSUFFICIENT_PERMISSIONS"
    exit_code = EXIT_CODE_PERMISSIONS

class ConfigurationError(UsrCtlError):
    message = "Invalid or missing internal configuration."
    error_code = "CONFIGURATION_ERROR"

class ResourceNotFoundError(UsrCtlError):
    message = "Resource not found."
    error_code = "RESOURCE_NOT_FOUND"
    exit_code = EXIT_CODE_NOT_FOUND

class ConflictError(UsrCtlError):
    message = "State conflict or duplication detected."
    error_code = "CONFLICT_ERROR"
    exit_code = EXIT_CODE_CONFLICT

class PreventiveSecurityError(UsrCtlError):
    message = "Operation blocked for preventative security reasons."
    error_code = "PREVENTIVE_SECURITY_ERROR"
    exit_code = EXIT_CODE_SECURITY

class CommandExecutionError(UsrCtlError):
    message = "Error executing an underlying Linux command."
    error_code = "COMMAND_EXECUTION_ERROR"
    exit_code = EXIT_CODE_COMMAND

class UserError(UsrCtlError):
    message = "User management error."
    error_code = "USER_ERROR"

class UserAlreadyExistsError(UserError):
    message = "The user already exists."
    error_code = "USER_ALREADY_EXISTS"
    exit_code = EXIT_CODE_CONFLICT

class UserNotFoundError(UserError):
    message = "The user was not found."
    error_code = "USER_NOT_FOUND"
    exit_code = EXIT_CODE_NOT_FOUND

class InvalidUsernameError(UserError):
    message = "Invalid username."
    error_code = "INVALID_USERNAME"
    exit_code = EXIT_CODE_VALIDATION

class InvalidUidError(UserError):
    message = "Invalid or conflicting UID."
    error_code = "INVALID_UID"
    exit_code = EXIT_CODE_VALIDATION

class HomeDirectoryError(UserError):
    message = "Error in the operation on the home directory."
    error_code = "HOME_DIRECTORY_ERROR"
    exit_code = EXIT_CODE_COMMAND

class InvalidShellError(UserError):
    message = "Invalid, disallowed, or unsafe shell."
    error_code = "INVALID_SHELL"
    exit_code = EXIT_CODE_VALIDATION

class AccountLockError(UserError):
    message = "Error blocking or unlocking the account."
    error_code = "ACCOUNT_LOCK_ERROR"
    exit_code = EXIT_CODE_SECURITY

class GroupError(UsrCtlError):
    message = "Error in group management."
    error_code = "GROUP_ERROR"

class GroupAlreadyExistsError(GroupError):
    message = "The group already exists."
    error_code = "GROUP_ALREADY_EXISTS"
    exit_code = EXIT_CODE_CONFLICT

class GroupNotFoundError(GroupError):
    message = "The group was not found."
    error_code = "GROUP_NOT_FOUND"
    exit_code = EXIT_CODE_NOT_FOUND

class UserAlreadyInGroupError(GroupError):
    message = "The user already belongs to the group."
    error_code = "USER_ALREADY_IN_GROUP"
    exit_code = EXIT_CODE_CONFLICT

class UserNotInGroupError(GroupError):
    message = "The user does not belong to the group."
    error_code = "USER_NOT_IN_GROUP"
    exit_code = EXIT_CODE_NOT_FOUND

class GroupMembershipError(GroupError):
    message = "Group membership error."
    error_code = "GROUP_MEMBERSHIP_ERROR"

class PasswordError(UsrCtlError):
    message = "Password management error."
    error_code = "PASSWORD_ERROR"

class WeakPasswordError(PasswordError):
    message = "The password does not meet the strength policy."
    error_code = "WEAK_PASSWORD"
    exit_code = EXIT_CODE_VALIDATION

class PasswordGenerationError(PasswordError):
    message = "It was not possible to generate a secure password."
    error_code = "PASSWORD_GENERATION_ERROR"

class PasswordChangeError(PasswordError):
    message = "It was not possible to change the password."
    error_code = "PASSWORD_CHANGE_ERROR"
    exit_code = EXIT_CODE_SECURITY

class ForcePasswordChangeError(PasswordError):
    message = "It was not possible to force a password change on the next login."
    error_code = "FORCE_PASSWORD_CHANGE_ERROR"

class PolicyError(UsrCtlError):
    message = "Error in security policies."
    error_code = "POLICY_ERROR"

class AccountExpirationError(PolicyError):
    message = "Error defining or applying account expiration."
    error_code = "ACCOUNT_EXPIRATION_ERROR"
    exit_code = EXIT_CODE_VALIDATION

class InactivityPolicyError(PolicyError):
    message = "Invalid or inconsistent inactivity rule."
    error_code = "INACTIVITY_POLICY_ERROR"
    exit_code = EXIT_CODE_VALIDATION

class LoginRestrictionError(PolicyError):
    message = "It was not possible to apply a login restriction."
    error_code = "LOGIN_RESTRICTION_ERROR"

class AdvancedSecurityPolicyError(PolicyError):
    message = "Error in advanced security policy."
    error_code = "ADVANCED_SECURITY_POLICY_ERROR"

class FilePermissionError(UsrCtlError):
    message = "Error in file permissions or operations."
    error_code = "FILE_PERMISSION_ERROR"

class OwnershipChangeError(FilePermissionError):
    message = "It was not possible to change the owner."
    error_code = "OWNERSHIP_CHANGE_ERROR"

class GroupOwnershipChangeError(FilePermissionError):
    message = "It was not possible to change the owning group."
    error_code = "GROUP_OWNERSHIP_CHANGE_ERROR"

class PermissionChangeError(FilePermissionError):
    message = "It was not possible to modify permissions (chmod)."
    error_code = "PERMISSION_CHANGE_ERROR"

class PathValidationError(FilePermissionError):
    message = "Non-existent, sensitive, or unauthorized route."
    error_code = "PATH_VALIDATION_ERROR"
    exit_code = EXIT_CODE_VALIDATION

class UnsafeRecursiveOperationError(FilePermissionError):
    message = "Unsafe recursive operation blocked."
    error_code = "UNSAFE_RECURSIVE_OPERATION_ERROR"
    exit_code = EXIT_CODE_SECURITY

class TemplateError(UsrCtlError):
    message = "Template management error."
    error_code = "TEMPLATE_ERROR"

class TemplateNotFoundError(TemplateError):
    message = "Template not found."
    error_code = "TEMPLATE_NOT_FOUND"
    exit_code = EXIT_CODE_NOT_FOUND

class InvalidTemplateError(TemplateError):
    message = "Invalid or incomplete template."
    error_code = "INVALID_TEMPLATE"
    exit_code = EXIT_CODE_VALIDATION

class TemplateApplicationError(TemplateError):
    message = "Error applying template."
    error_code = "TEMPLATE_APPLICATION_ERROR"

class BaseProfileCopyError(TemplateError):
    message = "Error copying base profile settings."
    error_code = "BASE_PROFILE_COPY_ERROR"

class LimitsError(UsrCtlError):
    message = "Error in resource limit management."
    error_code = "LIMITS_ERROR"

class InvalidLimitError(LimitsError):
    message = "Invalid or out-of-range limit."
    error_code = "INVALID_LIMIT"
    exit_code = EXIT_CODE_VALIDATION

class ApplyLimitsError(LimitsError):
    message = "It was not possible to apply resource limits."
    error_code = "APPLY_LIMITS_ERROR"

class LimitsConsistencyError(LimitsError):
    message = "Inconsistency between defined limits."
    error_code = "LIMITS_CONSISTENCY_ERROR"
    exit_code = EXIT_CODE_VALIDATION


class BackupError(UsrCtlError):
    message = "Backup operation error."
    error_code = "BACKUP_ERROR"

class BackupCreationError(BackupError):
    message = "It was not possible to create the backup."
    error_code = "BACKUP_CREATION_ERROR"
    exit_code = EXIT_CODE_COMMAND

class BackupVersioningError(BackupError):
    message = "Backup versioning error."
    error_code = "BACKUP_VERSIONING_ERROR"

class HomeBackupError(BackupError):
    message = "Error backing up home directory."
    error_code = "HOME_BACKUP_ERROR"
    exit_code = EXIT_CODE_COMMAND

class RestoreError(UsrCtlError):
    message = "Error in restoration operation."
    error_code = "RESTORE_ERROR"

class BackupNotFoundError(RestoreError):
    message = "The requested backup version was not found."
    error_code = "BACKUP_NOT_FOUND"
    exit_code = EXIT_CODE_NOT_FOUND

class PartialRestoreError(RestoreError):
    message = "Failed or partial restoration."
    error_code = "PARTIAL_RESTORE_ERROR"

class AuditError(UsrCtlError):
    message = "Error in audit and record."
    error_code = "AUDIT_ERROR"

class LogWriteError(AuditError):
    message = "It was not possible to write to the audit log."
    error_code = "LOG_WRITE_ERROR"
    exit_code = EXIT_CODE_COMMAND

class SyslogIntegrationError(AuditError):
    message = "Syslog integration error."
    error_code = "SYSLOG_INTEGRATION_ERROR"

class TraceabilityError(AuditError):
    message = "Event history or traceability error."
    error_code = "TRACEABILITY_ERROR"

class ReportError(UsrCtlError):
    message = "Error in generating or exporting reports."
    error_code = "REPORT_ERROR"

class ReportBuildError(ReportError):
    message = "It was not possible to build the report."
    error_code = "REPORT_BUILD_ERROR"
    exit_code = EXIT_CODE_COMMAND

class JsonExportError(ReportError):
    message = "JSON export error."
    error_code = "JSON_EXPORT_ERROR"
    exit_code = EXIT_CODE_COMMAND

class CsvExportError(ReportError):
    message = "CSV export error."
    error_code = "CSV_EXPORT_ERROR"
    exit_code = EXIT_CODE_COMMAND

class DryRunError(UsrCtlError):
    message = "Error in safe mode or simulation."
    error_code = "DRY_RUN_ERROR"

class InvalidSimulationError(DryRunError):
    message = "Invalid or unrepresentative simulation."
    error_code = "INVALID_SIMULATION_ERROR"
    exit_code = EXIT_CODE_VALIDATION

class SimulationDependencyError(DryRunError):
    message = "Missing dependency during simulation validation."
    error_code = "SIMULATION_DEPENDENCY_ERROR"

class ConfirmationRequiredError(DryRunError):
    message = "Operation requires explicit confirmation."
    error_code = "CONFIRMATION_REQUIRED_ERROR"
    exit_code = EXIT_CODE_SECURITY


class DangerousImpactError(DryRunError):
    message = "Hazardous impact detected: operation blocked."
    error_code = "DANGEROUS_IMPACT_ERROR"


__all__ = [
    "EXIT_CODE_GENERAL",
    "EXIT_CODE_VALIDATION",
    "EXIT_CODE_PERMISSIONS",
    "EXIT_CODE_NOT_FOUND",
    "EXIT_CODE_CONFLICT",
    "EXIT_CODE_SECURITY",
    "EXIT_CODE_COMMAND",
    "UsrCtlError",
    "ValidationError",
    "InsufficientPermissionsError",
    "ConfigurationError",
    "ResourceNotFoundError",
    "ConflictError",
    "PreventiveSecurityError",
    "CommandExecutionError",
    "UserError",
    "UserAlreadyExistsError",
    "UserNotFoundError",
    "InvalidUsernameError",
    "InvalidUidError",
    "HomeDirectoryError",
    "InvalidShellError",
    "AccountLockError",
    "GroupError",
    "GroupAlreadyExistsError",
    "GroupNotFoundError",
    "UserAlreadyInGroupError",
    "UserNotInGroupError",
    "GroupMembershipError",
    "PasswordError",
    "WeakPasswordError",
    "PasswordGenerationError",
    "PasswordChangeError",
    "ForcePasswordChangeError",
    "PolicyError",
    "AccountExpirationError",
    "InactivityPolicyError",
    "LoginRestrictionError",
    "AdvancedSecurityPolicyError",
    "FilePermissionError",
    "OwnershipChangeError",
    "GroupOwnershipChangeError",
    "PermissionChangeError",
    "PathValidationError",
    "UnsafeRecursiveOperationError",
    "TemplateError",
    "TemplateNotFoundError",
    "InvalidTemplateError",
    "TemplateApplicationError",
    "BaseProfileCopyError",
    "LimitsError",
    "InvalidLimitError",
    "ApplyLimitsError",
    "LimitsConsistencyError",
    "BackupError",
    "BackupCreationError",
    "BackupVersioningError",
    "HomeBackupError",
    "RestoreError",
    "BackupNotFoundError",
    "PartialRestoreError",
    "AuditError",
    "LogWriteError",
    "SyslogIntegrationError",
    "TraceabilityError",
    "ReportError",
    "ReportBuildError",
    "JsonExportError",
    "CsvExportError",
    "DryRunError",
    "InvalidSimulationError",
    "SimulationDependencyError",
    "ConfirmationRequiredError",
    "DangerousImpactError",
]