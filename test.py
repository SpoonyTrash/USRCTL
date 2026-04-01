"""Contrato central de excepciones para el proyecto ``usrctl``.

Este módulo define la jerarquía oficial de errores del sistema CLI y actúa
como contrato arquitectónico para el manejo uniforme de fallos.

Convención general: todas las excepciones del sistema deben derivar de
:class:`UsrCtlError`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


# Sección de soporte mínima del módulo (códigos de salida semánticos).
EXIT_CODE_GENERAL = 1
EXIT_CODE_VALIDATION = 2
EXIT_CODE_PERMISSIONS = 3
EXIT_CODE_NOT_FOUND = 4
EXIT_CODE_CONFLICT = 5
EXIT_CODE_SECURITY = 6
EXIT_CODE_COMMAND = 7


@dataclass(eq=False)
class UsrCtlError(Exception):
    """Excepción base de ``usrctl``.

    Atributos:
        message: Mensaje principal orientado a operador/usuario.
        error_code: Código estable y semántico del error.
        hint: Sugerencia opcional de remediación.
        details: Metadatos técnicos opcionales para diagnóstico.
        exit_code: Código de salida del proceso CLI.
        cause: Excepción original encadenada (si existe).
    """

    message: str = "Se produjo un error en usrctl."
    error_code: str = "USRCTL_ERROR"
    hint: str | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    exit_code: int = EXIT_CODE_GENERAL
    cause: Exception | None = None

    def __post_init__(self) -> None:
        super().__init__(self.message)
        if self.cause is not None and self.__cause__ is None:
            self.__cause__ = self.cause


# 5) Excepciones transversales del sistema
class ValidationError(UsrCtlError):
    def __init__(self, message: str = "Entrada inválida o inconsistente.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="VALIDATION_ERROR", exit_code=EXIT_CODE_VALIDATION, **kwargs)


class InsufficientPermissionsError(UsrCtlError):
    def __init__(self, message: str = "Permisos insuficientes para ejecutar la operación.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="INSUFFICIENT_PERMISSIONS", exit_code=EXIT_CODE_PERMISSIONS, **kwargs)


class ConfigurationError(UsrCtlError):
    def __init__(self, message: str = "Configuración interna inválida o ausente.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="CONFIGURATION_ERROR", **kwargs)


class ResourceNotFoundError(UsrCtlError):
    def __init__(self, message: str = "Recurso no encontrado.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="RESOURCE_NOT_FOUND", exit_code=EXIT_CODE_NOT_FOUND, **kwargs)


class ConflictError(UsrCtlError):
    def __init__(self, message: str = "Conflicto de estado o duplicidad detectada.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="CONFLICT_ERROR", exit_code=EXIT_CODE_CONFLICT, **kwargs)


class PreventiveSecurityError(UsrCtlError):
    def __init__(self, message: str = "Operación bloqueada por seguridad preventiva.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="PREVENTIVE_SECURITY_ERROR", exit_code=EXIT_CODE_SECURITY, **kwargs)


class CommandExecutionError(UsrCtlError):
    def __init__(self, message: str = "Error al ejecutar un comando Linux subyacente.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="COMMAND_EXECUTION_ERROR", exit_code=EXIT_CODE_COMMAND, **kwargs)


# 6) Dominio de usuarios
class UserError(UsrCtlError):
    def __init__(self, message: str = "Error en la gestión de usuarios.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="USER_ERROR", **kwargs)


class UserAlreadyExistsError(UserError):
    def __init__(self, message: str = "El usuario ya existe.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="USER_ALREADY_EXISTS", exit_code=EXIT_CODE_CONFLICT, **kwargs)


class UserNotFoundError(UserError):
    def __init__(self, message: str = "El usuario no fue encontrado.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="USER_NOT_FOUND", exit_code=EXIT_CODE_NOT_FOUND, **kwargs)


class InvalidUsernameError(UserError):
    def __init__(self, message: str = "Nombre de usuario inválido.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="INVALID_USERNAME", exit_code=EXIT_CODE_VALIDATION, **kwargs)


class InvalidUidError(UserError):
    def __init__(self, message: str = "UID inválido o en conflicto.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="INVALID_UID", exit_code=EXIT_CODE_VALIDATION, **kwargs)


class HomeDirectoryError(UserError):
    def __init__(self, message: str = "Error en la operación sobre el directorio home.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="HOME_DIRECTORY_ERROR", **kwargs)


class InvalidShellError(UserError):
    def __init__(self, message: str = "Shell inválida, no permitida o insegura.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="INVALID_SHELL", exit_code=EXIT_CODE_VALIDATION, **kwargs)


class AccountLockError(UserError):
    def __init__(self, message: str = "Error al bloquear o desbloquear la cuenta.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="ACCOUNT_LOCK_ERROR", **kwargs)


# 7) Dominio de grupos
class GroupError(UsrCtlError):
    def __init__(self, message: str = "Error en la gestión de grupos.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="GROUP_ERROR", **kwargs)


class GroupAlreadyExistsError(GroupError):
    def __init__(self, message: str = "El grupo ya existe.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="GROUP_ALREADY_EXISTS", exit_code=EXIT_CODE_CONFLICT, **kwargs)


class GroupNotFoundError(GroupError):
    def __init__(self, message: str = "El grupo no fue encontrado.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="GROUP_NOT_FOUND", exit_code=EXIT_CODE_NOT_FOUND, **kwargs)


class UserAlreadyInGroupError(GroupError):
    def __init__(self, message: str = "El usuario ya pertenece al grupo.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="USER_ALREADY_IN_GROUP", exit_code=EXIT_CODE_CONFLICT, **kwargs)


class UserNotInGroupError(GroupError):
    def __init__(self, message: str = "El usuario no pertenece al grupo.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="USER_NOT_IN_GROUP", exit_code=EXIT_CODE_NOT_FOUND, **kwargs)


class GroupMembershipError(GroupError):
    def __init__(self, message: str = "Error de membresía de grupo.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="GROUP_MEMBERSHIP_ERROR", **kwargs)


# 8) Dominio de contraseñas
class PasswordError(UsrCtlError):
    def __init__(self, message: str = "Error en la gestión de contraseñas.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="PASSWORD_ERROR", **kwargs)


class WeakPasswordError(PasswordError):
    def __init__(self, message: str = "La contraseña no cumple la política de fortaleza.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="WEAK_PASSWORD", exit_code=EXIT_CODE_VALIDATION, **kwargs)


class PasswordGenerationError(PasswordError):
    def __init__(self, message: str = "No fue posible generar una contraseña segura.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="PASSWORD_GENERATION_ERROR", **kwargs)


class PasswordChangeError(PasswordError):
    def __init__(self, message: str = "No fue posible cambiar la contraseña.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="PASSWORD_CHANGE_ERROR", **kwargs)


class ForcePasswordChangeError(PasswordError):
    def __init__(self, message: str = "No fue posible forzar el cambio de contraseña en el próximo inicio de sesión.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="FORCE_PASSWORD_CHANGE_ERROR", **kwargs)


# 9) Dominio de políticas de seguridad
class PolicyError(UsrCtlError):
    def __init__(self, message: str = "Error en políticas de seguridad.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="POLICY_ERROR", **kwargs)


class AccountExpirationError(PolicyError):
    def __init__(self, message: str = "Error al definir o aplicar expiración de cuenta.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="ACCOUNT_EXPIRATION_ERROR", exit_code=EXIT_CODE_VALIDATION, **kwargs)


class InactivityPolicyError(PolicyError):
    def __init__(self, message: str = "Regla de inactividad inválida o inconsistente.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="INACTIVITY_POLICY_ERROR", exit_code=EXIT_CODE_VALIDATION, **kwargs)


class LoginRestrictionError(PolicyError):
    def __init__(self, message: str = "No fue posible aplicar una restricción de login.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="LOGIN_RESTRICTION_ERROR", **kwargs)


class AdvancedSecurityPolicyError(PolicyError):
    def __init__(self, message: str = "Error en política de seguridad avanzada.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="ADVANCED_SECURITY_POLICY_ERROR", **kwargs)


# 10) Dominio de permisos y archivos
class FilePermissionError(UsrCtlError):
    def __init__(self, message: str = "Error en permisos u operaciones de archivos.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="FILE_PERMISSION_ERROR", **kwargs)


class OwnershipChangeError(FilePermissionError):
    def __init__(self, message: str = "No fue posible cambiar el propietario.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="OWNERSHIP_CHANGE_ERROR", **kwargs)


class GroupOwnershipChangeError(FilePermissionError):
    def __init__(self, message: str = "No fue posible cambiar el grupo propietario.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="GROUP_OWNERSHIP_CHANGE_ERROR", **kwargs)


class PermissionChangeError(FilePermissionError):
    def __init__(self, message: str = "No fue posible modificar permisos (chmod).", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="PERMISSION_CHANGE_ERROR", **kwargs)


class PathValidationError(FilePermissionError):
    def __init__(self, message: str = "Ruta inexistente, sensible o no autorizada.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="PATH_VALIDATION_ERROR", exit_code=EXIT_CODE_VALIDATION, **kwargs)


class UnsafeRecursiveOperationError(FilePermissionError):
    def __init__(self, message: str = "Operación recursiva insegura bloqueada.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="UNSAFE_RECURSIVE_OPERATION_ERROR", exit_code=EXIT_CODE_SECURITY, **kwargs)


# 11) Dominio de perfiles y plantillas
class TemplateError(UsrCtlError):
    def __init__(self, message: str = "Error en gestión de plantillas.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="TEMPLATE_ERROR", **kwargs)


class TemplateNotFoundError(TemplateError):
    def __init__(self, message: str = "Plantilla no encontrada.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="TEMPLATE_NOT_FOUND", exit_code=EXIT_CODE_NOT_FOUND, **kwargs)


class InvalidTemplateError(TemplateError):
    def __init__(self, message: str = "Plantilla inválida o incompleta.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="INVALID_TEMPLATE", exit_code=EXIT_CODE_VALIDATION, **kwargs)


class TemplateApplicationError(TemplateError):
    def __init__(self, message: str = "Error al aplicar plantilla.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="TEMPLATE_APPLICATION_ERROR", **kwargs)


class BaseProfileCopyError(TemplateError):
    def __init__(self, message: str = "Error al copiar configuración base de perfil.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="BASE_PROFILE_COPY_ERROR", **kwargs)


# 12) Dominio de límites de recursos
class LimitsError(UsrCtlError):
    def __init__(self, message: str = "Error en la gestión de límites de recursos.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="LIMITS_ERROR", **kwargs)


class InvalidLimitError(LimitsError):
    def __init__(self, message: str = "Límite inválido o fuera de rango.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="INVALID_LIMIT", exit_code=EXIT_CODE_VALIDATION, **kwargs)


class ApplyLimitsError(LimitsError):
    def __init__(self, message: str = "No fue posible aplicar límites de recursos.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="APPLY_LIMITS_ERROR", **kwargs)


class LimitsConsistencyError(LimitsError):
    def __init__(self, message: str = "Inconsistencia entre límites definidos.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="LIMITS_CONSISTENCY_ERROR", exit_code=EXIT_CODE_CONFLICT, **kwargs)


# 13) Dominio de backup y restauración
class BackupError(UsrCtlError):
    def __init__(self, message: str = "Error en operación de backup.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="BACKUP_ERROR", **kwargs)


class BackupCreationError(BackupError):
    def __init__(self, message: str = "No fue posible crear el backup.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="BACKUP_CREATION_ERROR", **kwargs)


class BackupVersioningError(BackupError):
    def __init__(self, message: str = "Error en versionado de backup.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="BACKUP_VERSIONING_ERROR", **kwargs)


class HomeBackupError(BackupError):
    def __init__(self, message: str = "Error al respaldar el directorio home.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="HOME_BACKUP_ERROR", **kwargs)


class RestoreError(UsrCtlError):
    def __init__(self, message: str = "Error en operación de restauración.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="RESTORE_ERROR", **kwargs)


class BackupNotFoundError(RestoreError):
    def __init__(self, message: str = "No se encontró la versión de backup solicitada.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="BACKUP_NOT_FOUND", exit_code=EXIT_CODE_NOT_FOUND, **kwargs)


class PartialRestoreError(RestoreError):
    def __init__(self, message: str = "Restauración fallida o parcial.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="PARTIAL_RESTORE_ERROR", **kwargs)


# 14) Dominio de auditoría y registro
class AuditError(UsrCtlError):
    def __init__(self, message: str = "Error en auditoría y registro.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="AUDIT_ERROR", **kwargs)


class LogWriteError(AuditError):
    def __init__(self, message: str = "No fue posible escribir en el log de auditoría.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="LOG_WRITE_ERROR", **kwargs)


class SyslogIntegrationError(AuditError):
    def __init__(self, message: str = "Error de integración con syslog.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="SYSLOG_INTEGRATION_ERROR", **kwargs)


class TraceabilityError(AuditError):
    def __init__(self, message: str = "Error de historial o trazabilidad de eventos.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="TRACEABILITY_ERROR", **kwargs)


# 15) Dominio de reportes y exportación
class ReportError(UsrCtlError):
    def __init__(self, message: str = "Error en generación o exportación de reportes.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="REPORT_ERROR", **kwargs)


class ReportBuildError(ReportError):
    def __init__(self, message: str = "No fue posible construir el reporte.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="REPORT_BUILD_ERROR", **kwargs)


class JsonExportError(ReportError):
    def __init__(self, message: str = "Error de exportación JSON.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="JSON_EXPORT_ERROR", **kwargs)


class CsvExportError(ReportError):
    def __init__(self, message: str = "Error de exportación CSV.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="CSV_EXPORT_ERROR", **kwargs)


# 16) Dominio de modo seguro y simulación
class DryRunError(UsrCtlError):
    def __init__(self, message: str = "Error en modo seguro o simulación.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="DRY_RUN_ERROR", **kwargs)


class InvalidSimulationError(DryRunError):
    def __init__(self, message: str = "Simulación inválida o no representativa.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="INVALID_SIMULATION_ERROR", exit_code=EXIT_CODE_VALIDATION, **kwargs)


class SimulationDependencyError(DryRunError):
    def __init__(self, message: str = "Dependencia faltante durante validación de simulación.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="SIMULATION_DEPENDENCY_ERROR", **kwargs)


class ConfirmationRequiredError(DryRunError):
    def __init__(self, message: str = "Operación requiere confirmación explícita.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="CONFIRMATION_REQUIRED_ERROR", exit_code=EXIT_CODE_SECURITY, **kwargs)


class DangerousImpactError(DryRunError):
    def __init__(self, message: str = "Impacto peligroso detectado: operación bloqueada.", **kwargs: Any) -> None:
        super().__init__(message=message, error_code="DANGEROUS_IMPACT_ERROR", exit_code=EXIT_CODE_SECURITY, **kwargs)


# 19) Interfaz pública del módulo (debe permanecer al final del archivo)
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