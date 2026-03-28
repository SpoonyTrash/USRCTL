from dataclasses import dataclass
from typing import Any

@dataclass(slots=True)
class ErrorDetails:
  context: dict[str, Any] | None = None

class UsrctlError(Exception):
  def __init__(
    self,
    message: str,
    *,
    error_code: str = "USRCTL_ERROR",
    suggestion: str | None = None,
    technical_details: str | dict[str, Any] |   ErrorDetails | None = None,
    exit_code: int = 1,
    cause: Exception | None = None
  ) -> None:
    super().__init__(message)
    self.message = message
    self.error_code = error_code
    self.suggestion = suggestion
    self.technical_details = technical_details
    self.exit_code = exit_code
    self.cause = cause

  def __str__(self) -> dict[str, Any]:
    payload: dict[str, Any] = {
      "message": self.message,
      "error_code": self.error_code,
      "suggestion": self.suggestion,
      "technical_details": self.technical_details,
      "exit_code": self.exit_code,
      "cause": repr(self.cause) if self.cause else None
    }

    return payload
  
class ValidationError(UsrctlError):
  def __init__(self, message: str, **kwargs: Any) -> None:
    super().__init__(message, error_code="VALIDATION_ERROR", **kwargs)

class InsufficientPermissionsError(UsrctlError):
  def __init__(self, message: str, **kwargs: Any) -> None:
    super().__init__(message, error_code="INSUFFICIENT_PERMISSIONS", **kwargs)

class ConfigurationError(UsrctlError):
  def __init__(self, message: str, **kwargs: Any) -> None:
    super().__init__(message, error_code="CONFIGURATION_ERROR", **kwargs)

class ResourceNotFoundError(UsrctlError):
  def __init__(self, message: str, **kwargs: Any) -> None:
    super().__init__(message, error_code="RESOURCE_NOT_FOUND", **kwargs)

class ConflictError(UsrctlError):
  def __init__(self, message: str, **kwargs: Any) -> None:
    super().__init__(message, error_code="CONFLICT_ERROR", **kwargs)

class PreventiveSecurityError(UsrctlError):
  def __init__(self, message: str, **kwargs: Any) -> None:
    super().__init__(message, error_code="PREVENTIVE_SECURITY_ERROR", **kwargs)

class CommandExecutionError(UsrctlError):
  def __init__(self, message: str, **kwargs: Any) -> None:
    super().__init__(message, error_code="COMMAND_EXECUTION_ERROR", **kwargs)