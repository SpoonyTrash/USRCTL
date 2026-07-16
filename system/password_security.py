from typing import TYPE_CHECKING

from ..config import PasswordStrengthConfig
from ..utils.errors import ValidationError, WeakPasswordError
from .password_sanitizer import REDACTED_SECRET

if TYPE_CHECKING:
    from .linux_password import PasswordCommandStrategy

FORBIDDEN_PASSWORD_CODEPOINTS = frozenset({"\n", "\r", "\x00"})
FORBIDDEN_PASSWORD_CODEPOINT_NAMES = {
    "\n": "LINE_FEED",
    "\r": "CARRIAGE_RETURN",
    "\x00": "NULL_BYTE",
}


def _validate_password_transport(password: str) -> None:
    if not isinstance(password, str):
        raise ValidationError(
            "Password must be a string.",
            details={
                "field": "password",
                "received_type": type(password).__name__,
                "password": REDACTED_SECRET,
            },
        )

    forbidden_characters = [
        FORBIDDEN_PASSWORD_CODEPOINT_NAMES[character]
        for character in FORBIDDEN_PASSWORD_CODEPOINTS
        if character in password
    ]

    if forbidden_characters:
        raise ValidationError(
            "Password contains characters that cannot be passed safely to chpasswd.",
            details={
                "field": "password",
                "forbidden_characters": sorted(forbidden_characters),
                "password": REDACTED_SECRET,
            },
        )


def _validate_password_strength_config(
    config: PasswordStrengthConfig,
) -> PasswordStrengthConfig:
    if not isinstance(config, PasswordStrengthConfig):
        raise ValidationError(
            "password_strength must be a PasswordStrengthConfig instance.",
            details={
                "field": "password_strength",
                "received_type": type(config).__name__,
            },
        )

    minimum_length = config.minimum_length

    if isinstance(minimum_length, bool):
        raise ValidationError(
            "Password minimum length cannot be a boolean.",
            details={"field": "minimum_length", "value": minimum_length},
        )

    if not isinstance(minimum_length, int):
        raise ValidationError(
            "Password minimum length must be an integer.",
            details={
                "field": "minimum_length",
                "received_type": type(minimum_length).__name__,
            },
        )

    if minimum_length < 8:
        raise ValidationError(
            "Password minimum length cannot be lower than 8.",
            details={"field": "minimum_length", "value": minimum_length},
        )

    boolean_fields = (
        "reject_username",
        "require_uppercase",
        "require_lowercase",
        "require_digit",
        "require_symbol",
    )

    for field_name in boolean_fields:
        value = getattr(config, field_name)

        if not isinstance(value, bool):
            raise ValidationError(
                f"{field_name} must be a boolean.",
                details={"field": field_name, "received_type": type(value).__name__},
            )

    return config


def _validate_password_strength(
    username: str,
    password: str | None,
    config: PasswordStrengthConfig,
) -> None:
    if password is None:
        raise WeakPasswordError(
            "Password value is required.",
            details={"username": username, "password": REDACTED_SECRET},
        )

    if len(password) < config.minimum_length:
        raise WeakPasswordError(
            f"Password must be at least {config.minimum_length} characters long.",
            details={"username": username, "password": REDACTED_SECRET},
        )

    if config.reject_username and username.lower() in password.lower():
        raise WeakPasswordError(
            "Password cannot contain the username.",
            details={"username": username, "password": REDACTED_SECRET},
        )

    checks = {
        "uppercase": (
            any(char.isupper() for char in password)
            if config.require_uppercase
            else True
        ),
        "lowercase": (
            any(char.islower() for char in password)
            if config.require_lowercase
            else True
        ),
        "digit": any(char.isdigit() for char in password) if config.require_digit else True,
        "symbol": (
            any(not char.isalnum() for char in password)
            if config.require_symbol
            else True
        ),
    }

    if not all(checks.values()):
        raise WeakPasswordError(
            "Password does not meet the configured strength policy.",
            details={
                "username": username,
                "password": REDACTED_SECRET,
                "checks": checks,
            },
        )


def _normalize_password_strategy(
    value: "PasswordCommandStrategy | str",
) -> "PasswordCommandStrategy":
    from .linux_password import PasswordCommandStrategy

    if isinstance(value, PasswordCommandStrategy):
        return value

    try:
        return PasswordCommandStrategy(str(value).strip().lower())
    except ValueError as exc:
        raise ValidationError(
            "Unsupported password command strategy.",
            details={
                "strategy": str(value),
                "allowed": [strategy.value for strategy in PasswordCommandStrategy],
            },
            cause=exc,
        ) from exc
