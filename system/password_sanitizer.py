from typing import Any, Mapping, Sequence

from .password_constants import (
    MAX_SANITIZE_DEPTH,
    REDACTED_SECRET,
    SENSITIVE_COMMAND_OPTIONS,
    SHADOW_PATH,
)
SENSITIVE_EXACT_KEYS = frozenset(
    {
        "password",
        "password_value",
        "generated_password",
        "current_password",
        "new_password",
        "old_password",
        "password_hash",
        "shadow_hash",
        "secret",
        "secret_value",
        "credential",
        "credential_value",
        "stdin",
        "stdin_data",
    }
)
SENSITIVE_KEY_SUFFIXES = (
    "_password_value",
    "_password_hash",
    "_shadow_hash",
    "_secret",
    "_secret_value",
    "_credential",
    "_credential_value",
    "_stdin",
    "_stdin_data",
)


def _split_sensitive_option(token: str) -> tuple[str, str] | None:
    text = str(token)
    lowered = text.lower()

    for option in SENSITIVE_COMMAND_OPTIONS:
        if not option.startswith("--"):
            continue

        prefix = f"{option}="

        if lowered.startswith(prefix):
            return (
                text[: len(option)],
                text[len(prefix) :],
            )

    return None


def _is_sensitive_detail_key(key: Any) -> bool:
    normalized = str(key).strip().lower()

    if normalized in SENSITIVE_EXACT_KEYS:
        return True

    return normalized.endswith(SENSITIVE_KEY_SUFFIXES)


def _sanitize_command(command: Sequence[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False

    for token in command:
        text = str(token)

        if redact_next:
            redacted.append(REDACTED_SECRET)
            redact_next = False
            continue

        inline_sensitive = _split_sensitive_option(text)

        if inline_sensitive is not None:
            option, _ = inline_sensitive
            redacted.append(f"{option}={REDACTED_SECRET}")
            continue

        if text.lower() in SENSITIVE_COMMAND_OPTIONS:
            redacted.append(text)
            redact_next = True
            continue

        redacted.append(text)
    return redacted


def _sanitize_text(value: str | None, *, sensitive_values: Sequence[str] = ()) -> str:
    if not value:
        return ""
    sanitized = str(value)

    for sensitive_value in sensitive_values:
        if sensitive_value:
            sanitized = sanitized.replace(str(sensitive_value), REDACTED_SECRET)
    sanitized_lines: list[str] = []
    for line in sanitized.splitlines():
        lowered = line.lower()
        if str(SHADOW_PATH) in line:
            sanitized_lines.append(REDACTED_SECRET)
            continue

        if any(
            marker in lowered
            for marker in (
                "stdin_data=",
                "password_value=",
                "generated_password=",
                "password_hash=",
                "shadow_hash=",
            )
        ):
            sanitized_lines.append(REDACTED_SECRET)
            continue

        sanitized_lines.append(line)

    return "\n".join(sanitized_lines)


def _sanitize_details(
    details: Mapping[str, Any] | None,
    *,
    sensitive_values: Sequence[str] = (),
) -> dict[str, Any]:
    def sanitize_value(value: Any, *, depth: int) -> Any:
        if depth > MAX_SANITIZE_DEPTH:
            return "[MAX_DEPTH_REACHED]"

        if isinstance(value, Mapping):
            return {
                str(key): (
                    REDACTED_SECRET
                    if _is_sensitive_detail_key(key)
                    else sanitize_value(item, depth=depth + 1)
                )
                for key, item in value.items()
            }

        if isinstance(value, list):
            return [sanitize_value(item, depth=depth + 1) for item in value]

        if isinstance(value, tuple):
            return tuple(sanitize_value(item, depth=depth + 1) for item in value)

        if isinstance(value, set):
            sanitized_items = [sanitize_value(item, depth=depth + 1) for item in value]

            return sorted(sanitized_items, key=lambda item: str(item))

        if isinstance(value, str):
            return _sanitize_text(value, sensitive_values=sensitive_values)
        return value

    return {
        str(key): (
            REDACTED_SECRET
            if _is_sensitive_detail_key(key)
            else sanitize_value(value, depth=0)
        )
        for key, value in dict(details or {}).items()
    }
