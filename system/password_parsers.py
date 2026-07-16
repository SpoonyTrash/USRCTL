from typing import Any

from ..utils.errors import CommandExecutionError, PolicyError
from .password_constants import (
    CHAGE_ACCOUNT_EXPIRES,
    CHAGE_EXPECTED_FIELDS,
    CHAGE_LAST_CHANGE,
    CHAGE_MAX_DAYS,
    CHAGE_MIN_DAYS,
    CHAGE_PASSWORD_EXPIRES,
    CHAGE_PASSWORD_INACTIVE,
    CHAGE_WARNING_DAYS,
    EXPIRE_IMMEDIATELY_VALUE,
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_LOCKED,
    STATUS_NO_PASSWORD,
    STATUS_UNKNOWN,
)
from .password_sanitizer import _sanitize_details
from .password_types import PasswordStatusInfo


def _normalize_password_state(value: str | None) -> str:
    text = (value or "").strip()

    if not text:
        return STATUS_UNKNOWN

    parts = text.split()

    if len(parts) < 2:
        return STATUS_UNKNOWN

    status_token = parts[1].strip().lower()

    if status_token == "p":
        return STATUS_ACTIVE

    if status_token in {"l", "lk"}:
        return STATUS_LOCKED

    if status_token == "np":
        return STATUS_NO_PASSWORD

    return STATUS_UNKNOWN


def _normalize_chage_date(value: str | None) -> str | None:
    text = (value or "").strip()
    if not text or text.lower() in {"never", "none"}:
        return None
    if text.lower() in {"password must be changed", "must be changed"}:
        return EXPIRE_IMMEDIATELY_VALUE
    return text


def _normalize_policy_days(
    value: Any, *, field_name: str, allow_never: bool = True
) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise PolicyError(
            f"{field_name} must be a day count, not a boolean.",
            details={"field": field_name},
        )
    try:
        days = int(value)
    except (TypeError, ValueError) as exc:
        raise PolicyError(
            f"{field_name} must be an integer day count.",
            details={"field": field_name, "value": value},
            cause=exc,
        ) from exc
    if days < 0 and not (allow_never and days == -1):
        raise PolicyError(
            f"{field_name} cannot be negative.",
            details={"field": field_name, "value": days},
        )
    return days


def _parse_chage_output(
    username: str,
    output: str,
) -> PasswordStatusInfo:
    fields: dict[str, Any] = {}
    name_map = {
        "last password change": CHAGE_LAST_CHANGE,
        "password expires": CHAGE_PASSWORD_EXPIRES,
        "password inactive": CHAGE_PASSWORD_INACTIVE,
        "account expires": CHAGE_ACCOUNT_EXPIRES,
        "minimum number of days between password change": CHAGE_MIN_DAYS,
        "maximum number of days between password change": CHAGE_MAX_DAYS,
        "number of days of warning before password expires": CHAGE_WARNING_DAYS,
    }
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        normalized_key = name_map.get(key.strip().lower())
        if not normalized_key:
            continue
        fields[normalized_key] = raw_value.strip()

    missing_fields = [
        field_name for field_name in CHAGE_EXPECTED_FIELDS if field_name not in fields
    ]

    if missing_fields:
        raise CommandExecutionError(
            "Incomplete chage output.",
            details={"username": username, "missing_fields": missing_fields},
        )

    minimum_days = _normalize_policy_days(
        fields[CHAGE_MIN_DAYS], field_name=CHAGE_MIN_DAYS, allow_never=False
    )
    maximum_days = _normalize_policy_days(
        fields[CHAGE_MAX_DAYS], field_name=CHAGE_MAX_DAYS, allow_never=True
    )
    warning_days = _normalize_policy_days(
        fields[CHAGE_WARNING_DAYS], field_name=CHAGE_WARNING_DAYS, allow_never=False
    )
    inactive_raw = str(fields[CHAGE_PASSWORD_INACTIVE]).strip()
    inactive_days = (
        None
        if inactive_raw.lower() in {"", "never"}
        else _normalize_policy_days(
            inactive_raw,
            field_name=CHAGE_PASSWORD_INACTIVE,
            allow_never=True,
        )
    )
    expires = _normalize_chage_date(fields.get(CHAGE_PASSWORD_EXPIRES))
    last_changed = _normalize_chage_date(fields.get(CHAGE_LAST_CHANGE))
    expired = (
        expires == EXPIRE_IMMEDIATELY_VALUE
        or str(fields.get(CHAGE_LAST_CHANGE, "")).strip().lower()
        == "password must be changed"
    )
    return PasswordStatusInfo(
        username=username,
        status=STATUS_EXPIRED if expired else STATUS_ACTIVE,
        expired=expired,
        requires_change=expired,
        last_changed=last_changed,
        password_expires=expires,
        password_inactive=_normalize_chage_date(fields.get(CHAGE_PASSWORD_INACTIVE)),
        account_expires=_normalize_chage_date(fields.get(CHAGE_ACCOUNT_EXPIRES)),
        minimum_days=minimum_days,
        maximum_days=maximum_days,
        warning_days=warning_days,
        inactive_days=inactive_days,
        raw_fields=_sanitize_details(fields),
    )
