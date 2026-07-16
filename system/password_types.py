from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .password_constants import STATUS_UNKNOWN


class PasswordCommandStrategy(StrEnum):
    PASSWD = "passwd"
    USERMOD = "usermod"


def _resolve_date_alias(
    *,
    canonical_name: str,
    canonical_value: str | None,
    legacy_name: str,
    legacy_value: str | None,
) -> str | None:
    if (
        canonical_value is not None
        and legacy_value is not None
        and canonical_value != legacy_value
    ):
        raise ValueError(
            f"{canonical_name} and {legacy_name} cannot contain different values."
        )
    return canonical_value if canonical_value is not None else legacy_value


@dataclass(slots=True, init=False)
class PasswordStatusInfo:
    username: str
    status: str = STATUS_UNKNOWN
    locked: bool = False
    expired: bool = False
    requires_change: bool = False
    last_changed_at: str | None = None
    password_expires_at: str | None = None
    password_inactive_at: str | None = None
    account_expires_at: str | None = None
    minimum_days: int | None = None
    maximum_days: int | None = None
    warning_days: int | None = None
    inactive_days: int | None = None
    raw_fields: dict[str, Any] = field(default_factory=dict)

    def __init__(
        self,
        username: str,
        status: str = STATUS_UNKNOWN,
        locked: bool = False,
        expired: bool = False,
        requires_change: bool = False,
        last_changed_at: str | None = None,
        password_expires_at: str | None = None,
        password_inactive_at: str | None = None,
        account_expires_at: str | None = None,
        minimum_days: int | None = None,
        maximum_days: int | None = None,
        warning_days: int | None = None,
        inactive_days: int | None = None,
        raw_fields: dict[str, Any] | None = None,
        *,
        last_changed: str | None = None,
        password_expires: str | None = None,
        password_inactive: str | None = None,
        account_expires: str | None = None,
    ) -> None:
        self.username = username
        self.status = status
        self.locked = locked
        self.expired = expired
        self.requires_change = requires_change
        self.last_changed_at = _resolve_date_alias(
            canonical_name="last_changed_at", canonical_value=last_changed_at,
            legacy_name="last_changed", legacy_value=last_changed,
        )
        self.password_expires_at = _resolve_date_alias(
            canonical_name="password_expires_at", canonical_value=password_expires_at,
            legacy_name="password_expires", legacy_value=password_expires,
        )
        self.password_inactive_at = _resolve_date_alias(
            canonical_name="password_inactive_at", canonical_value=password_inactive_at,
            legacy_name="password_inactive", legacy_value=password_inactive,
        )
        self.account_expires_at = _resolve_date_alias(
            canonical_name="account_expires_at", canonical_value=account_expires_at,
            legacy_name="account_expires", legacy_value=account_expires,
        )
        self.minimum_days = minimum_days
        self.maximum_days = maximum_days
        self.warning_days = warning_days
        self.inactive_days = inactive_days
        self.raw_fields = dict(raw_fields or {})

    @property
    def last_changed(self) -> str | None:
        return self.last_changed_at

    @property
    def password_expires(self) -> str | None:
        return self.password_expires_at

    @property
    def password_inactive(self) -> str | None:
        return self.password_inactive_at

    @property
    def account_expires(self) -> str | None:
        return self.account_expires_at

    def to_policy_dict(self) -> dict[str, Any]:
        return {
            "target": self.username,
            "last_changed_at": self.last_changed_at,
            "password_expires_at": self.password_expires_at,
            "password_inactive_at": self.password_inactive_at,
            "account_expires_at": self.account_expires_at,
            "min_password_age_days": self.minimum_days,
            "max_password_age_days": self.maximum_days,
            "warning_days": self.warning_days,
            "inactive_days": self.inactive_days,
            "password_expired": self.expired,
            "force_password_change": self.requires_change,
            "password_status": self.status,
        }


@dataclass(frozen=True, slots=True)
class UserIdentity:
    username: str
    uid: int

    @property
    def is_administrative(self) -> bool:
        return self.uid == 0
