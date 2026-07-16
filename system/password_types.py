from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .password_constants import STATUS_UNKNOWN


class PasswordCommandStrategy(StrEnum):
    PASSWD = "passwd"
    USERMOD = "usermod"


@dataclass(slots=True)
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

    @property
    def last_changed(self) -> str | None:
        return self.last_changed_at

    @property
    def password_expires(self) -> str | None:
        return self.password_expires_at

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
