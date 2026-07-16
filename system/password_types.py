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
    last_changed: str | None = None
    password_expires: str | None = None
    password_inactive: str | None = None
    account_expires: str | None = None
    minimum_days: int | None = None
    maximum_days: int | None = None
    warning_days: int | None = None
    inactive_days: int | None = None
    raw_fields: dict[str, Any] = field(default_factory=dict)

    def to_policy_dict(self) -> dict[str, Any]:
        return {
            "target": self.username,
            "last_changed_at": self.last_changed,
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
