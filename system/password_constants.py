from pathlib import Path

CMD_PASSWD = "passwd"
CMD_CHPASSWD = "chpasswd"
CMD_GETENT = "getent"
CMD_CHAGE = "chage"
CMD_USERMOD = "usermod"

SHADOW_PATH = Path("/etc/shadow")

ACTION_CHANGE_PASSWORD = "change_password"
ACTION_APPLY_GENERATED_PASSWORD = "apply_generated_password"
ACTION_EXPIRE_PASSWORD = "expire_password"
ACTION_FORCE_PASSWORD_CHANGE = "force_password_change"
ACTION_CLEAR_PASSWORD_EXPIRATION = "clear_password_expiration"
ACTION_LOCK_PASSWORD = "lock_password"
ACTION_UNLOCK_PASSWORD = "unlock_password"
ACTION_QUERY_PASSWORD_STATUS = "query_password_status"
ACTION_QUERY_USER_IDENTITY = "query_user_identity"
ACTION_SET_PASSWORD_POLICY = "set_password_policy"
ACTION_SET_PASSWORD_MAX_DAYS = "set_password_max_days"
ACTION_SET_PASSWORD_MIN_DAYS = "set_password_min_days"
ACTION_SET_PASSWORD_WARNING_DAYS = "set_password_warning_days"
ACTION_SET_PASSWORD_INACTIVE_DAYS = "set_password_inactive_days"

STATUS_ACTIVE = "active"
STATUS_LOCKED = "locked"
STATUS_UNKNOWN = "unknown"
STATUS_EXPIRED = "expired"
STATUS_NO_PASSWORD = "no_password"

CHAGE_LAST_CHANGE = "last_password_change"
CHAGE_PASSWORD_EXPIRES = "password_expires"
CHAGE_PASSWORD_INACTIVE = "password_inactive"
CHAGE_ACCOUNT_EXPIRES = "account_expires"
CHAGE_MIN_DAYS = "minimum_days_between_password_change"
CHAGE_MAX_DAYS = "maximum_days_between_password_change"
CHAGE_WARNING_DAYS = "warning_days_before_password_expires"

CHAGE_EXPECTED_FIELDS = (
    CHAGE_LAST_CHANGE,
    CHAGE_PASSWORD_EXPIRES,
    CHAGE_PASSWORD_INACTIVE,
    CHAGE_ACCOUNT_EXPIRES,
    CHAGE_MIN_DAYS,
    CHAGE_MAX_DAYS,
    CHAGE_WARNING_DAYS,
)

EXPIRE_IMMEDIATELY_VALUE = "0"
REDACTED_SECRET = "[REDACTED]"

REQUIRED_COMMANDS = (
    CMD_PASSWD,
    CMD_CHPASSWD,
    CMD_CHAGE,
    CMD_USERMOD,
    CMD_GETENT,
)

FORBIDDEN_PASSWORD_CODEPOINTS = frozenset({
    "\n",
    "\r",
    "\x00",
})

FORBIDDEN_PASSWORD_CODEPOINT_NAMES = {
    "\n": "LINE_FEED",
    "\r": "CARRIAGE_RETURN",
    "\x00": "NULL_BYTE",
}

SENSITIVE_COMMAND_OPTIONS = frozenset({
    "-p",
    "--password",
    "--secret",
    "--password-hash",
})

MAX_SANITIZE_DEPTH = 20
