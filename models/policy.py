from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from enum import Enum
from typing import Any, Mapping, Self

from utils.errors import (
    AccountExpirationError,
    InactivityPolicyError,
    LoginRestrictionError,
    PolicyError
)

ADMIN_TARGET_NAME = frozenset({"root", "admin", "sudo", "wheel"})
DEFAULT_INACTIVE_DAYS = 30
DEFAULT_WARNING_DAYS = 7
EXPIRATION_NEVER = "never"
EXPIRATION_NOT_CONFIGURED = "not_configured"
NON_INTERACTIVE_SHELL_MARKERS = ("nologin", "false")
RECOMMENDED_MAX_PASSWORD_AGE_DAYS = 90
RECOMMENDED_MIN_PASSWORD_AGE_DAYS = 0

class PolicyType(str, Enum):
    EXPIRATION = "expiration"
    PASSWORD = "password"
    INACTIVITY = "inactivity"
    LOGIN = "login"
    COMBINED = "combined"
    TEMPLATE_INHERITED = "template_inherited"
    MANUAL = "manual"

class PolicyStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    APPLIED = "applied"
    PARTIALLY_APPLIED = "partially_applied"
    INVALID = "invalid"
    UNKNOWN = "unknown"

class PolicyImpact(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class PolicyOrigin(str, Enum):
    CLI = "cli"
    TEMPLATE = "template"
    GLOBAL_CONFIG = "global_config"
    SYSTEM = "system"
    BACKUP = "backup"
    REPORT = "report"
    TEST = "test"

class LoginRestrictionType(str, Enum):
    NON_INTERCTIVE_SHELL = "non_interactive_shell"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_EXPIRATION = "account_expiration"
    LOGIN_ALLOWED = "login_allowed"
    LOGIN_DENIED = "login_denied"
    UNKNOWN = "unknown"

class ExpirationState(str, Enum):
    VALID  = "valid"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    NEVER_EXPIRES = "never_expires"
    INMEDIATE = "inmediate"
    UNKNOWN = "unknown"


class InactivityAction(str, Enum):
    WARN = "warn"
    LOCK = "lock"
    EXPIRE = "expire"
    DISABLE = "disable"
    NONE = "none"

@dataclass(slots=True)
class SecurityPolicy:
    name: str
    policy_type: PolicyType
    status: PolicyStatus = PolicyStatus.UNKNOWN
    target: str | None = None
    origin: PolicyOrigin = PolicyOrigin.SYSTEM
    impact: PolicyImpact = PolicyImpact.LOW
    description: str | None = None
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.policy_type = _coerce_enum(self.policy_type, PolicyType, PolicyType.MANUAL)
        self.status = _coerce_enum(self.status, PolicyStatus, PolicyStatus.UNKNOWN)
        self.origin = _coerce_enum(self.origin, PolicyOrigin, PolicyOrigin.SYSTEM)
        self.impact = _coerce_enum(self.impact, PolicyImpact, PolicyImpact.LOW)
        self.warnings = [str(item) for item in self.warnings]
        self.metadata = dict(self.metadata or {})
        if not str(self.name).strip():
            raise PolicyError("Policy name cannot be empty.", details={"field": "name"})
        self.name = str(self.name).strip()
        if self.target is not None:
            self.target = str(self.target).strip() or None
    
    @property
    def has_critical_impact(self) -> bool:
        return self.impact == PolicyImpact.CRITICAL
    
    @property
    def is_safe_for_automatic_apply(self) -> bool:
        return self.impact == PolicyImpact.CRITICAL
    
    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)
    
    def to_dict(self) -> dict[str, Any]:
        return _clean_dict(
            {
                "name": self.name,
                "policy_type": self.policy_type.value,
                "status": self.status.value,
                "target": self.target,
                "origin": self.origin.value,
                "impact": self.impact.value,
                "description": self.description,
                "warnings": list(self.warnings),
                "metadata": _json_safe(self.metadata)
            }
        )
    
    def to_audit_dict(self) -> dict[str, Any]:
        return {
                "name": self.name,
                "policy_type": self.policy_type.value,
                "status": self.status.value,
                "target": self.target,
                "origin": self.origin.value,
                "impact": self.impact.value,
                "warnings": list(self.warnings),
        }
    
    def to_report_dict(self) -> dict[str, Any]:
        return self.to_dict()
    
    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.policy_type.value,
            "status": self.status.value,
            "target": self.target,
            "impact": self.impact.value
        }

@dataclass(slots=True)
class ExpirationPolicy(SecurityPolicy):
    expires_at: date | None = None
    expire_immediately: bool = False
    never_expires: bool = False
    effective_at: date | None = None

    def __init__(
        self,
        *,
        name: str = "account_expiration",
        expires_at: date | str | None = None,
        expire_immediately: bool = False,
        never_expires: bool = False,
        effective_at: date | str | None = None,
        status: PolicyStatus = PolicyStatus.UNKNOWN,
        target: str | None = None,
        origin: PolicyOrigin = PolicyOrigin.SYSTEM,
        impact: PolicyImpact = PolicyImpact.LOW,
        description: str | None = None,
        warnings: list[str] | None = None,
        metadata: Mapping[str, Any] | None = None
    ) -> None:
        super().__init__(name, PolicyType.EXPIRATION, status, target, origin, impact, description, warnings or [], dict(metadata or {}))
        self.expires_at = _parse_date(expires_at, "expires_at")
        self.expire_immediately = bool(expire_immediately)
        self.never_expires = bool(never_expires)
        self.effective_at = _parse_date(effective_at, "effective_at")
        self._validate_expiration()
        if self.expire_immediately:
            self.impact = _max_impact(self.impact, PolicyImpact.CRITICAL)
    
    @property
    def days_remaining(self) -> int | None:
        if self.never_expires or self.expires_at is None:
            return None
        return (self.expires_at - date.today()).days
    
    @property
    def is_expired(self) -> bool:
        return self.expire_immediately or (self.expires_at is not None and self.expires_at < date.today())
    
    @property
    def is_expiring_soon(self) -> bool:
        return self.days_remaining is not None and 0 <= self.days_remaining <= DEFAULT_WARNING_DAYS
    
    @property
    def expiration_state(self) -> ExpirationState:
        if self.expire_immediately:
            return ExpirationState.INMEDIATE
        if self.never_expires:
            return ExpirationState.NEVER_EXPIRES
        if self.expires_at is None:
            return ExpirationState.UNKNOWN
        if self.is_expired:
            return ExpirationState.EXPIRING_SOON
        return ExpirationState.VALID
    
    @property
    def blocks_login(self) -> bool:
        return self.is_expired
        
    def _validate_expiration(self) -> None:
        if self.never_experies and (self.expires_at is not None or self.expire_immediately):
            raise AccountExpirationError("A policy cannot both never expire and define an expiration.")
        
    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data.update(
            {
                "expires_at": _date_to_str(self.expires_at),
                "expire_immediately": self.expire_immediately,
                "never_expires": self.never_expires,
                "effective_at": _date_to_str(self.effective_at),
                "days_remaining": self.days_remaining,
                "expiration_state": self.expiration_state.value,
                "blocks_login": self.blocks_login
            }
        )
        return _clean_dict(data)

@dataclass(slots=True)
class PasswordPolicy(SecurityPolicy):
    min_password_age_days: int | None = RECOMMENDED_MIN_PASSWORD_AGE_DAYS
    max_password_age_days: int | None = RECOMMENDED_MAX_PASSWORD_AGE_DAYS
    warning_days: int | None = DEFAULT_WARNING_DAYS
    last_changed_at: date | None = None
    force_password_change: bool = False
    password_expired: bool | None = None

    def __init__(
        self,
        *,
        name: str = "password_policy",
        min_password_age_days: int | None = RECOMMENDED_MIN_PASSWORD_AGE_DAYS,
        max_password_age_days: int | None = RECOMMENDED_MAX_PASSWORD_AGE_DAYS,
        warning_days: int | None = DEFAULT_WARNING_DAYS,
        last_changed_at: date | str | None = None,
        force_password_change: bool = False,
        password_expired: bool | None = None,
        status: PolicyStatus = PolicyStatus.UNKNOWN,
        target: str | None = None,
        origin: PolicyOrigin =  PolicyOrigin.SYSTEM,
        impact: PolicyImpact = PolicyImpact.LOW,
        description: str | None = None,
        warnings: list[str] | None = None,
        metadata: Mapping[str, Any] | None = None 
    ) -> None:
        super().__init__(name, PolicyType.PASSWORD, status, target, origin, impact, description, warnings or [], dict(metadata or {}))
        self.min_password_age_days = _validate_optional_days(min_password_age_days, "min_password_age_days")
        self.max_password_age_days = _validate_optional_days(max_password_age_days, "max_password_age_days")
        self.warning_days = _validate_optional_days(warning_days, "warning_days")
        self.last_changed_at = _parse_date(last_changed_at, "last_changed_at")
        self.force_password_change = bool(force_password_change)
        self.password_expired = password_expired if password_expired is None else bool(password_expired)
        self._validate_password_age()
        if self.force_password_change:
            self.impact = _max_impact(self.impact, PolicyImpact.HIGH)
    
    @property
    def password_expires_at(self) -> date | None:
        if self.last_changed_at is None or self.max_password_age_days in (None, 0):
            return None
        return self.last_changed_at + timedelta(days=self.max_password_age_days)
    
    @property
    def is_password_expired(self) -> bool:
        if self.password_expired is not None:
            return self.password_expired
        return self.password_expires_at is not None and self.password_expires_at < date.today()
    
    @property
    def is_password_expiring_soon(self) -> bool:
        if self.password_expires_at is None or self.warning_days is None:
            return False
        remaining = (self.password_expires_at - date.today()).days
        return 0 <= remaining <= self.warning_days
    
    @property
    def requires_password_change(self) -> bool:
        return self.force_password_change or self.is_password_expired
    
    def _validate_password_age(self) -> None:
        if None not in (self.min_password_age_days, self.max_password_age_days) and self.min_password_age_days > self.max_password_age_days:
            raise PolicyError("min_password_age_days connot be greater than max_password_age_days.")
        
    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data.update(
            {
                "min_password_age_days": self.min_password_age_days,
                "max_password_age_days": self.max_password_age_days,
                "warning_days": self.warning_days,
                "last_changed_at": _date_to_str(self.last_changed_at),
                "password_expires_at": _date_to_str(self.password_expires_at),
                "force_password_change": self.force_password_change,
                "password_expired": self.is_password_expired,
                "requires_password_change": self.requires_password_change,
                "password_expiring_soon": self.is_password_expiring_soon
            }
        )
        return _clean_dict(data)

@dataclass(slots=True)
class InactivityPolicy(SecurityPolicy):
    #      Represents policies related to user inactivity, including the number of inactive days before action is taken, the type of action to be taken (warn, lock, expire, disable), whether the account is disabled after the action, and whether the policy is strict. It includes logic to determine if the policy is active based on its status and configuration, and whether it blocks login.
    inactive_days: int | None = DEFAULT_INACTIVE_DAYS
    action: InactivityAction = InactivityAction.LOCK   
    disables_account: bool = False
    strict: bool = False

    def __init__(
        self,
        *,
        name: str = "inactivity_policy",
        inactive_days: int | None = DEFAULT_INACTIVE_DAYS,
        action: InactivityAction | str = InactivityAction.LOCK,
        disables_account: bool = False,
        strict: bool = False,
        status: PolicyStatus = PolicyStatus.UNKNOWN,
        target: str | None = None,
        origin: PolicyOrigin =  PolicyOrigin.SYSTEM,
        impact: PolicyImpact = PolicyImpact.MEDIUM,
        description: str | None = None,
        warnings: list[str] | None = None,
        metadata: Mapping[str, Any] | None = None 
    ) -> None:
        super().__init__(name, PolicyType.INACTIVITY, status, target, origin, impact, description, warnings or [], dict(metadata or {}))
        self.inactive_days = _validate_optional_days(inactive_days, "inactive_days")
        self.action = _coerce_enum(action, InactivityAction, InactivityAction.NONE)
        self.disables_account = bool(disables_account)
        self.strict = bool(strict)
        if self.action in {InactivityAction.LOCK, InactivityAction.EXPIRE, InactivityAction.DISABLE} or self.disables_account:
            self.impact = _max_impact(self.impact, PolicyImpact.HIGH)
        if self.strict:
            self.impact = _max_impact(self.impact, PolicyImpact.HIGH)
        
    @property
    def is_active(self) -> bool:
        return self.status == PolicyStatus.ACTIVE and self.inactive_days is not None and self.action != InactivityAction.NONE
    
    @property
    def blocks_login(self) -> bool:
        return self.action in {InactivityAction.LOCK, InactivityAction.EXPIRE, InactivityAction.DISABLE} or self.disables_account

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data.update(
            {
                "inactive_days": self.inactive_days,
                "action": self.action.value,
                "disable_account": self.disables_account,
                "strict": self.strict,
                "is_active": self.is_active,
                "blocks_login": self.blocks_login
            }
        )
        return _clean_dict(data)

@dataclass(slots=True)
class LoginRestrictionPolicy(SecurityPolicy):
    #       Represents policies that restrict user login based on various criteria such as allowed login status, restricted shells, account lock status, and interactive access. It includes logic to determine if login is blocked and to infer the type of restriction based on the provided attributes.


    login_allowed: bool = True 
    restricted_shell: str | None = None
    account_locked: bool = False
    interactive_access_disabled: bool = False
    restriction_scope: str | None = None
    reason: str | None = None
    reastriction_type: LoginRestrictionType = LoginRestrictionType.LOGIN_ALLOWED

    def __init__(
        self,
        *,
        name: str = "login_restriction",
        login_allowed: bool = True,
        restricted_shell: str | None = None,
        account_locked: bool = False,
        interactive_access_disabled: bool = False,
        restriction_scope: str | None = None,
        reason: str | None = None,
        restriction_type: LoginRestrictionType | str | None =  None,
        status: PolicyStatus = PolicyStatus.UNKNOWN,
        target: str | None = None,
        origin: PolicyOrigin = PolicyOrigin.SYSTEM,
        impact: PolicyImpact = PolicyImpact.LOW,
        description: str | None = None,
        warnings: list[str] | None = None,
        metadata: Mapping[str, Any] | None = None 
    ) -> None:
        #       Initializes a LoginRestrictionPolicy with various parameters that define the login restrictions for a user. It validates the input parameters, infers the restriction type if not provided, and determines the overall impact of the policy based on whether it blocks login.
        super().__init__(name, PolicyType.LOGIN, status, target, origin, impact, description, warnings or [], dict(metadata or {}))
        self.login_allowed = bool(login_allowed)
        self.restricted_shell = restricted_shell
        self.account_locked = bool(account_locked)
        self.interactive_access_disabled = bool(interactive_access_disabled)
        self.restriction_scope = restriction_scope
        self.reason = reason
        self.restriction_type = _coerce_enum(restriction_type or self._infer_restriction_type(), LoginRestrictionType, LoginRestrictionType.UNKNOWN)
        self._validate_login_restriction()
        if self.blocks_login:
            self.impact = _max_impact(self.impact, PolicyImpact.CRITICAL)

    @property
    def blocks_login(self) -> bool:
        #      Determines if the login is blocked based on the policy's attributes. Login is considered blocked if login is not allowed, the account is locked, or the restriction type is set to LOGIN_DENIED.
        return not self.login_allowed or self.account_locked or self.restriction_type == LoginRestrictionType.LOGIN_DENIED

    @property
    def disables_interactive_login(self) -> bool:
        #       Determines if interactive login is disabled based on the policy's attributes. Interactive login is considered disabled if interactive access is explicitly disabled or if the restricted shell contains markers that indicate a non-interactive shell.
        shell = (self.restricted_shell or "").lower()
        return self.interactive_access_disabled or any(marker in shell for marker in NON_INTERACTIVE_SHELL_MARKERS)
    
    def _infer_restriction_type(self) -> LoginRestrictionType:
        # infiere el tipo de restricción de login basado en los atributos del policy. Si login_allowed es False, se considera LOGIN_DENIED. Si account_locked es True, se considera ACCOUNT_LOCKED. Si disables_interactive_login es True, se considera NON_INTERACTIVE_SHELL. Si ninguna de estas condiciones se cumple, se considera LOGIN_ALLOWED.
        if not self.login_allowed:
            return LoginRestrictionType.LOGIN_DENIED
        if self.account_locked:
            return LoginRestrictionType.ACCOUNT_LOCKED
        if self.disables_interactive_login:
            return LoginRestrictionType.NON_INTERCTIVE_SHELL
        return LoginRestrictionType.LOGIN_ALLOWED
    
    def _validate_login_restriction(self) -> None:
        #       Validates the consistency of the login restriction policy. It checks for conflicting settings, such as having a non-interactive shell while allowing login, or having an account locked but still allowing login. It raises a LoginRestrictionError if any inconsistencies are found.
        if self.reastriction_type == LoginRestrictionType.LOGIN_ALLOWED and not self.login_allowed:
            raise LoginRestrictionError("login_allowed cannot be false for a login_allowed restriction.")
        
    def to_dict(self) -> dict[str, Any]:
        #      Converts the LoginRestrictionPolicy to a dictionary representation, including all relevant attributes and their values. It also includes computed properties such as whether the policy blocks login or disables interactive login.
        data = super().to_dict()
        data.update(
            {
                "login_allowed": self.login_allowed,
                "restricted_shell": self.restricted_shell,
                "account_locked": self.account_locked,
                "interactive_access_disabled": self.interactive_access_disabled,
                "restriction_scope": self.restriction_scope,
                "reason": self.reason,
                "restriction_type": self.restriction_type.value,
                "blocks_login": self.blocks_login,
                "disables_interactive_login": self.disables_interactive_login
            }
        )
        return _clean_dict(data)
        
@dataclass(slots=True)
class UserSecurityPolicy:
    #       Represents the combined security policies for a specific user, aggregating expiration, password, inactivity, and login restriction policies along with their overall impact and warnings.
    username: str
    expiration: ExpirationPolicy | None = None
    password: PasswordPolicy | None = None
    inactivity: InactivityPolicy | None = None
    login: LoginRestrictionPolicy | None = None
    origin: PolicyOrigin = PolicyOrigin.SYSTEM
    impact: PolicyImpact = PolicyImpact.LOW
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        #       Validates and normalizes the username, ensuring it is a non-empty string. Coerces the origin and impact to their respective enums, and ensures warnings and metadata are in the correct format.
        #       Raises:
        #           PolicyError: If the username is empty or invalid, or if the origin or
        #           impact values are invalid.
        self.username = str(self.username).strip()
        if not self.username:
            raise PolicyError("Username cannot be empty.", details={"field": "username"})
        self.origin = _coerce_enum(self.origin, PolicyOrigin, PolicyOrigin.SYSTEM)
        self.impact = _coerce_enum(self.impact, PolicyImpact, PolicyImpact.LOW)
        self.warnings = [str(item) for item in self.warnings]
        self.metadata = dict(self.metadata or {})

    @property
    def blocks_login(self) -> bool:
        #       Determines if any of the user's policies block login based on their respective criteria.
        #       Returns:
        #           True if any policy blocks login, False otherwise.
        return bool((self.expiration and self.expiration.blocks_login) or (self.login and self.login.blocks_login) or (self.inactivity and self.inactivity.blocks_login))
    
    @property
    def is_expired(self) -> bool:
        #       Determines if any of the user's policies are expired based on their respective criteria.
        #       Returns:
        #           True if any policy is expired, False otherwise.
        return bool(self.expiration and self.expiration.is_expired)
    
    @property
    def is_expiring_soon(self) -> bool:
        #       Determines if any of the user's policies are expiring soon based on their respective criteria.
        #       Returns:
        #           True if any policy is expiring soon, False otherwise.
        return bool((self.expiration and self.expiration.is_expiring_soon) or (self.password and self.password.is_password_expiring_soon))
    
    @property
    def requires_password_change(self) -> bool:
        #       Determines if the user is required to change their password based on the password policy.
        #       Returns:
        #           True if a password change is required, False otherwise.
        return bool(self.password and self.password.requires_password_change)
    
    @property
    def has_critical_impact(self) -> bool:
        #       Determines if any of the user's policies have a critical impact on security.
        #       Returns:
        #           True if any policy has a critical impact, False otherwise.
        return self.impact == PolicyImpact.CRITICAL or self.blocks_login
    
    @property
    def is_safe_for_automatic_apply(self) -> bool:
        #       Determines if the user's policies are safe to apply automatically without user intervention.
        #       Returns:
        #           True if the policies are safe for automatic application, False otherwise.
        return self.impact in {PolicyImpact.LOW, PolicyImpact.MEDIUM} and not self.blocks_login and not self.has_warnings
    
    @property
    def has_warnings(self) -> bool:
        #       Checks if there are any warnings associated with the user's policies.
        #       Returns:
        #           True if there are warnings, False otherwise.
        return bool(self.warnings)
    
    @property
    def all_warnings(self) -> list:
    #       Collects warnings from all policies into a single list.
    #       Returns:
    #           A list of warning messages.
        warnings = list(self.warnings) 
        for policy in self._policies():
            warnings.extend(policy.warnings)
        if self.has_critical_impact: 
            warnings.append("Policy has critical operational impact.")
        if self.username in ADMIN_TARGET_NAME and self.requires_password_change: 
            warnings.append("Password change forced for an administrative target.")
        return list(dict.fromkeys(warnings)) 

    def _policies(self) -> list[SecurityPolicy]:
        #      Helper method to get a list of all policies associated with the user, excluding None values.
        #      Returns:
        #          A list of SecurityPolicy instances that are not None.
        return [p for p in (self.expiration, self.password, self.inactivity, self.login) if p is not None] 
    
    def to_dict(self) -> dict[str, Any]:
       #     Converts the UserSecurityPolicy to a dictionary representation, including all relevant attributes and their values. It also aggregates warnings from all policies and includes metadata in a JSON-safe format.
        return _clean_dict(
            {
                "username": self.username, 
                "policy_type": PolicyType.COMBINED.value, 
                "origin": self.origin.value, 
                "impact": self.impact.value,
                "expiration": self.expiration.to_dict() if self.expiration else None, 
                "password": self.password.to_dict() if self.password else None,
                "inactivity": self.inactivity.to_dict() if self.inactivity else None,
                "login": self.login.to_dict() if self.login else None,
                "warnings": self.all_warnings,
                "metadata": _json_safe(self.metadata), 
            }
        )
    
    def to_audit_dict(self) -> dict[str, Any]:
        #    Converts the UserSecurityPolicy to a dictionary representation suitable for auditing purposes, including key attributes such as username, policy type, origin, impact, and aggregated warnings.
        return {
            "username": self.username, 
            "policy_type": PolicyType.COMBINED.value, 
            "origin": self.origin.value, 
            "impact": self.impact.value,
            "blocks_login": self.blocks_login,
            "requires_password_change": self.requires_password_change,
            "policies": [p.to_audit_dict() for p in self._policies()],
            "warnings": self.all_warnings,
        }
    
    def to_report_dict(self) -> dict[str, Any]:
        #     Converts the UserSecurityPolicy to a dictionary representation suitable for reporting purposes, including key attributes such as username, expiration state, password status, inactivity status, login restrictions, impact, and aggregated warnings.
        return {
            "username": self.username, 
            "expiration_state": self.expiration.expiration_state.value if self.expiration else ExpirationState.UNKNOWN.value,
            "password_expired": self.password.is_password_expired if self.password else None,
            "password_expiring_soon": self.password.is_password_expiring_soon if self.password else None,
            "inactive_days": self.inactivity.inactive_days if self.inactivity else None,
            "login_allowed": self.login.login_allowed if self.login else None,
            "login_blocked": self.blocks_login,
            "impact": self.impact.value,
            "warnings": self.all_warnings,
        }
    
    def to_summary_dict(self) -> dict[str, Any]:
        #     Converts the UserSecurityPolicy to a dictionary representation suitable for summary reporting purposes, including key attributes such as username, expiration status, password status, inactivity status, login restrictions, impact, and aggregated warnings.
        return PolicySummary.from_user_policy(self).to_dict()
    
    @classmethod
    def from_chage_data(cls, username: str, data: Mapping[str, Any], *, origin: PolicyOrigin = PolicyOrigin.SYSTEM) -> Self:
        #     Creates a UserSecurityPolicy instance from data typically obtained from the 'chage' command, which provides information about user account expiration and password policies. It extracts relevant attributes to construct the expiration, password, and inactivity policies, and aggregates them into a UserSecurityPolicy instance.
        expiration = ExpirationPolicy(
            expires_at=_none_if_never(data.get("account_expires") or data.get("expires_at")), 
            never_expires=_is_never(data.get("account_expires")),
            target=username, 
            origin=origin
        )
        password = PasswordPolicy(
            last_changed_at=data.get("last_password_change"),
            max_password_age_days=_int_or_none(data.get("maximum_password_age")),
            min_password_age_days=_int_or_none(data.get("minimum_password_age")),
            warning_days=_int_or_none(data.get("password_warning_period")),
            password_expired=_bool_or_none(data.get("password_expired")),
            target=username,
            origin=origin
        )
        inactivity = InactivityPolicy(
            inactive_days=_int_or_none(data.get("password_inactive") or data.get("inactive_days")),
            target=username,
            origin=origin
        )
        return cls(username=username, expiration=expiration, password=password, inactivity=inactivity, origin=origin, metadata={"source": "chage"})

    @classmethod
    def from_account_state(
        cls,
        username: str,
        *,
        account_locked: bool = False,
        restricted_shell: str | None = None,
        login_allowed: bool | None = None,
        expires_at: date | str | None = None,
        origin: PolicyOrigin = PolicyOrigin.SYSTEM,
        metadata: Mapping[str, Any] | None = None
        ) -> Self:
        login = LoginRestrictionPolicy(
            login_allowed=(not account_locked if login_allowed is None else login_allowed),
            restricted_shell=restricted_shell,
            account_locked=account_locked,
            target=username,
            origin=origin
        )
        expiration = ExpirationPolicy(
            expires_at=expires_at,
            target=username,
            origin=origin
        )  if expires_at is not None else None
        return cls(username=username, login=login, expiration=expiration, origin=origin, metadata=dict(metadata or {}))
    
    @classmethod
    def from_partial_data(
        cls,
        username: str,
        *,
        data: Mapping[str, Any],
        origin: PolicyOrigin = PolicyOrigin.SYSTEM, 
    ) -> Self:
        #    Creates a UserSecurityPolicy instance from partial data, which may include any combination of expiration, password, inactivity, and login policy attributes. It constructs the corresponding policy instances based on the provided data and aggregates them into a UserSecurityPolicy.
        return cls.from_template(username, data, origin=origin)
    
    @classmethod
    def from_cli(
        cls,
        username: str,
        *,
        expires_at: date | str | None = None,
        maz_password_age_days: int | None = None,
        inactive_days: int | None = None,
        force_password_change: bool = False,
        blocks_login: bool = False,
        origin: PolicyOrigin = PolicyOrigin.CLI,
    ) -> Self:
        #   Creates a UserSecurityPolicy instance from command-line interface (CLI) data, which may include attributes related to account expiration, password age, inactivity, and login restrictions. It constructs the corresponding policy instances based on the provided CLI data and aggregates them into a UserSecurityPolicy.
        return cls(
            username=username,
            expiration=ExpirationPolicy(
                expires_at=expires_at,
                target=username,
                origin=origin
            ) if expires_at is not None else None,
            password=PasswordPolicy(
                max_password_age_days=maz_password_age_days,
                force_password_change=force_password_change,
                target=username,
                origin=origin
            ) if maz_password_age_days is not None or force_password_change else None,
            inactivity=InactivityPolicy(
                inactive_days=inactive_days,
                target=username,
                origin=origin
            ) if inactive_days is not None else None,
            login=LoginRestrictionPolicy(
                login_allowed=(not blocks_login),
                account_locked= blocks_login,
                target=username,
                origin=origin
            ) if blocks_login else None,
            origin=origin
        )
    
    @classmethod
    def from_template(
        cls,
        username: str,
        template_data: Mapping[str, Any],
        *,
        origin: PolicyOrigin = PolicyOrigin.TEMPLATE
    ) -> Self:
        #    Creates a UserSecurityPolicy instance from a template data structure, which may include nested configurations for expiration, password, inactivity, and login policies. It extracts the relevant sections from the template and constructs the corresponding policy instances, aggregating them into a UserSecurityPolicy.
        expiration_data = template_data.get("expiration") or {}
        password_data = template_data.get("password") or {}
        inactivity_data = template_data.get("inactivity") or {}
        login_data = template_data.get("login") or {}
        return cls(
            username=username,
            expiration=ExpirationPolicy(
                target=username,
                origin=origin,
                **expiration_data
            ) if expiration_data else None,
            password=PasswordPolicy(
                target=username,
                origin=origin,
                **password_data
            ) if password_data else None,
            inactivity=InactivityPolicy(
                target=username,
                origin=origin,
                **inactivity_data
            ) if inactivity_data else None,
            login=LoginRestrictionPolicy(
                target=username,
                origin=origin,
                **login_data
            ) if login_data else None,
            origin=origin,
            metadata={"template": template_data.get("name") or template_data.get("role")}
        )
    
    @classmethod
    def from_global_config(cls, username: str, config_data: Mapping[str, Any]) -> Self:
        #   Creates a UserSecurityPolicy instance from global configuration data, which may include default settings for expiration, password, inactivity, and login policies. It uses the global configuration as a template to construct the corresponding policy instances for the user, aggregating them into a UserSecurityPolicy.
        return cls.from_template(username, config_data, origin=PolicyOrigin.BACKUP)
    
    @classmethod
    def from_backup(cls, username: str, backup_data: Mapping[str, Any]) -> Self:
        #  Creates a UserSecurityPolicy instance from backup data, which may include previously saved configurations for expiration, password, inactivity, and login policies. It extracts the relevant sections from the backup data and constructs the corresponding policy instances, aggregating them into a UserSecurityPolicy.
        policy_data = backup_data.get("policy", backup_data)
        return cls.from_template(username, policy_data, origin=PolicyOrigin.BACKUP)

@dataclass(slots=True)
class PolicyApplySpec:
    username: str
    policy:  UserSecurityPolicy
    dry_run: bool = True
    requires_confirmation: bool = True
    estimated_impact: PolicyImpact = PolicyImpact.LOW
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        #       Validates and normalizes the username, ensuring it is a non-empty string. Coerces the estimated impact to its respective enum, and ensures metadata is in the correct format. It also determines if confirmation is required based on the estimated impact and the policy's criticality.
        self.estimated_impact = _max_impact(_coerce_enum(self.estimated_impact, PolicyImpact, PolicyImpact.LOW), self.policy.impact)
        self.requires_confirmation = bool(self.requires_confirmation or self.policy.has_critical_impact)

    def to_dict(self) -> dict[str, Any]:
        #      Converts the PolicyApplySpec to a dictionary representation, including key attributes such as username, policy details, dry run status, confirmation requirement, estimated impact, and metadata in a JSON-safe format.
        return {
            "username": self.username,
            "policy": self.policy.to_dict(),
            "dry_run": self.dry_run,
            "requires_confirmation": self.requires_confirmation,
            "estimated_impact": self.estimated_impact.value,
            "metadata": _json_safe(self.metadata)
        }
    
@dataclass(slots=True)
class PolicyUpdateSpec:
    username: str
    new_expiration: date | None = None
    new_max_password_age_days: int | None = None
    new_inactive_days: int | None = None
    new_login_restriction: LoginRestrictionPolicy | None = None
    force_password_change: bool | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        #       Validates and normalizes the username, ensuring it is a non-empty string. It also ensures that the new login restriction, if provided, is a valid LoginRestrictionPolicy instance, and that metadata is in the correct format.
        self.new_expiration = _parse_date(self.new_expiration, "new_expiration")
        self.new_max_password_age_days = _validate_optional_days(self.new_max_password_age_days, "new_max_password_age_days")
        self.new_inactive_days = _validate_optional_days(self.new_inactive_days, "new_inactive_days")
        if self.new_login_restriction is not None:
            self.new_login_restriction = _coerce_enum(self.new_login_restriction, LoginRestrictionType, LoginRestrictionType.UNKNOWN)

    def to_dict(self) -> dict[str, Any]:
        return _clean_dict(
            {
                "username": self.username,
                "new_expiration": _date_to_str(self.new_expiration),
                "new_max_password_age_days": self.new_max_password_age_days,
                "new_inactive_days": self.new_inactive_days,
                "new_login_restriction": self.new_login_restriction.value if self.new_login_restriction else None,
                "force_password_change": self.force_password_change,
                "metadata": _json_safe(self.metadata)
            }
        )

@dataclass(slots=True)
class PolicySummary:
    #    Represents a concise summary of a user's security policies, including key attributes such as username, expiration status, password status, inactivity status, login restrictions, impact, and warnings. It provides a simplified view of the user's security posture for quick assessment and reporting.
    username: str
    expiration_status: str = ExpirationState.UNKNOWN.value
    password_status: str = PolicyStatus.UNKNOWN.value
    inactivity: int | None = None
    login_allowed: bool | None = None
    impact: PolicyImpact = PolicyImpact.LOW
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def from_user_policy(cls, policy: UserSecurityPolicy) -> Self:
        #     Creates a PolicySummary instance from a UserSecurityPolicy, extracting key attributes such as username, expiration status, password status, inactivity status, login restrictions, impact, and aggregated warnings for a concise summary representation.
        return cls(
            username=policy.username,
            expiration_status=policy.expiration.expiration_state.value if policy.expiration else ExpirationState.UNKNOWN.value,
            password_status="expired" if policy.password and policy.password.is_password_expired else "ok" if policy.password else PolicyStatus.UNKNOWN.value, 
            inactivity=_int_or_none(policy.inactivity.inactive_days) if policy.inactivity else None,
            login_allowed=policy.login.login_allowed if policy.login else None,
            impact=policy.impact,
            warnings=policy.all_warnings
        )
    
    def to_dict(self) -> dict[str, Any]:
        #     Converts the PolicySummary to a dictionary representation, including all relevant attributes and their values for a concise summary of the user's security policies.
        return {
            "username": self.username,
            "expiration_status": self.expiration_status,
            "password_status": self.password_status,
            "inactivity": self.inactivity,
            "login_allowed": self.login_allowed,
            "impact": self.impact.value,
            "warnings": self.warnings
        }

@dataclass(slots=True)
class PolicyDiff:
    current: UserSecurityPolicy | None
    desired: UserSecurityPolicy
    changes: dict[str, Any] = field(default_factory=dict)
    impact: PolicyImpact = PolicyImpact.LOW
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        #      Initializes the PolicyDiff instance by calculating the differences between the current and desired UserSecurityPolicy instances. It populates the changes dictionary with the specific differences for each policy attribute, determines the overall impact of the changes, and aggregates any warnings from both the current and desired policies.
        if not self.changes:
            self.changes = self._calculate_changes()
        self.impact = _max_impact(self.impact, self.desired.impact)
        self.warnings = list(dict.fromkeys([*self.warnings, *self.desired.all_warnings])) 
    
    @property
    def has_changes(self) -> bool:
        #      Determines if there are any changes between the current and desired UserSecurityPolicy instances. It checks if the changes dictionary is non-empty, indicating that there are differences in policy attributes.
        return bool(self.changes)
    
    def _calculate_changes(self) -> None:
        #     Calculates the differences between the current and desired UserSecurityPolicy instances, identifying changes in expiration, password, inactivity, and login policies. It populates the changes dictionary with the specific differences for each policy attribute, indicating the previous and new values.
        if self.current is None:
            return {"policy": {"from": None, "to": self.desired.to_summary_dict()}} 
        changes: dict[str, Any] = {}
        for key in {"expiration", "password", "inactivity", "login"}:
            left = getattr(self.current, key) 
            right = getattr(self.desired, key) 
            left_data = left.to_dict() if left else None
            right_data = right.to_dict() if right else None
            if left_data != right_data:
                changes[key] = {"from": left_data, "to": right_data}
        
        return changes
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "current": self.current.to_summary_dict() if self.current else None,
            "desired": self.desired.to_summary_dict(),
            "changes": _json_safe(self.changes),
            "impact": self.impact.value,
            "warnings": list(self.warnings),
            "has_changes": self.has_changes
        }

def _validate_optional_days(value: int | None, field_name: str) ->  int | None:
    if value is None:
        return None
    try:
        days = int(value)
    except (TypeError, ValueError) as exc:
        raise InactivityPolicyError(f"{field_name} must be an integer number of days.", details={"field": field_name, "value": value}) from exc
    if days < 0:
        raise InactivityPolicyError(f"{field_name} cannot be negative.", details={"field": field_name, "value": days})
    return days

def _parse_date(value: date | datetime | str | None, field_name: str) -> date | None:
    if value is None or _is_never(value):
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text or _is_never(text):
            return None
        try:
            return date.isoformat(text)
        except ValueError as exc:
            raise AccountExpirationError(f"{field_name} must be an ISO date (YYYY-MM-DD).", details={"field": field_name, "value": value}) from exc
    raise AccountExpirationError(f"{field_name} must be a date, datetime, ISO string or None.", details={"field": field_name})

def _date_to_str(value: date | None) -> str | None:
    return value.isoformat() if value is not None else None


def _json_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items() if not _looks_sensitive(str(k))}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    return value

def _clean_dict(data: Mapping[str, Any]) -> dict[str, Any]:
    return {key: _json_safe(value) for key, value in data.items() if value is not None}

def _coerce_enum(value: Any, enum_type: type[Enum], default: Any) -> Any:
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        if default is not None:
            return default
        raise PolicyError(f"Invalid {enum_type.__name__} value.", details={"value": value}) from exc
    
def _max_impact(*impacts: PolicyImpact) -> PolicyImpact:
    order = {PolicyImpact.LOW: 0, PolicyImpact.MEDIUM: 1, PolicyImpact.HIGH: 2, PolicyImpact.CRITICAL: 3}
    normalized = [_coerce_enum(impact, PolicyImpact, PolicyImpact.LOW) for impact in impacts if impact is not None]
    return max(normalized or [PolicyImpact.LOW], key=lambda item: order[item])

    
def _is_never(value: Any) -> bool:
    return str(value).strip().lower() in {"", "never", "none", "-1", EXPIRATION_NEVER, EXPIRATION_NOT_CONFIGURED}

def _none_if_never(value: Any) -> Any:
    #      Helper function to convert values that represent "never" or "none" to None. This is used to standardize the representation of policies that do not have an expiration or are not configured.
    return None if _is_never(value) else value 

def _int_or_none(value: Any) -> int | None:
    #      Helper function to convert a value to an integer if possible, or return None if the value represents "never" or "none". This is used for fields that can be either a number of days or a special value indicating no limit.
    if value is None or str(value).strip().lower() in {"", "none", "never", "-1"}:
        return None
    return int(value) 

def _bool_or_none(value: Any) -> bool | None:
    #      Helper function to convert a value to a boolean if possible, or return None if the value is None. This is used for fields that can be either a boolean or not set.
    if value is None: 
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "locked", "expired"}:
        return True 
    if text in {"0", "false", "no", "n", "active", "valid"}:
        return False
    return None

def _looks_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in ("password", "passwd", "secret", "hash", "shadow", "token"))


__all__ = [
    "PolicyType",
    "PolicyStatus",
    "PolicyImpact",
    "LoginRestrictionType",
    "ExpirationState",
    "InactivityAction",
    "SecurityPolicy",
    "ExpirationPolicy",
    "PasswordPolicy",
    "InactivityPolicy",
    "LoginRestrictionPolicy",
    "UserSecurityPolicy",
    "PolicyApplySpec",
    "PolicyUpdateSpec",
    "PolicySummary",
    "PolicyDiff",

]

#