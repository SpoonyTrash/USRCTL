from dataclasses import dataclass, field
from enum  import Enum
from typing import Callable, Sequence, Mapping

from utils.errors import ValidationError, PreventiveSecurityError
from  utils.output import CliOutput

YES_ANSWERS = frozenset({"y", "yes", "s", "si", "sí"})
NO_ANSWERS = frozenset({"n", "no"})

DEFAULT_ANSWER_YES = "yes"
DEFAULT_ANSWER_NO = "no"
SAFE_DEFAULT_ANSWER = DEFAULT_ANSWER_NO

RISK_HIGH = "[HIGH RISK]"
RISK_TAG_CRITICAL = "[CRITICAL]"

MSG_ABORTED_INVALID = "Operation aborted due to repeated invalid inputs."
MSG_BLOCKED_POLICY = "Operation blocked by confirmation policy."
MSG_CONTINUE_APPROVED = "Confirmation accepted. You may proceed with the operation."
MSG_CONTINUE_REJECTED = "Operation canceled by the operator."

@dataclass(slots=True)
class ConfirmationConfig:
    interactive: bool = True
    non_interactive_auto_confirm: bool = False
    default_answer: str = SAFE_DEFAULT_ANSWER
    max_attempts: int = 3
    silent: bool = False
    strict_critical: bool = True

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RISK_DISPLAY = {
    RiskLevel.LOW: "LOW RISK",
    RiskLevel.MEDIUM: "MEDIUM RISK",
    RiskLevel.HIGH: "HIGH RISK",
    RiskLevel.CRITICAL: "CRITICAL RISK",
}

class ConfirmationKind(str, Enum):
    SIMPLE = "simple"
    REINFORCED = "reinforced"
    CONTEXTUAL = "contextual"

class ConfirmationState(str, Enum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    ABORTED = "aborted"
    POLICY_BLOCKED = "policy_blocked"

@dataclass(slots=True)
class ConfirmationResult:
    state: ConfirmationState
    risk_level: RiskLevel
    kind: ConfirmationKind
    reason: str
    attempts_used: int = 0
    prompt: str = ""
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        return self.state is ConfirmationState.CONFIRMED
    
    @property
    def rejected(self) -> bool:
        return self.state is ConfirmationState.REJECTED
    
    @property
    def aborted(self) -> bool:
        return self.state is ConfirmationState.ABORTED

    @property
    def policy_blocked(self) -> bool:
        return self.state is ConfirmationState.POLICY_BLOCKED

class ConfirmationManager:
    def __init__(
        self,
        config: ConfirmationConfig | None = None,
        *,
        input_func: Callable[[str], str] = input,
        output: CliOutput | None = None
    ):
        self.config = config or ConfirmationConfig()
        self._input = input_func
        self._output = output
        self._validate_manager_configuration()
    
    def confirm(
        self,
        *,
        action: str,
        target: str,
        risk_level: RiskLevel = RiskLevel.MEDIUM,
        default_answer: str | None = None,
        impact: str | None = None,
        warning: str | None = None
    ) -> ConfirmationResult:
        normalized_default = {
            self._validate_default_answer(default_answer)
            if default_answer is not None
            else None
        }

        return self._run_yes_no_flow(
            kind=ConfirmationKind.SIMPLE,
            action=action,
            target=target,
            risk_level=risk_level,
            default_answer=normalized_default,
            impact=impact,
            warnings=[warning] if warning else None,
            dry_run=False
        )

    def confirm_with_context(
        self,
        *,
        action: str,
        target: str,
        impact: str,
        default_answer: str | None = None,
        risk_level: RiskLevel = RiskLevel.MEDIUM
    ) -> ConfirmationResult:
        normalized_default = {
            self._validate_default_answer(default_answer)
            if default_answer is not None
            else None
        }
        return self._run_yes_no_flow(
            kind=ConfirmationKind.CONTEXTUAL,
            action=action,
            target=target,
            risk_level=risk_level,
            default_answer=normalized_default,
            impact=impact,
            warnings=None,
            dry_run=False
        )

    def confirm_with_warning(
        self,
        *,
        action: str,
        target: str,
        warning: str,
        default_answer: str | None = None,
    ) -> ConfirmationResult:
        normalized_default = {
            self._validate_default_answer(default_answer)
            if default_answer is not None
            else None
        }
        return self._run_yes_no_flow(
            kind=ConfirmationKind.SIMPLE,
            action=action,
            target=target,
            risk_level=RiskLevel.MEDIUM,
            default_answer=normalized_default,
            impact=None,
            warnings=[warning],
            dry_run=False
        )
    
    def confirm_high_impact(
        self,
        *,
        action: str,
        target: str,
        expected_text: str,
        risk_level: RiskLevel,
        impact: str | None = None,
        warnings: Sequence[str] | None = None,
        irreversible: bool = False
    ) -> ConfirmationResult:
        if risk_level not in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            raise ValidationError(
                message="confirm_high_impact requires risk_level HIGH or CRITICAL"
            )
        return self._run_reinforced_flow(
            action=action,
            target=target,
            expected_text=expected_text,
            risk_level=risk_level,
            impact=impact,
            warnings=warnings,
            irreversible=irreversible
        )
    
    def confirm_irreversible(
        self,
        *,
        action: str,
        target: str,
        expected_text: str,
        impact: str | None = None,
        warnings: Sequence[str] | None = None
    ) -> ConfirmationResult:
        return self._run_reinforced_flow(
            action=action,
            target=target,
            expected_text=expected_text,
            risk_level=RiskLevel.CRITICAL,
            impact=impact,
            warnings=warnings,
            irreversible=True
        )
    
    def confirm_contextual(
        self,
        action: str,
        target: str,
        risk_level: RiskLevel,
        impact: str,
        warnings: Sequence[str] | None = None,
        side_effects: Sequence[str] | None = None,
        dry_run: bool = False,
        default_answer: str | None = None
    ) -> ConfirmationResult:
        normalized_default = {
            self._validate_default_answer(default_answer)
            if default_answer is not None
            else None
        }
        extra_warnings = list(warnings or [])
        if side_effects:
            extra_warnings.append(
                "Side effects: " + "; ".join(effect for effect in side_effects)
            )

        return self._run_yes_no_flow(
            kind=ConfirmationKind.CONTEXTUAL,
            action=action,
            target=target,
            risk_level=risk_level,
            default_answer=normalized_default,
            impact=impact,
            warnings=extra_warnings,
            dry_run=dry_run

        )
        

    def build_rejected_result(
        self,
        *,
        kind: ConfirmationKind,
        risk_level: RiskLevel,
        reason: str = MSG_CONTINUE_REJECTED,
        prompt: str = "",
        attempts_used: int = 0
    ) -> ConfirmationResult:
        return self._result(
        state=ConfirmationState.REJECTED,
        kind=kind,
        risk_level=risk_level,
        reason=reason,
        prompt=prompt,
        attempts_used=attempts_used
        )    

    def build_aborted_result(
        self,
        *,
        kind: ConfirmationKind,
        risk_level: RiskLevel,
        reason: str = MSG_ABORTED_INVALID,
        prompt: str = "",
        attempts_used: int = 0
    ) -> ConfirmationResult:
        return self._result(
            state=ConfirmationState.ABORTED,
            kind=kind,
            risk_level=risk_level,
            reason=reason,
            prompt=prompt,
            attempts_used=attempts_used
        )

    def build_policy_blocked_result(
        self,
        *,
        kind: ConfirmationKind,
        risk_level: RiskLevel,
        reason: str = MSG_BLOCKED_POLICY,
        prompt: str = "",
    ) -> ConfirmationResult:
        return self._result(
            state=ConfirmationState.POLICY_BLOCKED,
            kind=kind,
            risk_level=risk_level,
            reason=reason,
            prompt=prompt,
        )
    
    def ensure_confirmed(self, result: ConfirmationResult) -> None:
        if result.confirmed:
            return
        if result.policy_blocked:
            raise PreventiveSecurityError(
                message=result.reason,
                details={
                    "risk_level": result.risk_level.value,
                    "confirmation_kind": result.kind.value,
                    "state": result.state.value
                }
            )
        raise ValidationError(
            message=result.reason,
            details={
                "risk_level": result.risk_level.value,
                "confirmation_kind": result.kind.value,
                "state": result.state.value
            }
        )

    def _build_yes_no_prompt(
        self,
        *,
        action: str,
        target: str,
        risk_level: RiskLevel,
        default_answer: str,
        impact: str | None,
        warnings: Sequence[str] | None,
        dry_run: bool,
    ) -> str:
        self._validate_prompt_inputs(action=action, target=target)
        default_token = self._default_token(default_answer)
        risk_label = RISK_DISPLAY[risk_level]
        lines = [f"Action: {action}", f"Target: {target}", f"Level: {risk_label}"]

        if impact:
            lines.append(f"Impact: {impact}")
        lines.append("Mode: Simulation (dry-run)" if dry_run else "Mode: real execution")

        if warnings:
            for warn in warnings:
                if warn:
                    lines.append(f"Warning: {warn}")
        
        lines.append(f"Do you confirm to continue? [{default_token}]")
        return "\n".join(lines) + " "
    
    def _build_reinforced_prompt(
        self,
        *,
        action: str,
        target: str,
        risk_level: RiskLevel,
        expected_text: str,
        impact: str | None,
        warnings: Sequence[str] | None,
        irreversible: bool
    ) -> str:
        self._validate_prompt_inputs(action=action, target=target)
        self._validate_expected_text(expected_text)

        critical_tag = RISK_TAG_CRITICAL if risk_level is RiskLevel.CRITICAL else RISK_HIGH
        lines =[
            f"{critical_tag} Reinforced confirmation required",
            f"Action: {action}",
            f"Target: {target}",
            f"Level: {RISK_DISPLAY[risk_level]}"
        ]

        if impact:
            lines.append(f"impact: {impact}")
        if irreversible:
            lines.append("Irreversible: yes. This action may be destructive.")
        if warnings:
            for warn in warnings:
                if warn:
                    lines.append(f"Warning: {warn}")
        
        lines.append(f"Type exactly '{expected_text}' to confirm")
        lines.append("Any other value cancels the operation.")
        return "\n".join(lines) + "\n>"

    
    def _normalize_response(self, raw: str) -> str:
        return raw.strip().lower()


    def _normalize_yes_no_response(
        self,
        raw: str,
        *,
        default_answer: str,
    ) -> bool | None:
        normalized = self._normalize_response(raw)

        if not normalized:
            return default_answer == DEFAULT_ANSWER_YES
        if normalized in YES_ANSWERS:
            return True
        if normalized in NO_ANSWERS:
            return False
        
        return None

        
    
    def _validate_manager_configuration(self) -> None:
        if self.config.default_answer not in {DEFAULT_ANSWER_YES, DEFAULT_ANSWER_NO}:
            raise ValidationError(message="default_answer invalid in ConfirmationConfig")
        if self.config.max_attempts < 1:
            raise ValidationError(message="max_attempts must be >= 1")
    
    def _validate_prompt_inputs(
        self,
        *,
        action: str,
        target: str
    ) -> None:
        if not action.strip() or not target.strip():
            raise PreventiveSecurityError(message="Cannot build a reliable confirmation without action and resource.")
    
    def _validate_expected_text(self, expected_text: str) -> None:
        if not expected_text.strip():
            raise PreventiveSecurityError(message="Reinforced confirmation requires explicit expected text.")

    def _validate_default_answer(self, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {DEFAULT_ANSWER_YES, DEFAULT_ANSWER_NO}:
            raise ValidationError(message="default_answer must be 'yes' or 'no'")
        return normalized

    
    def _default_token(self, default_answer: str) -> str:
        if default_answer == DEFAULT_ANSWER_YES:
            return "Y/n"
        return "y/N"
    
    def _result(
        self,
        *,
        state: ConfirmationState,
        risk_level: RiskLevel,
        kind: ConfirmationKind,
        reason: str,
        prompt: str,
        attempts_used: int = 0,
        metadata: Mapping[str, str] | None = None
    ) -> ConfirmationResult:
        return ConfirmationResult(
            state=state,
            risk_level=risk_level,
            kind=kind,
            reason=reason,
            attempts_used=attempts_used,
            prompt=prompt,
            metadata=dict(metadata or {})
        )
    
    def _run_yes_no_flow(
        self,
        *,
        kind: ConfirmationKind,
        action: str,
        target: str,
        risk_level: RiskLevel,
        default_answer: str | None,
        impact: str | None,
        warnings: Sequence[str] | None,
        dry_run: bool
    ) -> ConfirmationResult:
        effective_default = self._validate_default_answer(default_answer if default_answer is not None else self.config.default_answer)

        if effective_default not in {DEFAULT_ANSWER_YES, DEFAULT_ANSWER_NO}:
            raise ValidationError(
                message="default_answer must be 'yes' or 'no'"
            )
        if (
            self.config.strict_critical 
            and risk_level is RiskLevel.CRITICAL
            and effective_default != DEFAULT_ANSWER_NO
        ):
            raise PreventiveSecurityError(
                message="Critical confirmations requre default answer 'no' when strict_critical is enabled."
            )

        prompt = self._build_yes_no_prompt(
            action=action,
            target=target,
            risk_level=risk_level,
            default_answer=effective_default,
            impact=impact,
            warnings=warnings,
            dry_run=dry_run
        )
        
        if not self.config.interactive:
            if self.config.non_interactive_auto_confirm:
                return self._result(
                    state=ConfirmationState.CONFIRMED,
                    risk_level=risk_level,
                    kind=kind,
                    reason="Confirmation auto-authorized by non-interactive policy.",
                    prompt=prompt
                )
            return self.build_policy_blocked_result(
                kind=kind,
                risk_level=risk_level,
                reason=(
                    "Non-interactive mode: explicit confirmation or"
                    "an equivalent authorization flag is required."
                ),
                prompt=prompt
            )
        
        if self._output and not self.config.silent:
            self._output.print_confirmation_required(reason="Sensitive operation: explicit consent is required.")
        
        for attempt in range(1, self.config.max_attempts + 1):
            raw = self._input(prompt)
            decision = self._normalize_yes_no_response(
                raw,
                default_answer=effective_default,
            )
            if decision is True:
                return self._result(
                    state=ConfirmationState.CONFIRMED,
                    kind=kind,
                    risk_level=risk_level,
                    attempts_used=attempt,
                    reason=MSG_CONTINUE_APPROVED,
                    prompt=prompt,
                )
            
            if decision is False:
                return self.build_rejected_result(
                    kind=kind,
                    risk_level=risk_level,
                    prompt=prompt,
                    attempts_used=attempt
                )

            if self._output and not self.config.silent:
                self._output.warning(
                    f"Invalid input ({attempt}/{self.config.max_attempts})"
                    "Please respond explicitly with yes/no."
                )
        
        return self.build_aborted_result(
            kind=kind,
            risk_level=risk_level,
            prompt=prompt,
            attempts_used=self.config.max_attempts
        )
    
    def _run_reinforced_flow(
        self,
        *,
        action: str,
        target: str,
        expected_text: str,
        risk_level: RiskLevel,
        impact: str | None,
        warnings: Sequence[str] | None,
        irreversible: bool
    ) -> ConfirmationResult:
        prompt = self._build_reinforced_prompt(
            action=action,
            target=target,
            risk_level=risk_level,
            expected_text=expected_text,
            impact=impact,
            warnings=warnings,
            irreversible=irreversible
        )

        if not self.config.interactive:
            return self.build_policy_blocked_result(
                kind=ConfirmationKind.REINFORCED,
                risk_level=risk_level,
                reason=(
                    "Non-interactive: reinforced actions require"
                    "secure explicit authorization."
                ),
                prompt=prompt
            )
        
        if self._output and not self.config.silent:
            self._output.print_confirmation_required(
                reason="Reinforced confirmation required for high-impact operation."
            )
        
        expected = expected_text.strip()
        for attempt in range(1, self.config.max_attempts + 1):
            entered = self._input(prompt).strip()
            if entered == expected:
                return self._result(
                    state=ConfirmationState.CONFIRMED,
                    risk_level=risk_level,
                    kind=ConfirmationKind.REINFORCED,
                    reason=MSG_CONTINUE_APPROVED,
                    attempts_used=attempt,
                    prompt=prompt,
                    metadata={"expected_text": expected}
                )
            
            if self._output and not self.config.silent:
                self._output.warning(
                    f"Invalid confirmation text ({attempt} / {self.config.max_attempts})"
                )
        
        return self.build_aborted_result(
            kind=ConfirmationKind.REINFORCED,
            risk_level=risk_level,
            reason=(
                "Operation aborted: the exact confirmation phrase was not received"
            ),
            prompt=prompt,
            attempts_used=self.config.max_attempts
        )



__all__ = [
    "ConfirmationConfig",
    "ConfirmationKind",
    "ConfirmationManager",
    "ConfirmationResult",
    "ConfirmationState",
    "RiskLevel"
]