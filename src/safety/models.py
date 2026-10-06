"""Structured records for security analysis and guarded optimization."""
from dataclasses import asdict, dataclass, field
from typing import Optional


@dataclass
class PolicyDecision:
    action: str
    allowed: bool
    reason: str
    canonical_action: str = ""
    fail_closed: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SecurityFinding:
    rule_id: str
    severity: str
    message: str
    file_path: str
    line: Optional[int] = None
    function: str = "<unknown>"
    source_kind: str = "source"
    snippet: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ValidationResult:
    passed: bool
    compile_success: bool
    behavior_checked: bool = False
    behavior_preserved: Optional[bool] = None
    benchmark_checked: bool = False
    baseline_ir: str = ""
    candidate_ir: str = ""
    details: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class OptimizationAttemptRecord:
    action: str
    policy: PolicyDecision
    executed: bool = False
    accepted: bool = False
    validation: Optional[ValidationResult] = None
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "policy": self.policy.to_dict(),
            "executed": self.executed,
            "accepted": self.accepted,
            "validation": self.validation.to_dict() if self.validation else None,
            "reason": self.reason,
        }
