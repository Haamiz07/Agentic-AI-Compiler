"""Connect pass recommendations, policy, LLVM execution, and validation."""
import shutil
import tempfile
from pathlib import Path
from .analysis import SecurityAnalyzer
from .models import OptimizationAttemptRecord
from .policy import PassPolicy
from .runner import LLVMOptRunner
from .validator import CandidateValidator


class SafeOptimizationController:
    def __init__(self, config=None):
        config = config or {}
        policy_cfg = config.get("policy_gate", {})
        validation_cfg = config.get("validation", {})
        self.policy = PassPolicy(policy_cfg.get("allowlist"))
        self.runner = LLVMOptRunner(policy_cfg.get("opt_path", ""),
                                    policy_cfg.get("timeout_s", 30))
        self.validator = CandidateValidator(
            validation_cfg.get("clang_path", ""),
            validation_cfg.get("timeout_s", 20),
            validation_cfg.get("behavior_inputs", []),
            validation_cfg.get("require_behavior_checks", False))
        self.max_passes = max(1, int(policy_cfg.get("max_passes_per_compile", 12)))

    def optimize(self, source_path: str, baseline_ir: str, actions,
                 security_findings=None):
        records = []
        baseline = Path(baseline_ir)
        if not baseline.is_file():
            return baseline_ir, [self._rejected("<input>", "Input IR is missing; failing closed.")]
        findings = security_findings or []
        # Security findings are visible to the policy layer; only configured
        # pass policy decides action eligibility. A source warning alone does
        # not claim that every optimization is unsafe.
        finding_context = f"{len(findings)} security/IR finding(s) supplied to policy context."
        with tempfile.TemporaryDirectory(prefix="agentic_safe_opt_", dir=str(baseline.parent)) as tmp:
            accepted = Path(tmp) / "accepted.ll"
            shutil.copy2(baseline, accepted)
            current = accepted
            seen = set()
            for action in actions:
                decision = self.policy.authorize(action)
                key = decision.canonical_action
                if not decision.allowed:
                    records.append(OptimizationAttemptRecord(str(action), decision,
                        reason=decision.reason))
                    continue
                if key in seen:
                    from .models import PolicyDecision
                    duplicate = PolicyDecision(str(action), False,
                        "Duplicate pass skipped to keep the run bounded.", key)
                    records.append(OptimizationAttemptRecord(str(action), duplicate,
                        reason=duplicate.reason))
                    continue
                if len(seen) >= self.max_passes:
                    from .models import PolicyDecision
                    capped = PolicyDecision(str(action), False,
                        f"Per-compilation pass limit ({self.max_passes}) reached.", key)
                    records.append(OptimizationAttemptRecord(str(action), capped,
                        reason=capped.reason))
                    continue
                seen.add(key)
                candidate = Path(tmp) / f"candidate_{len(seen)}.ll"
                run = self.runner.run(str(current), str(candidate), key)
                if not run.success:
                    records.append(OptimizationAttemptRecord(str(action), decision,
                        executed=True, reason=run.reason))
                    continue
                validation = self.validator.validate(str(baseline), str(candidate))
                if validation.passed:
                    shutil.copy2(candidate, accepted)
                    current = accepted
                    records.append(OptimizationAttemptRecord(str(action), decision,
                        executed=True, accepted=True, validation=validation,
                        reason=f"{run.reason} {finding_context}"))
                else:
                    records.append(OptimizationAttemptRecord(str(action), decision,
                        executed=True, validation=validation,
                        reason=f"Candidate rejected: {validation.reason}"))
            # Persist only the last candidate that passed configured validation.
            if current != accepted or any(row.accepted for row in records):
                final_path = baseline.with_name(f"{baseline.stem}_safe_opt.ll")
                shutil.copy2(current, final_path)
                return str(final_path), records
        return baseline_ir, records

    @staticmethod
    def _rejected(action, reason):
        from .models import PolicyDecision
        return OptimizationAttemptRecord(action, PolicyDecision(action, False, reason), reason=reason)


__all__ = ["SecurityAnalyzer", "SafeOptimizationController"]
