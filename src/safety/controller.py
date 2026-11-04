"""Connect pass recommendations, policy, LLVM execution, validation, and planner feedback."""
import shutil
import tempfile
from pathlib import Path
from .analysis import SecurityAnalyzer
from .models import OptimizationAttemptRecord, PolicyDecision
from .policy import PassPolicy
from .runner import LLVMOptRunner
from .validator import CandidateValidator

# Fallback alternative passes when a primary pass is rejected or fails validation
_FALLBACK_ALTERNATIVES = {
    "loop-vectorize": ["slp-vectorizer", "loop-unroll", "licm"],
    "slp-vectorizer": ["instcombine", "gvn"],
    "loop-unroll": ["licm", "indvars", "loop-idiom"],
    "inline": ["sccp", "simplifycfg", "instcombine"],
    "-inline": ["sccp", "simplifycfg", "instcombine"],
    "always-inline": ["inline", "simplifycfg"],
    "aggressive-instcombine": ["instcombine", "reassociate"],
    "gvn": ["sccp", "dce"],
    "sroa": ["mem2reg", "instcombine"],
}


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
            validation_cfg.get("behavior_inputs", [""]),
            validation_cfg.get("require_behavior_checks", False),
            validation_cfg.get("benchmark_runs", 3))
        self.max_passes = max(1, int(policy_cfg.get("max_passes_per_compile", 12)))

    def step_action(self, baseline_ir: str, current_ir: str, action: str,
                    seen: set, security_findings=None, stage: str = "planner_loop",
                    run_validator: bool = True, run_benchmark: bool = False):
        """
        Execute a single closed-loop Planner -> Policy Gate -> LLVM Runner -> Validator step.
        Returns (new_current_ir, OptimizationAttemptRecord, fallback_suggestions).
        """
        findings = security_findings or []
        summary = SecurityAnalyzer.summarize_for_planner(findings)
        finding_context = f"{len(findings)} security/IR finding(s) supplied to policy context."

        decision = self.policy.authorize(action)
        key = decision.canonical_action

        if not decision.allowed:
            alts = self._suggest_alternatives(action, key, seen, summary)
            fb = f"Policy blocked '{action}' ({decision.reason}). Suggested alternatives: {alts or 'none'}."
            rec = OptimizationAttemptRecord(
                str(action), decision, reason=decision.reason, stage=stage, feedback=fb
            )
            return current_ir, rec, alts

        # Security-aware constraint check: if high-severity finding advises avoiding this pass
        if summary["high_severity_count"] > 0 and key in summary["avoid_passes"]:
            blocked = PolicyDecision(
                str(action), False,
                f"Blocked by security-informed policy: pass '{key}' is unsafe around high-severity finding(s).",
                key
            )
            alts = [p for p in summary["prefer_passes"] if p not in seen]
            fb = f"Security constraint blocked '{key}'. Prefer safety-preserving passes: {alts}."
            rec = OptimizationAttemptRecord(
                str(action), blocked, reason=blocked.reason, stage=stage, feedback=fb
            )
            return current_ir, rec, alts

        if key in seen:
            duplicate = PolicyDecision(
                str(action), False, "Duplicate pass skipped to keep the run bounded.", key
            )
            rec = OptimizationAttemptRecord(
                str(action), duplicate, reason=duplicate.reason, stage=stage,
                feedback="Pass already applied in this session."
            )
            return current_ir, rec, []

        if len(seen) >= self.max_passes:
            capped = PolicyDecision(
                str(action), False, f"Per-compilation pass limit ({self.max_passes}) reached.", key
            )
            rec = OptimizationAttemptRecord(
                str(action), capped, reason=capped.reason, stage=stage,
                feedback="Pass budget exhausted."
            )
            return current_ir, rec, []

        seen.add(key)
        base_path = Path(baseline_ir)
        with tempfile.TemporaryDirectory(
            prefix="agentic_step_", dir=str(base_path.parent), ignore_cleanup_errors=True
        ) as tmp:
            candidate = Path(tmp) / f"candidate_{len(seen)}.ll"
            run = self.runner.run(str(current_ir), str(candidate), key)
            if not run.success:
                alts = self._suggest_alternatives(action, key, seen, summary)
                fb = f"LLVM opt failed on '{key}': {run.reason}. Try fallback: {alts or 'none'}."
                rec = OptimizationAttemptRecord(
                    str(action), decision, executed=True, reason=run.reason,
                    stage=stage, feedback=fb
                )
                return current_ir, rec, alts

            if not run_validator:
                accepted_path = base_path.with_name(f"{base_path.stem}_safe_opt.ll")
                shutil.copy2(candidate, accepted_path)
                fb = f"Accepted '{key}': LLVM opt applied and IR verified."
                rec = OptimizationAttemptRecord(
                    str(action), decision, executed=True, accepted=True,
                    reason=f"{run.reason} {finding_context}",
                    stage=stage, feedback=fb
                )
                return str(accepted_path), rec, []

            validation = self.validator.validate(
                str(baseline_ir), str(candidate), run_benchmark=run_benchmark
            )
            if validation.passed:
                accepted_path = base_path.with_name(f"{base_path.stem}_safe_opt.ll")
                shutil.copy2(candidate, accepted_path)
                fb = f"Accepted '{key}': IR verified, compiled, and passed behavior fixtures."
                if validation.speedup_pct is not None:
                    fb += f" Measured delta: {validation.speedup_pct:+.1f}%."
                rec = OptimizationAttemptRecord(
                    str(action), decision, executed=True, accepted=True,
                    validation=validation,
                    reason=f"{run.reason} {finding_context}",
                    stage=stage, feedback=fb
                )
                return str(accepted_path), rec, []
            else:
                alts = self._suggest_alternatives(action, key, seen, summary)
                fb = f"Validation rejected '{key}' ({validation.reason}). Suggesting fallback: {alts or 'none'}."
                rec = OptimizationAttemptRecord(
                    str(action), decision, executed=True, validation=validation,
                    reason=f"Candidate rejected: {validation.reason}",
                    stage=stage, feedback=fb
                )
                return current_ir, rec, alts

    def optimize(self, source_path: str, baseline_ir: str, actions,
                 security_findings=None, enable_critic_feedback: bool = True):
        """
        Run the closed-loop optimization controller across proposed actions.
        When enable_critic_feedback is True, rejected/failed actions automatically
        feed back into the planner queue with allowlisted fallback alternatives.
        """
        records = []
        baseline = Path(baseline_ir)
        if not baseline.is_file():
            return baseline_ir, [self._rejected("<input>", "Input IR is missing; failing closed.")]

        findings = security_findings or []
        summary = SecurityAnalyzer.summarize_for_planner(findings)
        current_ir = str(baseline)
        seen = set()

        # Prepend security-preferred passes if security findings exist
        queue = []
        for pref in summary.get("prefer_passes", []):
            if pref not in queue:
                queue.append((pref, "security_remediation"))
        for act in actions:
            queue.append((act, "planner_loop"))

        idx = 0
        while idx < len(queue):
            action, stage = queue[idx]
            idx += 1
            current_ir, rec, alts = self.step_action(
                str(baseline), current_ir, action, seen,
                security_findings=findings, stage=stage,
                run_validator=False, run_benchmark=False,
            )
            records.append(rec)
            # Closed-loop critic feedback: if an action was rejected or failed validation,
            # enqueue the top allowlisted alternative if budget remains.
            if enable_critic_feedback and not rec.accepted and alts and len(seen) < self.max_passes:
                next_alt = alts[0]
                if all(next_alt != item[0] for item in queue[idx:]):
                    queue.insert(idx, (next_alt, f"critic_fallback({action})"))

        # Validate & microbenchmark the resulting candidate IR against baseline
        accepted_recs = [r for r in records if r.accepted]
        if accepted_recs:
            bench_val = self.validator.validate(str(baseline), current_ir, run_benchmark=True)
            if bench_val.passed:
                for r in accepted_recs:
                    r.validation = bench_val
                last_acc = accepted_recs[-1]
                last_acc.feedback = (
                    f"Accepted '{last_acc.policy.canonical_action or last_acc.action}': "
                    f"IR verified, compiled, and passed behavior fixtures."
                )
                if bench_val.speedup_pct is not None:
                    last_acc.feedback += f" Measured delta: {bench_val.speedup_pct:+.1f}%."
            else:
                # Fail-closed: if final candidate failed validation, revert to baseline IR
                for r in accepted_recs:
                    r.accepted = False
                    r.validation = bench_val
                    r.reason = f"Candidate rejected: {bench_val.reason}"
                    r.feedback = f"Validation rejected candidate ({bench_val.reason}); reverted fail-closed."
                current_ir = str(baseline)

        return current_ir, records

    def _suggest_alternatives(self, raw_action: str, canonical: str, seen: set, summary: dict) -> list[str]:
        candidates = list(_FALLBACK_ALTERNATIVES.get(canonical, []))
        if not candidates:
            candidates = list(_FALLBACK_ALTERNATIVES.get(str(raw_action).strip().lower(), []))
        for pref in summary.get("prefer_passes", []):
            if pref not in candidates:
                candidates.insert(0, pref)
        avoid = set(summary.get("avoid_passes", []))
        out = []
        for c in candidates:
            norm = self.policy.normalize(c)
            if norm not in seen and norm not in avoid and self.policy.authorize(norm).allowed:
                out.append(norm)
        return out[:2]

    @staticmethod
    def _rejected(action, reason):
        return OptimizationAttemptRecord(action, PolicyDecision(action, False, reason), reason=reason)


__all__ = ["SecurityAnalyzer", "SafeOptimizationController"]
