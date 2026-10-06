"""Compile and optional fixture-based behavior validation for candidate IR."""
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from .models import ValidationResult


class CandidateValidator:
    def __init__(self, clang_path: str = "", timeout_s: int = 20,
                 behavior_inputs=None, require_behavior_checks: bool = False):
        self.clang_path = clang_path or shutil.which("clang") or ""
        self.timeout_s = timeout_s
        self.behavior_inputs = list(behavior_inputs or [])
        self.require_behavior_checks = bool(require_behavior_checks)

    def validate(self, baseline_ir: str, candidate_ir: str) -> ValidationResult:
        details = []
        if not self.clang_path:
            return ValidationResult(False, False, baseline_ir=baseline_ir,
                                    candidate_ir=candidate_ir,
                                    reason="clang is unavailable; failing closed.")
        with tempfile.TemporaryDirectory(prefix="agentic_validate_") as tmp:
            baseline_bin, candidate_bin = Path(tmp) / "baseline", Path(tmp) / "candidate"
            base_ok, base_msg = self._compile(baseline_ir, baseline_bin)
            candidate_ok, candidate_msg = self._compile(candidate_ir, candidate_bin)
            details.extend([f"baseline: {base_msg}", f"candidate: {candidate_msg}"])
            if not base_ok or not candidate_ok:
                return ValidationResult(False, False, baseline_ir=baseline_ir,
                    candidate_ir=candidate_ir, details=details,
                    reason="Baseline and candidate must both compile.")
            if not self.behavior_inputs:
                return ValidationResult(not self.require_behavior_checks, True,
                    baseline_ir=baseline_ir,
                    candidate_ir=candidate_ir, details=details,
                    reason=("Compile validation passed; behavior was not checked because no trusted fixtures are configured."
                            if not self.require_behavior_checks else
                            "Behavior validation is required, but no trusted fixtures are configured."))
            behavior_ok, behavior_details = self._compare_runs(baseline_bin, candidate_bin, tmp)
            details.extend(behavior_details)
            return ValidationResult(behavior_ok, True, behavior_checked=True,
                behavior_preserved=behavior_ok, baseline_ir=baseline_ir,
                candidate_ir=candidate_ir, details=details,
                reason="Behavior fixtures matched." if behavior_ok else "Behavior fixture mismatch or execution failure.")

    def _compile(self, ir_path: str, output_path: Path):
        cmd = [self.clang_path, ir_path, "-o", str(output_path)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                timeout=self.timeout_s, check=False)
        except subprocess.TimeoutExpired:
            return False, f"clang timed out after {self.timeout_s}s"
        except OSError as exc:
            return False, f"clang could not start: {exc}"
        if result.returncode:
            msg = (result.stderr or result.stdout or "compile failed").strip()
            return False, msg[-800:]
        return True, "compiled successfully"

    def _compare_runs(self, baseline_bin: Path, candidate_bin: Path, tmp: str):
        details = []
        for index, input_text in enumerate(self.behavior_inputs, 1):
            baseline = self._run(baseline_bin, input_text, tmp)
            candidate = self._run(candidate_bin, input_text, tmp)
            if baseline is None or candidate is None:
                details.append(f"fixture {index}: execution failed or timed out")
                return False, details
            if (baseline.returncode, baseline.stdout, baseline.stderr) != (
                    candidate.returncode, candidate.stdout, candidate.stderr):
                details.append(f"fixture {index}: output or exit status changed")
                return False, details
            details.append(f"fixture {index}: output and exit status matched")
        return True, details

    def _run(self, executable: Path, input_text: str, cwd: str):
        try:
            return subprocess.run([str(executable)], input=input_text,
                capture_output=True, text=True, timeout=self.timeout_s,
                cwd=cwd, env={"PATH": os.environ.get("PATH", "")}, check=False)
        except (subprocess.TimeoutExpired, OSError):
            return None
