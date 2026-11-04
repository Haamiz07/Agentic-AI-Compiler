"""Compile, fixture-based behavior validation, and empirical microbenchmarking for candidate IR."""
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from .models import ValidationResult

_DEFAULT_TOOLCHAIN_DIRS = (
    r"C:\msys64\ucrt64\bin",
    r"C:\msys64\clang64\bin",
    r"C:\msys64\mingw64\bin",
    r"C:\Program Files\LLVM\bin",
    "/opt/homebrew/opt/llvm/bin",
    "/usr/local/opt/llvm/bin",
)


def _locate_tool(configured_path: str, tool_names: tuple[str, ...]) -> str:
    if configured_path and os.path.exists(configured_path):
        return configured_path
    for name in tool_names:
        found = shutil.which(name)
        if found:
            return found
    for d in _DEFAULT_TOOLCHAIN_DIRS:
        if os.path.isdir(d):
            for name in tool_names:
                for ext in ("", ".exe"):
                    candidate = os.path.join(d, name + ext)
                    if os.path.isfile(candidate):
                        return candidate
    return ""


class CandidateValidator:
    def __init__(self, clang_path: str = "", timeout_s: int = 20,
                 behavior_inputs=None, require_behavior_checks: bool = False,
                 benchmark_runs: int = 5):
        self.clang_path = _locate_tool(clang_path, ("clang++", "clang"))
        self.timeout_s = timeout_s
        self.behavior_inputs = list(behavior_inputs if behavior_inputs is not None else [""])
        self.require_behavior_checks = bool(require_behavior_checks)
        self.benchmark_runs = max(1, int(benchmark_runs))
        self._baseline_cache_dir = tempfile.mkdtemp(prefix="agentic_base_cache_")
        self._baseline_cache: dict[tuple[str, float], Path] = {}
        if os.name == "nt":
            try:
                import ctypes
                ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002)
            except Exception:
                pass

    def _get_compiled_baseline(self, baseline_ir: str, ext: str) -> tuple[bool, str, Path]:
        try:
            mtime = os.path.getmtime(baseline_ir)
        except OSError:
            mtime = 0.0
        key = (os.path.abspath(baseline_ir), mtime)
        cached = self._baseline_cache.get(key)
        if cached and cached.is_file():
            return True, "compiled successfully (cached)", cached
        target = Path(self._baseline_cache_dir) / f"base_{len(self._baseline_cache)}{ext}"
        ok, msg = self._compile(baseline_ir, target)
        if ok:
            self._baseline_cache[key] = target
        return ok, msg, target

    def validate(self, baseline_ir: str, candidate_ir: str,
                 run_benchmark: bool = True) -> ValidationResult:
        details = []
        if not self.clang_path:
            return ValidationResult(False, False, baseline_ir=baseline_ir,
                                    candidate_ir=candidate_ir,
                                    reason="clang is unavailable; failing closed.")
        with tempfile.TemporaryDirectory(prefix="agentic_validate_", ignore_cleanup_errors=True) as tmp:
            ext = ".exe" if os.name == "nt" else ""
            base_ok, base_msg, baseline_bin = self._get_compiled_baseline(baseline_ir, ext)
            candidate_bin = Path(tmp) / f"candidate{ext}"
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
            bench_checked = False
            base_ns, cand_ns, speedup = None, None, None
            if behavior_ok and run_benchmark and self.benchmark_runs > 0:
                bench_checked, base_ns, cand_ns, speedup, bench_msg = self._benchmark_runs(
                    baseline_bin, candidate_bin, tmp
                )
                if bench_msg:
                    details.append(bench_msg)
            return ValidationResult(
                behavior_ok, True,
                behavior_checked=True,
                behavior_preserved=behavior_ok,
                benchmark_checked=bench_checked,
                baseline_latency_ns=base_ns,
                candidate_latency_ns=cand_ns,
                speedup_pct=speedup,
                baseline_ir=baseline_ir,
                candidate_ir=candidate_ir,
                details=details,
                reason="Behavior fixtures matched." if behavior_ok else "Behavior fixture mismatch or execution failure.")

    def _compile(self, ir_path: str, output_path: Path):
        compiler = self.clang_path
        # Use clang++ so C++ standard library symbols link cleanly on all platforms
        if compiler.endswith("clang") or compiler.endswith("clang.exe"):
            cxx_candidate = compiler.replace("clang.exe", "clang++.exe") if compiler.endswith(".exe") else compiler + "++"
            if os.path.exists(cxx_candidate) or shutil.which(cxx_candidate):
                compiler = cxx_candidate
        cmd = [compiler, "-Wno-everything", ir_path, "-o", str(output_path)]
        if os.name != "nt":
            cmd.append("-lm")
        env = self._build_env()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                timeout=self.timeout_s, env=env, check=False)
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

    def _benchmark_runs(self, baseline_bin: Path, candidate_bin: Path, tmp: str):
        """Run empirical wall-clock microbenchmark across configured iterations."""
        input_text = self.behavior_inputs[0] if self.behavior_inputs else ""
        # Warm-up run
        if self._run(baseline_bin, input_text, tmp) is None or self._run(candidate_bin, input_text, tmp) is None:
            return False, None, None, None, "benchmark skipped: warmup failed"

        base_times = []
        cand_times = []
        for _ in range(self.benchmark_runs):
            t0 = time.perf_counter_ns()
            r_b = self._run(baseline_bin, input_text, tmp)
            t1 = time.perf_counter_ns()
            r_c = self._run(candidate_bin, input_text, tmp)
            t2 = time.perf_counter_ns()
            if r_b is None or r_c is None:
                return False, None, None, None, "benchmark aborted: timed out"
            base_times.append(float(t1 - t0))
            cand_times.append(float(t2 - t1))

        base_times.sort()
        cand_times.sort()
        # Median wall-clock time in nanoseconds
        mid = len(base_times) // 2
        base_med = round(base_times[mid], 1)
        cand_med = round(cand_times[mid], 1)
        speedup = round((base_med - cand_med) / max(base_med, 1.0) * 100.0, 2)
        msg = f"empirical median ({self.benchmark_runs} runs): baseline={base_med/1e6:.2f}ms, candidate={cand_med/1e6:.2f}ms ({speedup:+.1f}%)"
        return True, base_med, cand_med, speedup, msg

    def _build_env(self) -> dict:
        env = dict(os.environ)
        path_parts = [p for p in _DEFAULT_TOOLCHAIN_DIRS if os.path.isdir(p)]
        if self.clang_path:
            clang_dir = str(Path(self.clang_path).parent)
            if clang_dir not in path_parts:
                path_parts.insert(0, clang_dir)
        current_path = env.get("PATH", "")
        env["PATH"] = os.pathsep.join(path_parts + ([current_path] if current_path else []))
        return env

    def _run(self, executable: Path, input_text: str, cwd: str):
        try:
            return subprocess.run([str(executable)], input=input_text,
                capture_output=True, text=True, timeout=self.timeout_s,
                cwd=cwd, env=self._build_env(), check=False)
        except (subprocess.TimeoutExpired, OSError):
            return None
