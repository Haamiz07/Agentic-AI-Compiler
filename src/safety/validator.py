"""Compile, fixture-based behavior validation, CWE-14 security checks, and microbenchmarking for candidate IR."""
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional
from .models import ValidationResult

L1I_CACHE_BYTES = 32768  # 32 KB typical per-core L1 instruction cache capacity

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
        self.size_path = _locate_tool("", ("llvm-size", "size"))
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

    @staticmethod
    def _extract_ir_functions(ir_text: str) -> dict[str, str]:
        """Extract per-function IR bodies keyed by symbol name."""
        funcs: dict[str, str] = {}
        current_name = ""
        current_lines: list[str] = []
        for line in ir_text.splitlines():
            if not current_name:
                m = re.match(r'^\s*define\b[^@]*@"?([^"\s(]+)"?\s*\(', line)
                if m:
                    current_name = m.group(1)
                    current_lines = [line]
            else:
                current_lines.append(line)
                if line.strip() == "}":
                    funcs[current_name] = "\n".join(current_lines)
                    current_name = ""
                    current_lines = []
        return funcs

    @classmethod
    def check_security_invariants(cls, baseline_ir: str, candidate_ir: str) -> tuple[bool, str]:
        """Verify optimization passes preserved security-critical memory scrubs (CWE-14)."""
        try:
            base_text = Path(baseline_ir).read_text(encoding="utf-8", errors="replace")
            cand_text = Path(candidate_ir).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return False, f"Could not inspect IR for security invariants: {exc}"

        explicit_pat = re.compile(r"\bcall\b[^\n]*@(?:explicit_bzero|memset_s)\b")
        base_explicit = len(explicit_pat.findall(base_text))
        cand_explicit = len(explicit_pat.findall(cand_text))
        if cand_explicit < base_explicit:
            return False, (
                f"Rejected (CWE-14): Pass eliminated {base_explicit - cand_explicit} "
                f"explicit memory-scrubbing call(s)."
            )

        base_funcs = cls._extract_ir_functions(base_text)
        cand_funcs = cls._extract_ir_functions(cand_text)
        memset_pat = re.compile(r"\bcall\b[^\n]*@(?:llvm\.memset[^\s(]*|memset|explicit_bzero|memset_s)\b")
        zero_store_pat = re.compile(
            r"\bstore\s+(?:i\d+|ptr|float|double|<\d+\s*x\s*[^>]+>)\s+(?:0|0\.0+e\+00|null|zeroinitializer)\s*,"
        )

        for fn_name, base_body in base_funcs.items():
            if fn_name.startswith(("_ZNSt", "_ZSt", "_ZNKSt")) or fn_name not in cand_funcs:
                continue
            cand_body = cand_funcs[fn_name]
            base_clears = len(memset_pat.findall(base_body))
            cand_clears = len(memset_pat.findall(cand_body))
            if cand_clears < base_clears:
                added_zeros = len(zero_store_pat.findall(cand_body)) - len(zero_store_pat.findall(base_body))
                if added_zeros < (base_clears - cand_clears):
                    return False, (
                        f"Rejected (CWE-14): Pass eliminated {base_clears - cand_clears} "
                        f"memory-scrubbing memset call(s) in '{fn_name}' without zero-store replacement."
                    )

        return True, "Security invariants (CWE-14 memory scrubbing) preserved."

    def _measure_code_footprint(self, binary_path: Path) -> tuple[Optional[int], Optional[int]]:
        """Measure linked executable file size and .text instruction section bytes."""
        try:
            file_bytes = binary_path.stat().st_size
        except OSError:
            return None, None
        text_bytes = None
        if self.size_path:
            try:
                res = subprocess.run(
                    [self.size_path, str(binary_path)],
                    capture_output=True, text=True, timeout=5,
                    env=self._build_env(), check=False,
                )
                if res.returncode == 0:
                    lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
                    if len(lines) >= 2:
                        parts = lines[1].split()
                        if parts and parts[0].isdigit():
                            text_bytes = int(parts[0])
            except Exception:
                pass
        return file_bytes, text_bytes

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

            inv_ok, inv_msg = self.check_security_invariants(baseline_ir, candidate_ir)
            details.append(inv_msg)
            if not inv_ok:
                return ValidationResult(
                    False, True,
                    baseline_ir=baseline_ir,
                    candidate_ir=candidate_ir,
                    details=details,
                    reason=inv_msg,
                    security_invariants_preserved=False,
                )

            base_size, base_text = self._measure_code_footprint(baseline_bin)
            cand_size, cand_text = self._measure_code_footprint(candidate_bin)
            l1i_ok = (cand_text <= L1I_CACHE_BYTES) if cand_text is not None else None
            if cand_text is not None:
                details.append(
                    f"code footprint: .text={cand_text}B"
                    + (f" (baseline={base_text}B)" if base_text is not None else "")
                    + f" vs {L1I_CACHE_BYTES}B L1i budget -> {'OK' if l1i_ok else 'OVER L1i'}"
                )

            if not self.behavior_inputs:
                return ValidationResult(not self.require_behavior_checks, True,
                    baseline_ir=baseline_ir,
                    candidate_ir=candidate_ir, details=details,
                    baseline_size_bytes=base_size,
                    candidate_size_bytes=cand_size,
                    baseline_text_bytes=base_text,
                    candidate_text_bytes=cand_text,
                    l1i_cache_budget_ok=l1i_ok,
                    security_invariants_preserved=True,
                    reason=("Compile validation passed; behavior was not checked because no trusted fixtures are configured."
                            if not self.require_behavior_checks else
                            "Behavior validation is required, but no trusted fixtures are configured."))
            behavior_ok, behavior_details = self._compare_runs(baseline_bin, candidate_bin, tmp)
            details.extend(behavior_details)
            bench_checked = False
            base_ns, cand_ns, speedup = None, None, None
            base_p99, cand_p99 = None, None
            if behavior_ok and run_benchmark and self.benchmark_runs > 0:
                bench_checked, base_ns, cand_ns, speedup, base_p99, cand_p99, bench_msg = self._benchmark_runs(
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
                reason="Behavior fixtures matched." if behavior_ok else "Behavior fixture mismatch or execution failure.",
                p99_baseline_ns=base_p99,
                p99_candidate_ns=cand_p99,
                baseline_size_bytes=base_size,
                candidate_size_bytes=cand_size,
                baseline_text_bytes=base_text,
                candidate_text_bytes=cand_text,
                l1i_cache_budget_ok=l1i_ok,
                security_invariants_preserved=True)

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
        """Run empirical wall-clock microbenchmark across configured iterations (median + p99 tail)."""
        input_text = self.behavior_inputs[0] if self.behavior_inputs else ""
        # Warm-up run
        if self._run(baseline_bin, input_text, tmp) is None or self._run(candidate_bin, input_text, tmp) is None:
            return False, None, None, None, None, None, "benchmark skipped: warmup failed"

        base_times = []
        cand_times = []
        for _ in range(self.benchmark_runs):
            t0 = time.perf_counter_ns()
            r_b = self._run(baseline_bin, input_text, tmp)
            t1 = time.perf_counter_ns()
            r_c = self._run(candidate_bin, input_text, tmp)
            t2 = time.perf_counter_ns()
            if r_b is None or r_c is None:
                return False, None, None, None, None, None, "benchmark aborted: timed out"
            base_times.append(float(t1 - t0))
            cand_times.append(float(t2 - t1))

        base_times.sort()
        cand_times.sort()
        # Median and nearest-rank p99 tail latency in nanoseconds
        mid = len(base_times) // 2
        p99_idx = max(0, math.ceil(0.99 * len(base_times)) - 1)
        base_med = round(base_times[mid], 1)
        cand_med = round(cand_times[mid], 1)
        base_p99 = round(base_times[p99_idx], 1)
        cand_p99 = round(cand_times[p99_idx], 1)
        speedup = round((base_med - cand_med) / max(base_med, 1.0) * 100.0, 2)
        msg = (
            f"empirical ({self.benchmark_runs} runs): median baseline={base_med/1e6:.2f}ms, "
            f"candidate={cand_med/1e6:.2f}ms ({speedup:+.1f}%) | "
            f"p99 tail={cand_p99/1e6:.2f}ms"
        )
        return True, base_med, cand_med, speedup, base_p99, cand_p99, msg

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
