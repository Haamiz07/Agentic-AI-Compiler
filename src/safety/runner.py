"""Run one allowlisted LLVM pass without invoking a shell."""
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from .validator import _locate_tool, _DEFAULT_TOOLCHAIN_DIRS


@dataclass
class PassRunResult:
    success: bool
    output_path: str = ""
    reason: str = ""


class LLVMOptRunner:
    def __init__(self, opt_path: str = "", timeout_s: int = 30):
        self.opt_path = _locate_tool(opt_path, ("opt",))
        self.timeout_s = timeout_s

    def _build_env(self) -> dict:
        env = dict(os.environ)
        path_parts = [p for p in _DEFAULT_TOOLCHAIN_DIRS if os.path.isdir(p)]
        if self.opt_path:
            opt_dir = str(Path(self.opt_path).parent)
            if opt_dir not in path_parts:
                path_parts.insert(0, opt_dir)
        current_path = env.get("PATH", "")
        env["PATH"] = os.pathsep.join(path_parts + ([current_path] if current_path else []))
        return env

    def run(self, input_path: str, output_path: str, pass_name: str) -> PassRunResult:
        if not self.opt_path:
            self.opt_path = _locate_tool("", ("opt",))
        if not self.opt_path:
            return PassRunResult(False, reason="LLVM opt executable was not found; optimization rejected.")
        cmd = [self.opt_path, f"-passes={pass_name}", "-S", input_path, "-o", output_path]
        env = self._build_env()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=self.timeout_s, env=env, check=False)
        except subprocess.TimeoutExpired:
            return PassRunResult(False, reason=f"LLVM opt timed out after {self.timeout_s}s.")
        except OSError as exc:
            return PassRunResult(False, reason=f"Could not start LLVM opt: {exc}")
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "LLVM opt returned a failure status.").strip()
            return PassRunResult(False, reason=detail[-1200:])
        # Confirm the output is parseable by LLVM's verifier before exposing it.
        verify = [self.opt_path, "-passes=verify", "-disable-output", output_path]
        try:
            checked = subprocess.run(verify, capture_output=True, text=True,
                                     timeout=self.timeout_s, env=env, check=False)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return PassRunResult(False, reason=f"IR verifier could not complete: {exc}")
        if checked.returncode != 0:
            detail = (checked.stderr or checked.stdout or "LLVM IR verification failed.").strip()
            return PassRunResult(False, reason=detail[-1200:])
        return PassRunResult(True, output_path, "Pass ran and LLVM IR verification passed.")
