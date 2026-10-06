"""Run one allowlisted LLVM pass without invoking a shell."""
import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class PassRunResult:
    success: bool
    output_path: str = ""
    reason: str = ""


class LLVMOptRunner:
    def __init__(self, opt_path: str = "", timeout_s: int = 30):
        self.opt_path = opt_path or shutil.which("opt") or ""
        self.timeout_s = timeout_s

    def run(self, input_path: str, output_path: str, pass_name: str) -> PassRunResult:
        if not self.opt_path:
            return PassRunResult(False, reason="LLVM opt executable was not found; optimization rejected.")
        cmd = [self.opt_path, f"-passes={pass_name}", "-S", input_path, "-o", output_path]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=self.timeout_s, check=False)
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
                                     timeout=self.timeout_s, check=False)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return PassRunResult(False, reason=f"IR verifier could not complete: {exc}")
        if checked.returncode != 0:
            detail = (checked.stderr or checked.stdout or "LLVM IR verification failed.").strip()
            return PassRunResult(False, reason=detail[-1200:])
        return PassRunResult(True, output_path, "Pass ran and LLVM IR verification passed.")
