"""Small platform-specific helpers for invoking the native compiler toolchain."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def macos_sdk_args() -> list[str]:
    """Return Clang's SDK sysroot arguments on macOS, if one can be located."""
    if sys.platform != "darwin":
        return []

    sdk = os.environ.get("SDKROOT", "")
    if sdk and Path(sdk).is_dir():
        return ["-isysroot", sdk]

    xcrun = shutil.which("xcrun")
    if not xcrun:
        return []
    try:
        result = subprocess.run(
            [xcrun, "--show-sdk-path"], capture_output=True, text=True,
            timeout=5, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    sdk = result.stdout.strip()
    return ["-isysroot", sdk] if result.returncode == 0 and Path(sdk).is_dir() else []
