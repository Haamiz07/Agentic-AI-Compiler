"""Fail-closed allowlist for the LLVM pass runner."""
import re
from .models import PolicyDecision

# These are LLVM's commonly available middle-end passes, not arbitrary shell
# commands or target-specific pseudo-passes from the prototype catalogue.
DEFAULT_SAFE_PASSES = frozenset({
    "mem2reg", "sroa", "inline", "simplifycfg", "instcombine",
    "aggressive-instcombine", "gvn", "dce", "reassociate", "sccp",
    "licm", "loop-unroll", "loop-vectorize", "slp-vectorizer",
    "jump-threading", "loop-idiom", "indvars",
})


class PassPolicy:
    def __init__(self, allowed_passes=None):
        self.allowed_passes = frozenset(DEFAULT_SAFE_PASSES if allowed_passes is None
                                        else allowed_passes)

    @staticmethod
    def normalize(action: str) -> str:
        value = str(action or "").strip().lower()
        # The inherited tuner spells the LLVM inline pass as "-inline".
        value = value.removeprefix("-")
        return value

    def authorize(self, action: str) -> PolicyDecision:
        canonical = self.normalize(action)
        if not canonical:
            return PolicyDecision(str(action), False, "Empty action is not allowed.")
        if not re.fullmatch(r"[a-z][a-z0-9-]*", canonical):
            return PolicyDecision(str(action), False, "Action contains unsupported characters.")
        if canonical not in self.allowed_passes:
            return PolicyDecision(str(action), False, "Pass is not in the reviewed allowlist.", canonical)
        return PolicyDecision(str(action), True, "Pass is allowlisted.", canonical)
