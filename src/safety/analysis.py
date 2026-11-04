"""Small, explainable source and LLVM IR safety scanner.

Findings are review signals, not proof that a vulnerability is exploitable.
Supports source-to-IR debug location mapping (!dbg -> !DILocation) and
live entrance prompt-injection / trojan checks.
"""
import re
from pathlib import Path
from .models import SecurityFinding

_SOURCE_RULES = (
    ("CWE-242", "high", re.compile(r"\bgets\s*\("), "Unsafe gets() has no destination-size limit."),
    ("CWE-120", "high", re.compile(r"\b(?:strcpy|strcat|sprintf)\s*\("), "Unbounded buffer operation; validate destination capacity."),
    ("CWE-120", "medium", re.compile(r"\bscanf\s*\(\s*\"[^\"]*%s"), "scanf %s may overrun its destination; use a width limit."),
    ("IR-MEMCPY-REVIEW", "medium", re.compile(r"\b(?:memcpy|memmove)\s*\("), "Memory copy needs a valid length and destination bounds."),
)
_IR_RULES = (
    ("IR-UNSAFE-CALL", "high", re.compile(r"\bcall\b[^\n]*@(?:gets|strcpy|strcat|sprintf|scanf)\b"), "IR calls a risky C library function; inspect its arguments and source."),
    ("IR-MEMCPY-REVIEW", "medium", re.compile(r"\bcall\b[^\n]*@(?:memcpy|memmove|llvm\.memcpy[^\s(]*|llvm\.memmove[^\s(]*)\b"), "IR contains a memory-copy call; bounds depend on runtime values."),
)
_PROMPT_INJECTION_RULES = (
    ("ADV-PROMPT-INJECTION", "critical", re.compile(r"\b(?:ignore|override|bypass|disregard)\b.{0,70}\b(?:security\s+)?(?:policy|rules|instructions|guardrails)\b", re.I), "Adversarial prompt-injection directive attempting to override compiler policy."),
    ("ADV-DISABLE-CHECKS", "critical", re.compile(r"\b(?:disable|skip|turn\s+off)\b.{0,45}\b(?:validation|verifier|safety\s+checks?)\b", re.I), "Adversarial directive attempting to disable compiler verification or safety checks."),
    ("ADV-MARK-SAFE", "critical", re.compile(r"\bmark\b.{0,35}\b(?:vulnerable|unsafe|malicious)\b.{0,25}\bsafe\b", re.I), "Adversarial directive attempting to spoof security classification."),
)
_FUNCTION = re.compile(r"^\s*(?:[\w:<>,*&~]+\s+)+(?P<name>[A-Za-z_]\w*)\s*\([^;]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{")
_CONTROL = {"if", "for", "while", "switch", "catch"}
_DBG_REF = re.compile(r"!dbg\s+!(?P<id>\d+)")
_DILOCATION = re.compile(r"^!(?P<id>\d+)\s*=\s*!DILocation\([^)]*line:\s*(?P<line>\d+)")

# Recommended pass constraints when specific security rules are triggered
RULE_PASS_CONSTRAINTS = {
    "CWE-242": {
        "prefer": ["dce", "simplifycfg"],
        "avoid": ["loop-unroll", "loop-vectorize", "slp-vectorizer", "aggressive-instcombine"],
    },
    "CWE-120": {
        "prefer": ["sroa", "mem2reg", "simplifycfg"],
        "avoid": ["loop-unroll", "loop-vectorize", "slp-vectorizer"],
    },
    "IR-UNSAFE-CALL": {
        "prefer": ["simplifycfg", "dce"],
        "avoid": ["inline", "loop-unroll", "loop-vectorize"],
    },
    "IR-MEMCPY-REVIEW": {
        "prefer": ["sroa", "mem2reg", "instcombine"],
        "avoid": ["loop-unroll"],
    },
}


def _without_comments(line: str) -> str:
    return re.sub(r"//.*$|/\*.*?\*/", "", line)


class SecurityAnalyzer:
    """Scan source and IR with line-aware, explainable rules and IR-to-source mapping."""

    def analyze(self, source_path: str, ir_path: str = "", include_prompt_scan: bool = False) -> list[SecurityFinding]:
        findings = []
        source = Path(source_path) if source_path else None
        if source and source.is_file():
            findings.extend(self._scan_source(source))
            if include_prompt_scan:
                findings.extend(self.scan_adversarial_directives(source))
        ir = Path(ir_path) if ir_path else None
        if ir and ir.is_file():
            findings.extend(self._scan_ir(ir, source_path=str(source) if source else ""))
        # The source and IR checks may identify the same issue; keep both because
        # one gives source coordinates and the other proves it survived lowering.
        return findings

    @staticmethod
    def scan_adversarial_directives(path_or_text, is_text: bool = False) -> list[SecurityFinding]:
        """Scan raw source text (including comments/strings) or prompt text for adversarial instructions."""
        raw_str = str(path_or_text or "")
        is_existing_file = False
        if not is_text and "\n" not in raw_str and len(raw_str) < 400:
            try:
                is_existing_file = Path(raw_str).is_file()
            except OSError:
                is_existing_file = False

        if is_existing_file:
            path = Path(raw_str)
            text = path.read_text(errors="replace")
            file_label = str(path)
        else:
            text = raw_str
            file_label = "<input>"
        out = []
        for number, raw in enumerate(text.splitlines(), 1):
            for rule, severity, pattern, message in _PROMPT_INJECTION_RULES:
                if pattern.search(raw):
                    out.append(SecurityFinding(
                        rule_id=rule, severity=severity, message=message,
                        file_path=file_label, line=number, function="<comment/directive>",
                        source_kind="prompt_guard", snippet=raw.strip()[:180]))
        return out

    @staticmethod
    def summarize_for_planner(findings: list[SecurityFinding]) -> dict:
        """Build structured security guidance for the Boss and IR/HW Planner Agents."""
        prefer = []
        avoid = []
        by_function = {}
        high_or_critical = 0
        for f in findings:
            if f.severity in ("high", "critical"):
                high_or_critical += 1
            fn = f.function or "<unknown>"
            by_function.setdefault(fn, []).append(f.rule_id)
            constraints = RULE_PASS_CONSTRAINTS.get(f.rule_id, {})
            for p in constraints.get("prefer", []):
                if p not in prefer:
                    prefer.append(p)
            for a in constraints.get("avoid", []):
                if a not in avoid:
                    avoid.append(a)
        return {
            "finding_count": len(findings),
            "high_severity_count": high_or_critical,
            "prefer_passes": prefer,
            "avoid_passes": [a for a in avoid if a not in prefer],
            "by_function": by_function,
            "has_adversarial_directive": any(f.source_kind == "prompt_guard" for f in findings),
        }

    def _scan_source(self, path: Path) -> list[SecurityFinding]:
        text = path.read_text(errors="replace")
        out, function, depth = [], "<global>", 0
        for number, raw in enumerate(text.splitlines(), 1):
            line = _without_comments(raw)
            match = _FUNCTION.match(line)
            if match and match.group("name") not in _CONTROL:
                function = match.group("name")
            for rule, severity, pattern, message in _SOURCE_RULES:
                if pattern.search(line):
                    out.append(SecurityFinding(
                        rule_id=rule, severity=severity, message=message,
                        file_path=str(path), line=number, function=function,
                        source_kind="source", snippet=raw.strip()[:180]))
            depth += line.count("{") - line.count("}")
            if depth <= 0:
                depth, function = 0, "<global>"
        return out

    def _scan_ir(self, path: Path, source_path: str = "") -> list[SecurityFinding]:
        text = path.read_text(errors="replace")
        lines = text.splitlines()
        # Extract !DILocation metadata table for source-to-IR traceability
        dbg_line_map = {}
        for raw in lines:
            m = _DILOCATION.match(raw.strip())
            if m:
                dbg_line_map[m.group("id")] = int(m.group("line"))

        out, function = [], "<unknown>"
        for number, raw in enumerate(lines, 1):
            start = re.search(r"^\s*define\b.*?@([\w.$-]+)\s*\(", raw)
            if start:
                function = start.group(1)
            for rule, severity, pattern, message in _IR_RULES:
                if pattern.search(raw):
                    mapped_line = number
                    dbg_match = _DBG_REF.search(raw)
                    msg = message
                    if dbg_match and dbg_match.group("id") in dbg_line_map:
                        src_line = dbg_line_map[dbg_match.group("id")]
                        mapped_line = src_line
                        msg = f"{message} (Traced to source line {src_line})"
                    out.append(SecurityFinding(
                        rule_id=rule, severity=severity, message=msg,
                        file_path=str(path), line=mapped_line, function=function,
                        source_kind="llvm_ir", snippet=raw.strip()[:180]))
            if raw.strip() == "}":
                function = "<unknown>"
        return out
