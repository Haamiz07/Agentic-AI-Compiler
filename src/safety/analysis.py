"""Small, explainable source and LLVM IR safety scanner.

Findings are review signals, not proof that a vulnerability is exploitable.
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
    ("IR-MEMCPY-REVIEW", "medium", re.compile(r"\bcall\b[^\n]*@(?:memcpy|memmove)\b"), "IR contains a memory-copy call; bounds depend on runtime values."),
)
_FUNCTION = re.compile(r"^\s*(?:[\w:<>,*&~]+\s+)+(?P<name>[A-Za-z_]\w*)\s*\([^;]*\)\s*(?:const\s*)?(?:noexcept\s*)?\{")
_CONTROL = {"if", "for", "while", "switch", "catch"}


def _without_comments(line: str) -> str:
    return re.sub(r"//.*$|/\*.*?\*/", "", line)


class SecurityAnalyzer:
    """Scan source and IR with line-aware, deliberately limited rules."""

    def analyze(self, source_path: str, ir_path: str = "") -> list[SecurityFinding]:
        findings = []
        source = Path(source_path)
        if source.is_file():
            findings.extend(self._scan_source(source))
        ir = Path(ir_path) if ir_path else None
        if ir and ir.is_file():
            findings.extend(self._scan_ir(ir))
        # The source and IR checks may identify the same issue; keep both because
        # one gives source coordinates and the other proves it survived lowering.
        return findings

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

    def _scan_ir(self, path: Path) -> list[SecurityFinding]:
        out, function = [], "<unknown>"
        for number, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
            start = re.search(r"^\s*define\b.*?@([\w.$-]+)\s*\(", raw)
            if start:
                function = start.group(1)
            for rule, severity, pattern, message in _IR_RULES:
                if pattern.search(raw):
                    out.append(SecurityFinding(
                        rule_id=rule, severity=severity, message=message,
                        file_path=str(path), line=number, function=function,
                        source_kind="llvm_ir", snippet=raw.strip()[:180]))
            if raw.strip() == "}":
                function = "<unknown>"
        return out
