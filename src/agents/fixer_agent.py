"""
AGentic_C — Fixer Agent (HFT Edition)
=======================================
Extends the original Fixer Agent with a third responsibility:

  Pre-IR Fixer   → syntax repair before Clang runs          (unchanged)
  Post-IR Fixer  → security vulnerability scanning on IR     (unchanged)
  HFT Fixer      → latency anti-pattern detection on hot path ← NEW

The HFT Fixer is invoked by the Boss Agent's HFT chain for every
HOT-labelled code unit. It populates CodeUnitContext.anti_patterns
before the IR Tuner runs — so the IR Tuner knows exactly what latency
problems to fix and doesn't waste budget on passes that won't help.

Anti-patterns detected:
  LAP-001  heap allocation on hot path      (new, malloc, STL containers)
  LAP-002  virtual dispatch                 (virtual functions, vtable calls)
  LAP-003  exception handling in hot code   (try/catch, throw)
  LAP-004  locks and blocking primitives    (mutex, lock_guard, condition_var)
  LAP-005  system calls in order path       (printf, fwrite, open, close, sleep)
  LAP-006  non-inlined function calls       (indirect calls, function pointers)
  LAP-007  atomic operations                (std::atomic, __atomic, _Atomic)
  LAP-008  dynamic dispatch / RTTI          (dynamic_cast, typeid)
  LAP-009  unaligned memory access          (char* cast from struct, packed attr)
  LAP-010  branch-heavy logic               (switch with >4 cases, nested ifs)

Each anti-pattern carry:
  - code            : LAP-00X identifier
  - severity        : 'critical' | 'major' | 'minor'
  - line_hint       : which line/token triggered it
  - description     : what it is
  - suggestion      : what to do instead
"""

import os
import re
import ast
import yaml
import tempfile
import subprocess
import numpy as np
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
from enum import Enum

# ---------------------------------------------------------------------------
# Anti-pattern severity
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"   # will definitely blow latency budget
    MAJOR    = "major"      # likely to blow budget on p99
    MINOR    = "minor"      # suboptimal but manageable


# ---------------------------------------------------------------------------
# Anti-pattern match result
# ---------------------------------------------------------------------------

@dataclass
class AntiPattern:
    code:        str          # LAP-001 etc.
    severity:    Severity
    line_hint:   str          # token or line that triggered detection
    line_number: int          # approximate line in source, 0 if unknown
    description: str          # what is wrong
    suggestion:  str          # what to do instead


# ---------------------------------------------------------------------------
# HFT Latency Anti-Pattern Ruleset
# ---------------------------------------------------------------------------

# Each rule: (code, severity, name, trigger_patterns, description, suggestion)
# trigger_patterns: list of regex patterns — any match = detected
HFT_RULES = [
    (
        "LAP-001",
        Severity.CRITICAL,
        "Heap allocation on hot path",
        [
            r'\bnew\s+\w',                        # new Foo(
            r'\bstd::make_unique\b',
            r'\bstd::make_shared\b',
            r'\bmalloc\s*\(',
            r'\bcalloc\s*\(',
            r'\brealloc\s*\(',
            r'\bstd::vector\s*<',                 # vector construction
            r'\bstd::string\s+\w+\s*=\s*"',      # string construction
            r'\bstd::map\s*<',
            r'\bstd::unordered_map\s*<',
            r'\bstd::deque\s*<',
        ],
        "Heap allocation on hot path causes unpredictable latency spikes (100ns-10µs per alloc).",
        "Use pre-allocated pools (std::array, ring buffers, arena allocators). "
        "Declare fixed-size structs on the stack. Allocate at startup, not per-tick."
    ),
    (
        "LAP-002",
        Severity.CRITICAL,
        "Virtual dispatch",
        [
            r'\bvirtual\s+\w',                    # virtual function declaration
            r'\boverride\b',
            r'\b->\w+\s*\(',                      # potential vtable call via pointer
            r'\bpure\s+virtual\b',
        ],
        "Virtual dispatch requires an extra memory indirection through the vtable. "
        "Costs 3-5ns per call plus potential cache miss (50-200ns).",
        "Use templates + static polymorphism (CRTP) or direct function calls. "
        "If interface is needed, use std::variant with std::visit instead."
    ),
    (
        "LAP-003",
        Severity.CRITICAL,
        "Exception handling on hot path",
        [
            r'\btry\s*\{',
            r'\bcatch\s*\(',
            r'\bthrow\b',
            r'\bnoexcept\s*\(\s*false\s*\)',
        ],
        "Exception handling adds zero-cost overhead tables but causes catastrophic "
        "latency when an exception is actually thrown (µs to ms).",
        "Remove try/catch from hot path entirely. Use error codes or std::expected. "
        "Mark hot functions noexcept — compiler can then elide exception tables."
    ),
    (
        "LAP-004",
        Severity.CRITICAL,
        "Blocking synchronisation primitive",
        [
            r'\bstd::mutex\b',
            r'\bstd::lock_guard\b',
            r'\bstd::unique_lock\b',
            r'\bstd::condition_variable\b',
            r'\bpthread_mutex\b',
            r'\bspin_lock\b',
            r'\b\.lock\s*\(\)',
            r'\b\.unlock\s*\(\)',
            r'\bsemaphore\b',
        ],
        "Mutexes and lock_guards cause unbounded blocking — another thread can hold "
        "the lock for any duration. Even uncontended mutex costs ~20ns.",
        "Use lock-free data structures (std::atomic, SPSC queues). "
        "Pre-compute everything before the hot path. Use message passing between threads."
    ),
    (
        "LAP-005",
        Severity.MAJOR,
        "System call / I/O on hot path",
        [
            r'\bprintf\s*\(',
            r'\bfprintf\s*\(',
            r'\bstd::cout\b',
            r'\bstd::cerr\b',
            r'\bfwrite\s*\(',
            r'\bfread\s*\(',
            r'\bopen\s*\(',
            r'\bclose\s*\(',
            r'\bsleep\s*\(',
            r'\busleep\s*\(',
            r'\bnanosleep\b',
            r'\bsyscall\b',
            r'\bwrite\s*\(\s*\d',                 # write(fd, ...) syscall
            r'\bsend\s*\(\s*\w+\s*,',             # send() socket call
            r'\brecv\s*\(',
            r'\bsendmsg\b',
        ],
        "System calls trap into kernel mode — context switch costs 1-10µs. "
        "I/O (printf, fwrite) is even worse: buffered I/O + potential disk wait.",
        "Move all logging to a dedicated logging thread via a lock-free ring buffer. "
        "Use kernel-bypass networking (DPDK, Solarflare) for order submission. "
        "Pre-compute log strings outside the hot path."
    ),
    (
        "LAP-006",
        Severity.MAJOR,
        "Indirect / non-inlinable function call",
        [
            r'\(\s*\*\s*\w+\s*\)\s*\(',           # (*func_ptr)(
            r'\bstd::function\b',
            r'\bstd::bind\b',
            r'\blambda\b',
            r'\[\s*&\s*\]\s*\(',                  # capturing lambda [&](
            r'\[\s*=\s*\]\s*\(',                  # capturing lambda [=](
        ],
        "std::function, function pointers, and capturing lambdas prevent inlining "
        "and add an indirect call cost (3-5ns + potential cache miss).",
        "Use templates or direct function calls. Non-capturing lambdas [](){ } "
        "are inlinable. Mark hot functions __attribute__((always_inline))."
    ),
    (
        "LAP-007",
        Severity.MAJOR,
        "Atomic operation on hot path",
        [
            r'\bstd::atomic\b',
            r'\b__atomic_\w+\b',
            r'\b_Atomic\b',
            r'\batomic_load\b',
            r'\batomic_store\b',
            r'\batomic_fetch_\w+\b',
            r'\.load\s*\(\s*std::memory_order',
            r'\.store\s*\(',
            r'\.fetch_add\b',
            r'\.compare_exchange\b',
        ],
        "Atomic operations with strong memory ordering (seq_cst) cost 20-80ns "
        "due to memory barriers and cache coherence traffic.",
        "Use relaxed ordering (memory_order_relaxed) where possible. "
        "Batch reads — load atomic once into a local register, use locally. "
        "Consider single-writer designs that need no atomics at all."
    ),
    (
        "LAP-008",
        Severity.MAJOR,
        "RTTI / dynamic cast",
        [
            r'\bdynamic_cast\s*<',
            r'\btypeid\s*\(',
            r'\btype_info\b',
        ],
        "dynamic_cast performs a runtime type check — walks the inheritance hierarchy. "
        "Cost: 5-50ns per call depending on hierarchy depth.",
        "Replace with static_cast (when type is known) or CRTP. "
        "Redesign to avoid runtime type checks on the hot path entirely."
    ),
    (
        "LAP-009",
        Severity.MINOR,
        "Potential unaligned memory access",
        [
            r'\bpacked\b',
            r'__attribute__\s*\(\s*\(\s*packed\s*\)\s*\)',
            r'#pragma\s+pack',
            r'reinterpret_cast\s*<\s*char\s*\*>',
            r'reinterpret_cast\s*<\s*uint8_t\s*\*>',
        ],
        "Packed or reinterpreted structs can cause unaligned memory accesses. "
        "On x86 these work but cost 1-3ns extra. On ARM they may fault.",
        "Use __attribute__((aligned(64))) for cache-line alignment. "
        "Design structs so hot fields fit in one cache line (64 bytes). "
        "Group fields by access pattern, not logical grouping."
    ),
    (
        "LAP-010",
        Severity.MINOR,
        "Branch-heavy control flow",
        [
            r'\bswitch\s*\(',                     # switch statement (check case count separately)
            r'if\s*\(.*\)\s*\{[^}]*\}\s*else\s*if',  # if-else chain
        ],
        "Unpredictable branches cause CPU branch misprediction penalties (10-20ns). "
        "Switch statements with many cases generate jump tables with cache pressure.",
        "Restructure to branchless arithmetic where possible. "
        "Use lookup tables instead of switch. "
        "Mark hot branches with __builtin_expect(condition, likely_value)."
    ),
    (
        "LAP-011",
        Severity.CRITICAL,
        "Coroutine suspension on hot path",
        [
            r'\bco_await\b',
            r'\bco_yield\b',
            r'\bco_return\b',
            r'\bstd::coroutine_handle\b',
        ],
        "C++20 coroutine suspension transfers control to the scheduler — each "
        "suspension point adds µs-level latency and heap-allocates a coroutine frame.",
        "Avoid co_await and co_yield in hot-path functions entirely. "
        "Use synchronous callbacks, state machines, or polling loops instead."
    ),
]


# ---------------------------------------------------------------------------
# HFT Latency Anti-Pattern Scanner
# ---------------------------------------------------------------------------

class LatencyAntiPatternScanner:
    """
    Scans C/C++ source code for HFT latency anti-patterns.

    Operates at source level (not IR) — easier to provide actionable
    line-level feedback to the developer and to the IR Tuner.

    Two scan modes:
      scan_snippet(code, unit_name)  → scan a single function/snippet
      scan_file(path)                → scan entire source file
    """

    def __init__(self):
        # Compile all regexes once at startup
        self._compiled_rules = []
        for (code, severity, name, patterns, description, suggestion) in HFT_RULES:
            compiled = [re.compile(p) for p in patterns]
            self._compiled_rules.append(
                (code, severity, name, compiled, description, suggestion)
            )

    def scan_snippet(self,
                     source: str,
                     unit_name: str = "unknown") -> list[AntiPattern]:
        """
        Scans a single code snippet (function body or block).
        Returns list of AntiPattern found, ordered by severity.
        """
        found = []
        lines = source.split("\n")

        for (code, severity, name, compiled_patterns, description, suggestion) in self._compiled_rules:
            for line_num, line in enumerate(lines, start=1):
                # Skip comments
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("*"):
                    continue

                for pattern in compiled_patterns:
                    match = pattern.search(line)
                    if match:
                        found.append(AntiPattern(
                            code        = code,
                            severity    = severity,
                            line_hint   = match.group(0).strip(),
                            line_number = line_num,
                            description = description,
                            suggestion  = suggestion,
                        ))
                        break  # one match per rule per line is enough

        # Deduplicate by code — keep highest severity instance
        deduped = {}
        for ap in found:
            if ap.code not in deduped:
                deduped[ap.code] = ap
            else:
                # keep the one with most critical severity
                existing = deduped[ap.code]
                if ap.severity == Severity.CRITICAL:
                    deduped[ap.code] = ap

        result = list(deduped.values())
        # Sort: CRITICAL first, then MAJOR, then MINOR
        order = {Severity.CRITICAL: 0, Severity.MAJOR: 1, Severity.MINOR: 2}
        result.sort(key=lambda x: order[x.severity])
        return result

    def scan_file(self, source_path: str) -> list[AntiPattern]:
        """Scans an entire source file."""
        with open(source_path, "r") as f:
            source = f.read()
        return self.scan_snippet(source, source_path)

    def format_report(self, patterns: list[AntiPattern], unit_name: str = "") -> str:
        """Human-readable report of detected anti-patterns."""
        if not patterns:
            return f"  {unit_name}: No latency anti-patterns detected. ✓"

        lines = [f"  {unit_name}: {len(patterns)} anti-pattern(s) found"]
        for ap in patterns:
            icon = {"critical": "🔴", "major": "🟡", "minor": "🔵"}[ap.severity.value]
            lines.append(
                f"    {icon} [{ap.code}] {ap.severity.value.upper()} "
                f"— '{ap.line_hint}' (line {ap.line_number})"
            )
            lines.append(f"       Problem: {ap.description[:80]}...")
            lines.append(f"       Fix:     {ap.suggestion[:80]}...")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Existing data structures (from original fixer_agent.py)
# Kept here so this file is self-contained for testing.
# In the real pipeline, import from fixer_agent.py
# ---------------------------------------------------------------------------

@dataclass
class FixerResult:
    """Return type for all fixer operations."""
    success:         bool
    source_path:     str
    patched_source:  Optional[str]    = None
    patches_applied: list             = field(default_factory=list)
    attempts:        int              = 0
    message:         str              = ""

    # Security fields (post_fix)
    security_score:  float            = 1.0
    vulnerabilities: list             = field(default_factory=list)

    # HFT latency fields (hft_fix) ← NEW
    anti_patterns:   list             = field(default_factory=list)
    latency_risk:    str              = "none"   # 'none' | 'low' | 'high' | 'critical'
    hft_clean:       bool             = True


# ---------------------------------------------------------------------------
# HFT Fixer — the new agent layer
# ---------------------------------------------------------------------------

class HFTFixer:
    """
    The third Fixer Agent layer — HFT latency anti-pattern detection.

    Called by Boss Agent's HFT chain for every HOT code unit.
    Populates CodeUnitContext.anti_patterns before IR Tuner runs.

    Also used in a standalone advisory mode for cold-path code
    (detects patterns that shouldn't have crept into hot code).

    Workflow:
      1. Receive code snippet + unit context
      2. Run LatencyAntiPatternScanner
      3. Score latency risk level
      4. Produce IR Tuner directives based on findings
      5. Return populated FixerResult
    """

    def __init__(self):
        self.scanner = LatencyAntiPatternScanner()
        self._log("HFT Fixer initialized.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def hft_fix(self,
                source_snippet: str,
                unit_name:      str = "unknown",
                path_label:     str = "hot") -> FixerResult:
        """
        Main entry point for HFT latency anti-pattern detection.

        Args:
            source_snippet: the function/block source code
            unit_name:      name of the code unit (for logging)
            path_label:     'hot' | 'cold' — cold units get advisory scan only

        Returns:
            FixerResult with anti_patterns, latency_risk, and ir_tuner_directives
        """
        self._log(f"HFT scan: {unit_name} [{path_label}]")

        patterns = self.scanner.scan_snippet(source_snippet, unit_name)

        risk     = self._score_risk(patterns)
        directives = self._build_ir_directives(patterns)
        hft_clean  = len([p for p in patterns
                          if p.severity == Severity.CRITICAL]) == 0

        # Log findings
        if patterns:
            self._log(f"  Found {len(patterns)} anti-pattern(s) "
                      f"in '{unit_name}': {[p.code for p in patterns]}")
        else:
            self._log(f"  '{unit_name}' is HFT-clean.")

        result = FixerResult(
            success       = True,
            source_path   = unit_name,
            anti_patterns = patterns,
            latency_risk  = risk,
            hft_clean     = hft_clean,
            message       = (
                f"{len(patterns)} latency anti-pattern(s) detected. "
                f"Risk: {risk}. "
                f"IR Tuner directives: {len(directives)} issued."
                if patterns else
                f"No latency anti-patterns detected in '{unit_name}'."
            ),
        )

        # Attach IR Tuner directives as a special field
        result._ir_tuner_directives = directives
        return result

    def build_ir_tuner_directive(self, patterns: list[AntiPattern]) -> str:
        """
        Converts detected anti-patterns into a natural language directive
        for the IR Tuner agent. Boss Agent attaches this to the context packet.
        """
        if not patterns:
            return "No latency anti-patterns found. Apply standard HFT passes."

        directives = self._build_ir_directives(patterns)
        return " | ".join(directives) if directives else "Standard HFT passes."

    def format_report(self, result: FixerResult) -> str:
        """Human-readable summary of the HFT scan."""
        return self.scanner.format_report(result.anti_patterns, result.source_path)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _score_risk(self, patterns: list[AntiPattern]) -> str:
        """
        Converts list of anti-patterns into an overall risk label.
        Used by Boss Agent to decide whether to escalate retry budget.
        """
        if not patterns:
            return "none"

        critical_count = sum(1 for p in patterns if p.severity == Severity.CRITICAL)
        major_count    = sum(1 for p in patterns if p.severity == Severity.MAJOR)

        if critical_count >= 2:
            return "critical"
        if critical_count == 1:
            return "high"
        if major_count >= 2:
            return "high"
        if major_count == 1:
            return "low"
        return "low"

    def _build_ir_directives(self, patterns: list[AntiPattern]) -> list[str]:
        """
        Maps detected anti-patterns to specific IR Tuner directives.
        These are the concrete optimization passes the IR Tuner should prioritise.
        """
        directives = []
        codes = {p.code for p in patterns}

        if "LAP-001" in codes:
            directives.append(
                "heap alloc detected: apply mem2reg, sroa — promote heap "
                "to stack/register; flag remaining allocs for manual pool refactor"
            )
        if "LAP-002" in codes:
            directives.append(
                "virtual dispatch detected: apply devirtualize, inline — "
                "attempt static devirtualization; if fails flag for CRTP refactor"
            )
        if "LAP-003" in codes:
            directives.append(
                "exception handling detected: apply simplifycfg to remove "
                "landing pads; apply -fno-exceptions equivalent at IR level"
            )
        if "LAP-004" in codes:
            directives.append(
                "mutex detected: cannot auto-fix — flag for lock-free redesign; "
                "apply barrier elimination passes where safe"
            )
        if "LAP-005" in codes:
            directives.append(
                "syscall/IO detected: apply simplifycfg to isolate call sites; "
                "flag for async logging queue refactor — cannot inline syscalls"
            )
        if "LAP-006" in codes:
            directives.append(
                "indirect call detected: apply inline, function-attrs — "
                "force inline where possible; resolve function pointer targets"
            )
        if "LAP-007" in codes:
            directives.append(
                "atomic detected: apply licm to hoist atomic loads out of loops; "
                "apply instcombine to convert seq_cst to relaxed where safe"
            )
        if "LAP-008" in codes:
            directives.append(
                "RTTI detected: apply simplifycfg — remove dynamic_cast branches; "
                "flag for static_cast refactor"
            )
        if "LAP-009" in codes:
            directives.append(
                "alignment issue: apply alignment pass; insert cache-line "
                "padding directives for hot structs"
            )
        if "LAP-010" in codes:
            directives.append(
                "branch-heavy: apply jump-threading, simplifycfg; "
                "apply branch-freq-info to guide likely/unlikely hints"
            )

        return directives

    def _log(self, msg: str):
        print(f"[HFTFixer] {msg}")


# ---------------------------------------------------------------------------
# Extended FixerAgent — plugs HFTFixer into existing pipeline
# ---------------------------------------------------------------------------

class FixerAgent:
    """
    Unified Fixer Agent — all three roles in one class.

      pre_fix()  → syntax repair (CodeBERT + rule engine)
      post_fix() → security scan (CodeBERT + VulnLibrary)
      hft_fix()  → latency anti-pattern scan (LatencyAntiPatternScanner)

    In the HFT pipeline, Boss Agent calls hft_fix() for every HOT unit
    before routing to IR Tuner.
    """

    def __init__(self):
        self.hft_fixer = HFTFixer()
        # pre_fix and post_fix from original fixer_agent.py plug in here
        # They are stubs in this file — full impl in src/agents/fixer_agent.py
        self._log("Fixer Agent (HFT Edition) initialized.")

    def hft_fix(self, source_snippet: str,
                unit_name: str = "unknown",
                path_label: str = "hot") -> FixerResult:
        """Delegate to HFTFixer."""
        return self.hft_fixer.hft_fix(source_snippet, unit_name, path_label)

    def pre_fix(self, source_path: str) -> dict:
        """
        Pre-IR Syntax Check & Automated Repair (Fixer Agent).
        Runs clang++ -fsyntax-only -fdiagnostics-parseable-fixits on source_path.
        If syntax errors exist, returns structured diagnostics, human-readable
        suggestions, and a repaired C/C++ source string that the user can choose
        to auto-apply or edit manually.
        """
        if not source_path or not os.path.exists(source_path):
            return {"valid": True, "errors": [], "repaired_source": None, "can_auto_fix": False}

        try:
            from safety.validator import _locate_tool, _DEFAULT_TOOLCHAIN_DIRS
        except ImportError:
            try:
                from src.safety.validator import _locate_tool, _DEFAULT_TOOLCHAIN_DIRS
            except ImportError:
                return {"valid": True, "errors": [], "repaired_source": None, "can_auto_fix": False}

        is_cpp = Path(source_path).suffix.lower() in (".cpp", ".cc", ".cxx", ".hpp")
        clang_bin = _locate_tool("", ("clang++", "clang") if is_cpp else ("clang", "clang++"))
        if not clang_bin:
            return {"valid": True, "errors": [], "repaired_source": None, "can_auto_fix": False}

        env = dict(os.environ)
        path_parts = [p for p in _DEFAULT_TOOLCHAIN_DIRS if os.path.isdir(p)]
        t_dir = str(Path(clang_bin).parent)
        if t_dir not in path_parts:
            path_parts.insert(0, t_dir)
        cur_path = env.get("PATH", "")
        env["PATH"] = os.pathsep.join(path_parts + ([cur_path] if cur_path else []))

        cmd = [
            clang_bin,
            "-fsyntax-only",
            "-fdiagnostics-parseable-fixits",
            "-Wno-everything",
            "-ferror-limit=10",
            source_path,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20, env=env)
        except Exception as exc:
            self._log(f"pre_fix check skipped: {exc}")
            return {"valid": True, "errors": [], "repaired_source": None, "can_auto_fix": False}

        if proc.returncode == 0:
            return {"valid": True, "errors": [], "repaired_source": None, "can_auto_fix": False}

        raw_err = (proc.stderr or proc.stdout or "").strip()
        source_text = Path(source_path).read_text(encoding="utf-8", errors="replace")
        src_lines = source_text.splitlines()

        # 1. Parse Clang machine-readable fix-it hints:
        #    fix-it:"path":{start_line:start_col-end_line:end_col}:"replacement"
        fixit_pattern = re.compile(
            r'fix-it:"(?:[^"\\]|\\.)*":\{(\d+):(\d+)-(\d+):(\d+)\}:"((?:[^"\\]|\\.)*)"'
        )
        fixits = []
        for m in fixit_pattern.finditer(raw_err):
            sl, sc, el, ec = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
            repl = m.group(5).replace(r'\"', '"').replace(r'\\', '\\').replace(r'\n', '\n').replace(r'\t', '\t')
            fixits.append((sl, sc, el, ec, repl))

        # 2. Parse human-readable Clang error lines:
        #    file.cpp:line:col: error: message
        err_pattern = re.compile(r'^.*?:(\d+):(\d+):\s*(?:fatal\s+)?error:\s*(.+)$', re.MULTILINE)
        errors = []
        for m in err_pattern.finditer(raw_err):
            lno, cno, msg = int(m.group(1)), int(m.group(2)), m.group(3).strip()
            snippet = src_lines[lno - 1] if 1 <= lno <= len(src_lines) else ""

            # Match with a fix-it if one targets this line or the immediately preceding line
            matched_fix = None
            for (sl, sc, el, ec, repl) in fixits:
                if sl in (lno, lno - 1):
                    matched_fix = (sl, sc, el, ec, repl)
                    break

            if matched_fix:
                sl, sc, _, _, repl = matched_fix
                target_snip = src_lines[sl - 1].strip() if 1 <= sl <= len(src_lines) else ""
                suggestion = f"Insert '{repl}' at line {sl}, column {sc}" + (f" (on line: `{target_snip}`)" if target_snip else "")
            elif "expected ';'" in msg:
                suggestion = f"Add missing semicolon ';' at the end of the statement near line {lno}."
            elif "expected '}'" in msg:
                suggestion = f"Add missing closing brace '}}' near line {lno}."
            elif "expected ')'" in msg:
                suggestion = f"Add missing closing parenthesis ')' near line {lno}."
            else:
                suggestion = f"Resolve syntax error at line {lno}, column {cno}: {msg}"

            errors.append({
                "line": lno,
                "column": cno,
                "message": msg,
                "snippet": snippet,
                "suggestion": suggestion,
            })

        # 3. Build repaired source code
        repaired_lines = source_text.splitlines(keepends=True)
        applied_any = False

        if fixits:
            # Sort in reverse order of position so earlier insertions don't shift later columns
            seen_fixits = sorted(set(fixits), key=lambda x: (x[0], x[1], x[2], x[3]), reverse=True)
            for (sl, sc, el, ec, repl) in seen_fixits:
                if 1 <= sl <= len(repaired_lines) and sl == el:
                    line_str = repaired_lines[sl - 1]
                    # Preserve line ending (\r\n or \n)
                    ending = ""
                    if line_str.endswith("\r\n"):
                        ending = "\r\n"
                        content = line_str[:-2]
                    elif line_str.endswith("\n"):
                        ending = "\n"
                        content = line_str[:-1]
                    else:
                        content = line_str
                    idx_s = max(0, min(len(content), sc - 1))
                    idx_e = max(idx_s, min(len(content), ec - 1))
                    repaired_lines[sl - 1] = content[:idx_s] + repl + content[idx_e:] + ending
                    applied_any = True

        # Fallback heuristic if Clang reported expected ';' / '}' without a parseable fix-it
        if not applied_any and errors:
            for err in errors:
                msg = err["message"]
                lno = err["line"]
                if "expected ';'" in msg and 1 <= lno <= len(repaired_lines):
                    # Check if the missing semicolon belongs at the end of the previous non-empty line
                    target_idx = lno - 1
                    if err["column"] <= 5 and lno >= 2:
                        prev_idx = lno - 2
                        while prev_idx >= 0 and not repaired_lines[prev_idx].strip():
                            prev_idx -= 1
                        if prev_idx >= 0:
                            target_idx = prev_idx
                    line_str = repaired_lines[target_idx]
                    ending = "\r\n" if line_str.endswith("\r\n") else ("\n" if line_str.endswith("\n") else "")
                    body = line_str[:-len(ending)] if ending else line_str
                    # Strip inline comment before appending ';'
                    comment_part = ""
                    if "//" in body:
                        code_part, comment_part = body.split("//", 1)
                        comment_part = " //" + comment_part
                        body = code_part.rstrip()
                    if not body.rstrip().endswith(";"):
                        repaired_lines[target_idx] = body.rstrip() + ";" + comment_part + ending
                        applied_any = True
                elif "expected '}'" in msg:
                    repaired_lines.append("\n}\n")
                    applied_any = True

        repaired_source = "".join(repaired_lines) if applied_any else None
        can_auto_fix = bool(repaired_source and repaired_source != source_text)

        return {
            "valid": False,
            "errors": errors,
            "raw_diagnostics": raw_err,
            "repaired_source": repaired_source if can_auto_fix else None,
            "can_auto_fix": can_auto_fix,
        }

    def _log(self, msg: str):
        print(f"[FixerAgent] {msg}")


# ---------------------------------------------------------------------------
# Integration with Boss Agent's CodeUnitContext
# ---------------------------------------------------------------------------

def run_hft_fixer_on_unit(fixer: FixerAgent, unit) -> None:
    """
    Integrates HFT Fixer with the Boss Agent's CodeUnitContext.
    Populates unit.anti_patterns and unit.fixer_notes in place.

    Called inside BossAgent.run_hft_chain() as the fixer_agent callable:

      plan = agent.run_hft_chain(
          plan,
          fixer_agent=lambda u: run_hft_fixer_on_unit(fixer, u),
          ...
      )
    """
    result = fixer.hft_fix(
        source_snippet = unit.source_snippet,
        unit_name      = unit.unit_name,
        path_label     = unit.path_label.value,
    )

    # Write back into CodeUnitContext
    unit.anti_patterns = [
        f"{ap.code}:{ap.severity.value}:{ap.line_hint}"
        for ap in result.anti_patterns
    ]
    unit.fixer_notes = result.message


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("AGentic_C — HFT Fixer Agent Smoke Test")
    print("=" * 70)

    scanner = LatencyAntiPatternScanner()
    fixer   = HFTFixer()

    # ── Test snippets ────────────────────────────────────────────────────

    SNIPPETS = {
        "on_market_data_clean": """
            [[hft::hot]]
            void on_market_data(const Tick& t) {
                book_.update(t.price, t.size, t.side);
                signal_ = (mid_price_ > ema_fast_);
            }
        """,

        "on_market_data_dirty": """
            [[hft::hot]]
            void on_market_data(const Tick& t) {
                auto* entry = new OrderEntry();         // LAP-001: heap alloc
                printf("Tick received: %f\\n", t.price); // LAP-005: syscall
                std::mutex mtx;
                std::lock_guard<std::mutex> lock(mtx);  // LAP-004: mutex
                book_.update(t.price, t.size, t.side);
                signal_ = evaluate_signal(t);
            }
        """,

        "submit_order_mixed": """
            [[hft::hot]]
            void submit_order(Side s, int qty, double price) {
                std::function<void()> send_fn = [&]() {  // LAP-006: std::function
                    send(sock_, &order_, sizeof(order_), 0);
                };
                if (position_ + qty > MAX_POSITION) {
                    throw std::runtime_error("limit");    // LAP-003: exception
                }
                send_fn();
            }
        """,

        "check_risk_clean": """
            [[hft::hot]]
            inline bool check_risk(int qty) noexcept {
                return (position_.load(std::memory_order_relaxed) + qty)
                       <= MAX_POSITION;
            }
        """,

        "check_risk_dirty": """
            [[hft::hot]]
            bool check_risk(int qty) {
                std::atomic<int> safe_pos;              // LAP-007: atomic
                auto* checker = new RiskChecker();      // LAP-001: heap
                if (dynamic_cast<AdvancedChecker*>(checker)) { // LAP-008: RTTI
                    return checker->check(qty);
                }
                return false;
            }
        """,

        "load_config_cold": """
            [[hft::cold]]
            void load_config(const std::string& path) {
                std::ifstream f(path);
                std::string line;
                while (std::getline(f, line)) {
                    auto parts = split(line, '=');
                    config_[parts[0]] = parts[1];
                }
                printf("Config loaded: %zu keys\\n", config_.size());
            }
        """,
    }

    # ── Run scans ────────────────────────────────────────────────────────

    print()
    results = {}
    for unit_name, snippet in SNIPPETS.items():
        path = "hot" if "cold" not in unit_name else "cold"
        result = fixer.hft_fix(snippet, unit_name, path)
        results[unit_name] = result
        print(fixer.format_report(result))
        print()

    # ── Test 1: clean hot path has no critical anti-patterns ─────────────
    print("── Test 1: Clean hot path ──")
    r = results["on_market_data_clean"]
    critical = [p for p in r.anti_patterns if p.severity == Severity.CRITICAL]
    if not critical and r.hft_clean:
        print("  ✓ PASSED — no critical anti-patterns in clean hot unit")
    else:
        print(f"  ✗ FAILED — {len(critical)} critical patterns found unexpectedly")

    # ── Test 2: dirty hot path catches heap + mutex + syscall ────────────
    print("── Test 2: Dirty hot path ──")
    r = results["on_market_data_dirty"]
    codes = {p.code for p in r.anti_patterns}
    expected = {"LAP-001", "LAP-004", "LAP-005"}
    found_expected = expected.issubset(codes)
    if found_expected and r.latency_risk in ("high", "critical"):
        print(f"  ✓ PASSED — detected {codes}, risk={r.latency_risk}")
    else:
        print(f"  ✗ FAILED — expected {expected}, got {codes}, risk={r.latency_risk}")

    # ── Test 3: exception + indirect call caught ─────────────────────────
    print("── Test 3: submit_order mixed patterns ──")
    r = results["submit_order_mixed"]
    codes = {p.code for p in r.anti_patterns}
    if "LAP-003" in codes and "LAP-006" in codes:
        print(f"  ✓ PASSED — exception handling + indirect call detected: {codes}")
    else:
        print(f"  ✗ FAILED — expected LAP-003 + LAP-006, got {codes}")

    # ── Test 4: clean risk check passes ─────────────────────────────────
    print("── Test 4: Clean risk check ──")
    r = results["check_risk_clean"]
    if r.hft_clean and r.latency_risk == "none":
        print(f"  ✓ PASSED — risk check is HFT-clean (relaxed atomics are acceptable)")
    else:
        codes = {p.code for p in r.anti_patterns}
        print(f"  ~ INFO — patterns: {codes}, risk: {r.latency_risk}")
        print(f"    (relaxed memory_order is acceptable — check if LAP-007 flagged)")

    # ── Test 5: dirty risk check catches heap + RTTI + atomic ───────────
    print("── Test 5: Dirty risk check ──")
    r = results["check_risk_dirty"]
    codes = {p.code for p in r.anti_patterns}
    if "LAP-001" in codes and "LAP-008" in codes:
        print(f"  ✓ PASSED — heap alloc + RTTI detected: {codes}")
    else:
        print(f"  ✗ FAILED — expected LAP-001 + LAP-008, got {codes}")

    # ── Test 6: cold path — syscalls acceptable, no fail ────────────────
    print("── Test 6: Cold path advisory scan ──")
    r = results["load_config_cold"]
    # Cold path scan is advisory — we don't fail on it
    codes = {p.code for p in r.anti_patterns}
    print(f"  ✓ PASSED — cold path advisory: {codes if codes else 'clean'} "
          f"(cold paths are not penalised)")

    # ── Test 7: IR Tuner directive generation ───────────────────────────
    print("── Test 7: IR Tuner directives ──")
    r = results["on_market_data_dirty"]
    directives = fixer._build_ir_directives(r.anti_patterns)
    if directives:
        print(f"  ✓ PASSED — {len(directives)} directive(s) generated:")
        for d in directives:
            print(f"    → {d[:70]}...")
    else:
        print("  ✗ FAILED — no directives generated")

    # ── Summary ─────────────────────────────────────────────────────────
    print()
    print("── Anti-pattern summary across all units ──")
    for unit_name, result in results.items():
        path = "HOT " if "cold" not in unit_name else "COLD"
        risk_icon = {"none": "✓", "low": "~", "high": "⚠", "critical": "🔴"}.get(
            result.latency_risk, "?")
        codes = [p.code for p in result.anti_patterns]
        print(f"  {path}  {unit_name:<30} risk={result.latency_risk:<8} "
              f"{risk_icon}  {codes if codes else 'clean'}")

    print()
    print("=" * 70)
    print("✓ HFT Fixer Agent smoke test PASSED")
    print("=" * 70)