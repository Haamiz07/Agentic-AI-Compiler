"""Load scenario-driven Attack Lab reports without executing scenario payloads.

The scenarios are inert text samples from configs/security_scenarios.json. The
lab applies the project's existing checks to those strings and labels results;
it is a demonstration harness, not a live agent sandbox.
"""
from __future__ import annotations

import json
import re
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import analysis as _analysis
from .analysis import SecurityAnalyzer
from .policy import PassPolicy

ROOT = Path(__file__).resolve().parents[2]
VISIBLE_SCENARIOS = ROOT / 'configs' / 'security_scenarios.json'
HELDOUT_SCENARIOS = ROOT / 'configs' / 'security_heldout.json'
LOG_PATH = Path('/tmp/agentic_c/attack_lab_log.jsonl')
_LOG_LOCK = threading.Lock()

# These are unchanged from the first Attack Lab prototype. No cases in the new
# JSON corpus were used to add or tune these checks.
_PROMPT_INJECTION_PATTERNS = (
    re.compile(r"\b(?:ignore|override|bypass|disregard)\b.{0,70}\b(?:security\s+)?(?:policy|rules|instructions|guardrails)\b", re.I),
    re.compile(r"\b(?:disable|skip|turn\s+off)\b.{0,45}\b(?:validation|verifier|safety\s+checks?)\b", re.I),
    re.compile(r"\bmark\b.{0,35}\b(?:vulnerable|unsafe|malicious)\b.{0,25}\bsafe\b", re.I),
)
_SENSITIVE_ACCESS = re.compile(r"(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|\.ssh[/\\]|id_rsa|/etc/passwd|keychain|credentials)", re.I)
_NETWORK_SEND = re.compile(r"(?:\bcurl\b|\bwget\b|\bsocket\s*\(|\bconnect\s*\(|\bsend\s*\(|\bsystem\s*\()", re.I)


def _detect_prompt(text: str) -> tuple[bool, str]:
    for pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(text or ''):
            return True, 'A configured prompt-injection phrase matched.'
    return False, 'No configured prompt-injection phrase matched.'


def _detect_data_access(code: str) -> tuple[bool, str]:
    sensitive = bool(_SENSITIVE_ACCESS.search(code or ''))
    outbound = bool(_NETWORK_SEND.search(code or ''))
    if sensitive and outbound:
        return True, 'Sensitive-data and outbound-transfer indicators matched.'
    if sensitive:
        return True, 'A configured sensitive credential or path indicator matched.'
    return False, 'No configured sensitive-data indicator matched.'


def _pattern_counts() -> dict:
    source = len(_analysis._SOURCE_RULES)
    ir = len(_analysis._IR_RULES)
    lab = len(_PROMPT_INJECTION_PATTERNS) + 2  # sensitive-access and outbound-transfer patterns
    return {'source': source, 'llvm_ir': ir, 'attack_lab': lab,
            'regex_total': source + ir + lab,
            'source_score_uses': source}


def load_scenarios(heldout: bool = False) -> list[dict]:
    """Load a dataset from disk. Held-out data is only loaded on explicit request."""
    path = HELDOUT_SCENARIOS if heldout else VISIBLE_SCENARIOS
    payload = json.loads(path.read_text(encoding='utf-8'))
    if payload.get('dataset') != ('held_out_do_not_tune' if heldout else 'visible_demo'):
        raise ValueError(f'Unexpected dataset marker in {path.name}')
    rows = payload.get('scenarios')
    if not isinstance(rows, list):
        raise ValueError(f'No scenario list in {path.name}')
    required = {'id', 'name', 'category', 'input', 'label', 'evasive', 'notes'}
    for row in rows:
        if not required.issubset(row) or row['label'] not in {'malicious', 'benign'}:
            raise ValueError(f'Invalid scenario record in {path.name}: {row.get("id", "<no id>")}')
    return rows


def _source_findings(code: str) -> list[dict]:
    """Apply existing source scanner rules to inert text; never compile or execute it."""
    with tempfile.TemporaryDirectory(prefix='agentic_attack_case_') as tmp:
        sample = Path(tmp) / 'scenario.cpp'
        sample.write_text(code or '', encoding='utf-8')
        findings = SecurityAnalyzer().analyze(str(sample))
    return [finding.to_dict() for finding in findings]


def _evaluate(row: dict, policy: PassPolicy) -> dict:
    kind = row.get('input_type', 'source_code')
    text = str(row.get('input', ''))
    detected, reason, blocked = False, '', False
    trace_results = []
    finding_ids = []

    if kind == 'prompt':
        detected, reason = _detect_prompt(text)
        # This is a simulated prompt gate, not a live planner input control.
        blocked = detected
    elif kind == 'source_code':
        data_hit, data_reason = _detect_data_access(text)
        findings = _source_findings(text)
        finding_ids = list(dict.fromkeys(item['rule_id'] for item in findings))
        detected = data_hit or bool(findings)
        reason_parts = ([data_reason] if data_hit else []) + [f['message'] for f in findings]
        reason = '; '.join(reason_parts) if reason_parts else data_reason
        # Simulate rejecting a candidate when the demo scanner flags it.
        blocked = detected
    elif kind == 'agent_trace':
        trace_text = text + ' ' + json.dumps(row.get('trace', []), ensure_ascii=False)
        prompt_hit, prompt_reason = _detect_prompt(trace_text)
        data_hit, data_reason = _detect_data_access(trace_text)
        detected = prompt_hit or data_hit
        reason = '; '.join(r for hit, r in ((prompt_hit, prompt_reason), (data_hit, data_reason)) if hit)
        if not reason:
            reason = 'No configured prompt or data-access indicator matched the simulated plan.'
        trace_denials = []
        for event in row.get('trace', []):
            event = dict(event)
            if event.get('kind') == 'compiler_pass':
                decision = policy.authorize(str(event.get('operation', '')))
                event['status'] = 'blocked by compiler-pass allowlist' if not decision.allowed else 'allowed by compiler-pass allowlist'
                event['reason'] = decision.reason
                event['blocked'] = not decision.allowed
                detected = detected or not decision.allowed
                blocked = blocked or not decision.allowed
                if not decision.allowed:
                    trace_denials.append(decision.reason)
            else:
                event['status'] = 'allowed in simulation; prototype has no matching live tool firewall'
                event['reason'] = 'The current policy gate controls LLVM pass names, not this tool/resource type.'
                event['blocked'] = False
            trace_results.append(event)
        if trace_denials:
            reason = '; '.join([reason] + [f'Pass policy: {item}' for item in trace_denials])
        # A pattern finding is detection. It only counts as blocked when a
        # simulated compiler-pass decision actually denies an operation.
    else:
        reason = f'Unsupported scenario input_type: {kind}'

    malicious = row['label'] == 'malicious'
    outcome = 'TP' if malicious and detected else 'FN' if malicious else 'FP' if detected else 'TN'
    if outcome == 'FN' and not reason:
        reason = 'The scenario is malicious, but none of the configured checks matched.'
    return {
        'id': row['id'], 'name': row['name'], 'category': row['category'],
        'input': text, 'input_type': kind, 'expected_label': row['label'],
        'evasive': bool(row['evasive']), 'case_type': row.get('case_type', 'evasive_attack' if row['evasive'] else 'obvious_attack'), 'scanner_verdict': 'FLAGGED' if detected else 'NO MATCH',
        'detected': detected, 'blocked': blocked, 'outcome': outcome,
        'reason': reason, 'notes': row['notes'], 'finding_ids': finding_ids,
        'gap_technique': row.get('gap_technique', '') if outcome == 'FN' else '',
        'trace': trace_results, 'trace_is_simulated': kind == 'agent_trace',
    }


def _metrics(rows: list[dict]) -> dict:
    tp = sum(r['outcome'] == 'TP' for r in rows)
    fp = sum(r['outcome'] == 'FP' for r in rows)
    fn = sum(r['outcome'] == 'FN' for r in rows)
    tn = sum(r['outcome'] == 'TN' for r in rows)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    attacks = [r for r in rows if r['expected_label'] == 'malicious']
    block_rate = sum(r['blocked'] for r in attacks) / len(attacks) if attacks else 0.0
    # Block rate adds information only when enforcement differs from detection.
    same_as_recall = round(block_rate, 10) == round(recall, 10)
    return {
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'precision_pct': round(100 * precision, 1),
        'recall_pct': round(100 * recall, 1), 'f1_pct': round(100 * f1, 1),
        'block_rate_pct': None if same_as_recall else round(100 * block_rate, 1),
        'block_rate_omitted': same_as_recall,
        'scenario_count': len(rows), 'attack_count': len(attacks),
        'precision_fraction': f'{tp}/{tp + fp}' if tp + fp else 'n/a',
        'recall_fraction': f'{tp}/{tp + fn}' if tp + fn else 'n/a',
        'block_fraction': f'{sum(r["blocked"] for r in attacks)}/{len(attacks)}' if attacks else 'n/a',
    }


def _code_score(source_path: str) -> dict:
    if not source_path:
        return {'available': False, 'score_pct': None, 'scanned_lines': 0,
                'flagged_lines': 0, 'finding_count': 0,
                'note': 'Run the compiler on a source file to calculate this heuristic.'}
    path = Path(source_path)
    if not path.is_file():
        path = ROOT / source_path
    if not path.is_file():
        return {'available': False, 'score_pct': None, 'scanned_lines': 0,
                'flagged_lines': 0, 'finding_count': 0,
                'note': 'The source file from the latest run could not be located.'}
    try:
        lines = path.read_text(errors='replace').splitlines()
        code_lines = [line for line in lines if line.strip() and not line.lstrip().startswith(('//', '/*', '*', '*/'))]
        findings = SecurityAnalyzer().analyze(str(path))
        flagged = {f.line for f in findings if f.line is not None}
        denominator = len(code_lines)
        score = 100.0 * max(0, denominator - len(flagged)) / denominator if denominator else 100.0
        return {'available': True, 'score_pct': round(score, 1),
                'scanned_lines': denominator, 'flagged_lines': len(flagged),
                'source_patterns': len(_analysis._SOURCE_RULES),
                'finding_count': len(findings),
                'note': 'Share of nonblank, non-comment lines with no match from the limited source-rule set. Not a probability or proof of security.',
                'source_path': str(path)}
    except OSError as exc:
        return {'available': False, 'score_pct': None, 'scanned_lines': 0,
                'flagged_lines': 0, 'finding_count': 0, 'note': f'Source scan failed: {exc}'}


def build_report(source_path: str = '', category: str | None = None,
                 heldout: bool = False) -> dict:
    dataset = load_scenarios(heldout=heldout)
    categories = sorted({row['category'] for row in load_scenarios(False)}) if heldout else sorted({row['category'] for row in dataset})
    selected = [row for row in dataset if category is None or row['category'] == category]
    if category is not None and not selected:
        raise ValueError(f'Unknown or empty scenario category: {category}')
    evaluated = [_evaluate(row, PassPolicy()) for row in selected]
    return {
        'status': 'ready', 'dataset': 'heldout' if heldout else 'visible_demo',
        'created_at': datetime.now(timezone.utc).isoformat(),
        'selected_category': category or 'All scenarios', 'categories': categories,
        'category_counts': {name: sum(row['category'] == name for row in load_scenarios(False)) for name in categories},
        'scenarios': evaluated, 'metrics': _metrics(evaluated),
        'code_safety': _code_score(source_path), 'pattern_counts': _pattern_counts(),
        'scope_note': 'Results measure only these hand-built scenarios, not general protection.',
        'simulation_note': 'Agent traces and candidate blocking are simulated. Scenario text is never executed.',
    }


def save_report(report: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LOG_LOCK, LOG_PATH.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(report, ensure_ascii=False) + '\n')


def latest_report(source_path: str = '', category: str | None = None) -> dict:
    """Generate a fresh visible-set preview; held-out data is never included."""
    return build_report(source_path, category=category, heldout=False)
