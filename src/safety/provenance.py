"""Hash-based build provenance records for compiler outputs.

The manifest detects whether recorded files changed after a build. It is not
signed, so it does not authenticate who created the manifest or prove that a
build is secure.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1


def sha256_file(path: str | Path) -> str:
    """Return the SHA-256 digest of a file, reading it in bounded chunks."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_record(path: str | Path | None, role: str) -> dict[str, Any] | None:
    if not path:
        return None
    artifact = Path(path).expanduser().resolve()
    if not artifact.is_file():
        return {"role": role, "path": str(artifact), "available": False}
    return {
        "role": role,
        "path": str(artifact),
        "available": True,
        "size_bytes": artifact.stat().st_size,
        "sha256": sha256_file(artifact),
    }


def _validation_summary(validation: Any) -> dict[str, Any] | None:
    if validation is None:
        return None
    fields = (
        "passed", "compile_success", "behavior_checked", "behavior_preserved",
        "benchmark_checked", "speedup_pct", "p99_baseline_ns",
        "p99_candidate_ns", "security_invariants_preserved", "reason",
    )
    return {name: getattr(validation, name, None) for name in fields}


def _attempt_summary(attempt: Any) -> dict[str, Any]:
    policy = getattr(attempt, "policy", None)
    return {
        "action": getattr(attempt, "action", ""),
        "policy": policy.to_dict() if hasattr(policy, "to_dict") else None,
        "executed": bool(getattr(attempt, "executed", False)),
        "accepted": bool(getattr(attempt, "accepted", False)),
        "stage": getattr(attempt, "stage", ""),
        "reason": getattr(attempt, "reason", ""),
        "validation": _validation_summary(getattr(attempt, "validation", None)),
    }


def write_provenance_manifest(
    manifest_path: str | Path,
    *,
    source_path: str,
    ir_path: str,
    binary_path: str = "",
    ir_origin: str = "unknown",
    compiler: dict[str, Any] | None = None,
    pipeline_success: bool = False,
    security_findings: list[Any] | None = None,
    optimization_attempts: list[Any] | None = None,
) -> Path:
    """Write a JSON build receipt and return its path."""
    findings = []
    for finding in security_findings or []:
        findings.append(finding.to_dict() if hasattr(finding, "to_dict") else finding)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "Record build inputs, outputs, and compiler decisions for integrity checking.",
        "limitations": [
            "This manifest is not digitally signed and does not authenticate its creator.",
            "Hash matches do not prove the program is secure or behaviorally correct.",
        ],
        "pipeline_success": bool(pipeline_success),
        "ir_origin": ir_origin,
        "compiler": compiler or {},
        "artifacts": [
            item for item in (
                _artifact_record(source_path, "source"),
                _artifact_record(ir_path, "final_llvm_ir"),
                _artifact_record(binary_path, "binary"),
            ) if item is not None
        ],
        "security_findings": findings,
        "optimization_attempts": [
            _attempt_summary(attempt) for attempt in optimization_attempts or []
        ],
    }

    destination = Path(manifest_path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(destination)
    return destination


def verify_provenance_manifest(manifest_path: str | Path) -> dict[str, Any]:
    """Recompute recorded artifact hashes and report matches or mismatches."""
    path = Path(manifest_path).expanduser().resolve()
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"valid_manifest": False, "manifest": str(path), "error": str(exc), "artifacts": []}

    if manifest.get("schema_version") != SCHEMA_VERSION or not isinstance(manifest.get("artifacts"), list):
        return {
            "valid_manifest": False,
            "manifest": str(path),
            "error": "Unsupported or malformed provenance manifest.",
            "artifacts": [],
        }

    checks = []
    for artifact in manifest["artifacts"]:
        if not isinstance(artifact, dict):
            checks.append({
                "role": "unknown",
                "path": "",
                "matches": False,
                "reason": "Malformed artifact record.",
            })
            continue
        artifact_path = Path(str(artifact.get("path", ""))).expanduser()
        if not artifact_path.is_absolute():
            artifact_path = (path.parent / artifact_path).resolve()
        expected = artifact.get("sha256")
        if not artifact.get("available") or not expected:
            checks.append({
                "role": artifact.get("role", "unknown"),
                "path": str(artifact_path),
                "matches": False,
                "reason": "Artifact was unavailable when the manifest was written.",
            })
            continue
        try:
            exists = artifact_path.is_file()
        except OSError:
            exists = False
        if not exists:
            checks.append({
                "role": artifact.get("role", "unknown"),
                "path": str(artifact_path),
                "matches": False,
                "reason": "Artifact file is missing.",
            })
            continue
        try:
            actual = sha256_file(artifact_path)
        except OSError as exc:
            checks.append({
                "role": artifact.get("role", "unknown"),
                "path": str(artifact_path),
                "matches": False,
                "reason": f"Could not read artifact: {exc}",
            })
            continue
        checks.append({
            "role": artifact.get("role", "unknown"),
            "path": str(artifact_path),
            "matches": actual == expected,
            "expected_sha256": expected,
            "actual_sha256": actual,
            "reason": "Hash matches." if actual == expected else "Hash mismatch; artifact changed.",
        })

    return {
        "valid_manifest": bool(checks) and all(item["matches"] for item in checks),
        "manifest": str(path),
        "created_at_utc": manifest.get("created_at_utc"),
        "ir_origin": manifest.get("ir_origin", "unknown"),
        "artifacts": checks,
    }
