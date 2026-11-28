"""Resumable campaign state.

A checkpoint is a local JSON snapshot of verified recoveries, stage counters,
and completed stages.  It can contain recovered plaintext, so it is written
with owner-only permissions where the platform supports them and should be
stored in a protected directory (the default ``checkpoints/`` is gitignored).

Resuming re-verifies every restored plaintext against the target's current
patterns.  A checkpoint is therefore a work-saving hint, not an authority.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

CHECKPOINT_SCHEMA_VERSION = 1


class CheckpointError(RuntimeError):
    """Raised when a checkpoint is malformed or incompatible."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def build_snapshot(
    engine: Any,
    *,
    completed_stages: set[str] | list[str],
    campaign_id: str,
    elapsed_seconds: float = 0.0,
) -> dict[str, Any]:
    """Serialize the current campaign state."""
    return {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "campaign_id": campaign_id,
        "updated_at": _utc_now(),
        "completed_stages": sorted(set(completed_stages)),
        "elapsed_seconds": round(elapsed_seconds, 3),
        "candidates_generated": engine.candidates_generated,
        "checks": engine.checks,
        "notes": list(engine.notes),
        "targets": [
            {
                "target_id": target.target_id,
                "status": target.status,
                "plaintext": target.plaintext,
                "pattern_name": target.pattern_name,
                "method": target.method,
                "confidence": target.confidence,
                "evidence": [item.to_dict() for item in target.evidence],
                "metadata": dict(target.metadata),
            }
            for target in engine.targets
        ],
        "recoveries": [
            recovery.to_dict(include_plaintext=True)
            for recovery in engine._recoveries
        ],
        "stages": [stage.to_dict() for stage in engine._last_plan_stages],
    }


def write_checkpoint(snapshot: dict[str, Any], path: str | Path) -> Path:
    """Atomically write a checkpoint with restrictive permissions."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(
        json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    try:
        temporary.chmod(0o600)
    except OSError:  # pragma: no cover - Windows ACLs
        pass
    temporary.replace(target)
    return target


def load_checkpoint(path: str | Path) -> dict[str, Any]:
    """Load and minimally validate a checkpoint."""
    target = Path(path)
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CheckpointError(f"cannot read checkpoint: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CheckpointError(f"checkpoint is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise CheckpointError("checkpoint must be a JSON object")
    if document.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        raise CheckpointError(
            "unsupported checkpoint schema version: "
            f"{document.get('schema_version')!r}"
        )
    if not isinstance(document.get("targets"), list):
        raise CheckpointError("checkpoint targets must be a list")
    return document


def restore_snapshot(engine: Any, snapshot: dict[str, Any]) -> set[str]:
    """Restore verified recoveries and counters into an engine.

    Every stored plaintext is re-verified against the engine's current pattern
    candidates.  A target whose pattern is no longer supported, or whose
    plaintext no longer verifies, stays unresolved and is reported in notes.
    """
    targets = {target.target_id: target for target in engine.targets}
    restored = 0
    rejected = 0
    for state in snapshot.get("targets", []):
        if not isinstance(state, dict) or state.get("status") != "resolved":
            continue
        target = targets.get(str(state.get("target_id", "")))
        plaintext = state.get("plaintext")
        if target is None or not isinstance(plaintext, str):
            rejected += 1
            continue
        if target.resolved:
            continue
        pattern_name = engine._verify(target, plaintext, include_slow=True)
        if pattern_name is None:
            rejected += 1
            continue
        engine._resolve(
            target,
            plaintext,
            pattern_name,
            str(state.get("method") or "checkpoint"),
            f"checkpoint:{state.get('target_id', '')}",
        )
        engine._known.append((plaintext, target.target_id))
        restored += 1

    if restored:
        engine.notes.append(f"restored {restored} verified recovery(ies) from checkpoint")
    if rejected:
        engine.notes.append(
            f"rejected {rejected} checkpoint recovery(ies) that no longer verify"
        )

    engine.candidates_generated = int(snapshot.get("candidates_generated", 0) or 0)
    engine.checks = int(snapshot.get("checks", 0) or 0)
    engine._elapsed_offset = float(snapshot.get("elapsed_seconds", 0.0) or 0.0)
    engine._checkpoint_stage_stats = {
        str(stage.get("name")): stage
        for stage in snapshot.get("stages", [])
        if isinstance(stage, dict) and stage.get("name")
    }
    completed = snapshot.get("completed_stages", [])
    return {str(name) for name in completed} if isinstance(completed, list) else set()
