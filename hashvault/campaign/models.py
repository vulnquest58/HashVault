"""Typed models for corpus-level recovery campaigns."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class Evidence:
    kind: str
    value: str
    origin: str = ""
    weight: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "origin": self.origin,
            "weight": self.weight,
        }


@dataclass
class Target:
    target_id: str
    raw_hash: str
    normalized_hash: str
    username: str | None = None
    source: str = ""
    patterns: list[Any] = field(default_factory=list)
    status: str = "unresolved"
    plaintext: str | None = None
    pattern_name: str | None = None
    method: str | None = None
    confidence: float = 0.0
    evidence: list[Evidence] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def resolved(self) -> bool:
        return self.status == "resolved" and self.plaintext is not None

    def pattern_names(self) -> list[str]:
        names: list[str] = []
        for pattern in self.patterns:
            name = getattr(pattern, "name", None)
            if name and name not in names:
                names.append(str(name))
        return names

    def is_slow(self) -> bool:
        return any(
            bool(getattr(pattern, "is_slow", False)) for pattern in self.patterns
        )

    def to_dict(self, *, include_plaintext: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "target_id": self.target_id,
            "username": self.username,
            "hash": self.normalized_hash,
            "source": self.source,
            "status": self.status,
            "pattern": self.pattern_name,
            "patterns": self.pattern_names(),
            "confidence": round(self.confidence, 4),
            "method": self.method,
            "evidence": [item.to_dict() for item in self.evidence],
            "metadata": dict(self.metadata),
        }
        if include_plaintext:
            data["plaintext"] = self.plaintext
        return data


@dataclass
class Recovery:
    target_id: str
    plaintext: str
    pattern_name: str
    method: str
    evidence: list[str] = field(default_factory=list)
    verified: bool = True
    elapsed_seconds: float = 0.0

    def to_dict(self, *, include_plaintext: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "target_id": self.target_id,
            "pattern": self.pattern_name,
            "method": self.method,
            "evidence": list(self.evidence),
            "verified": self.verified,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
        }
        if include_plaintext:
            data["plaintext"] = self.plaintext
        return data


@dataclass
class Stage:
    name: str
    kind: str
    target_ids: list[str]
    candidates: int
    expected_recoveries: float
    cost_seconds: float
    priority: float
    tested: int = 0
    recoveries: int = 0
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "targets": len(self.target_ids),
            "candidates": self.candidates,
            "expected_recoveries": round(self.expected_recoveries, 3),
            "cost_seconds": round(self.cost_seconds, 3),
            "priority": round(self.priority, 3),
            "tested": self.tested,
            "recoveries": self.recoveries,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


@dataclass
class CampaignPlan:
    stages: list[Stage]
    total_targets: int
    supported_targets: int
    slow_targets: int
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_targets": self.total_targets,
            "supported_targets": self.supported_targets,
            "slow_targets": self.slow_targets,
            "stages": [stage.to_dict() for stage in self.stages],
            "notes": list(self.notes),
        }


@dataclass
class CampaignReport:
    campaign_id: str
    created_at: datetime
    targets: list[Target]
    recoveries: list[Recovery]
    stages: list[Stage]
    elapsed_seconds: float
    candidates_generated: int
    checks: int
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        resolved = sum(1 for target in self.targets if target.resolved)
        by_method: dict[str, int] = {}
        for recovery in self.recoveries:
            by_method[recovery.method] = by_method.get(recovery.method, 0) + 1
        return {
            "campaign_id": self.campaign_id,
            "created_at": self.created_at.isoformat(),
            "targets": len(self.targets),
            "resolved": resolved,
            "unresolved": len(self.targets) - resolved,
            "recoveries": len(self.recoveries),
            "by_method": by_method,
            "candidates_generated": self.candidates_generated,
            "checks": self.checks,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "stages": [stage.to_dict() for stage in self.stages],
            "notes": list(self.notes),
        }

    def to_dict(self, *, include_plaintext: bool = True) -> dict[str, Any]:
        return {
            "summary": self.summary(),
            "targets": [
                target.to_dict(include_plaintext=include_plaintext)
                for target in self.targets
            ],
            "recoveries": [
                recovery.to_dict(include_plaintext=include_plaintext)
                for recovery in self.recoveries
            ],
        }
