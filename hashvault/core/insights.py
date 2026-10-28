"""Local audit analytics for analysis, cracking, and strategy feedback."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from hashvault.models.orm import (
    AnalysisLog,
    CrackAttempt,
    CrackedHash,
    Pattern,
    StrategyStat,
)


@dataclass
class InsightsReport:
    days: Optional[int]
    analyses: dict[str, Any] = field(default_factory=dict)
    cracking: dict[str, Any] = field(default_factory=dict)
    cracked: dict[str, Any] = field(default_factory=dict)
    strategies: dict[str, Any] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "days": self.days,
            "analyses": self.analyses,
            "cracking": self.cracking,
            "cracked": self.cracked,
            "strategies": self.strategies,
            "recommendations": self.recommendations,
        }


def _cutoff(days: Optional[int]) -> Optional[datetime]:
    if not days or days <= 0:
        return None
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)


def _analysis_metrics(
    session: Session,
    cutoff: Optional[datetime],
) -> dict[str, Any]:
    query = session.query(AnalysisLog)
    if cutoff is not None:
        query = query.filter(AnalysisLog.timestamp >= cutoff)

    total = query.count()
    resolved = query.filter(AnalysisLog.resolved.is_(True)).count()
    confidence_query = session.query(func.avg(AnalysisLog.confidence_score))
    if cutoff is not None:
        confidence_query = confidence_query.filter(AnalysisLog.timestamp >= cutoff)
    average_confidence = confidence_query.scalar()

    top_operations: Counter[str] = Counter()
    recent = query.filter(AnalysisLog.layers_applied > 0).order_by(
        AnalysisLog.timestamp.desc()
    ).limit(2000).all()
    for entry in recent:
        if not entry.layers_json:
            continue
        try:
            layers = json.loads(entry.layers_json)
        except (TypeError, ValueError):
            continue
        if not isinstance(layers, list):
            continue
        for layer in layers:
            if isinstance(layer, dict) and layer.get("operation"):
                top_operations[str(layer["operation"])] += 1

    pattern_query = (
        session.query(Pattern.name, func.count(AnalysisLog.id))
        .join(AnalysisLog, AnalysisLog.chosen_pattern_id == Pattern.id)
        .filter(AnalysisLog.chosen_pattern_id.isnot(None))
    )
    if cutoff is not None:
        pattern_query = pattern_query.filter(AnalysisLog.timestamp >= cutoff)
    top_patterns = [
        {"pattern": name, "count": count}
        for name, count in pattern_query.group_by(Pattern.name)
        .order_by(func.count(AnalysisLog.id).desc())
        .limit(5)
        .all()
    ]

    return {
        "total": total,
        "resolved": resolved,
        "ambiguous": total - resolved,
        "resolution_rate": round(resolved / total, 4) if total else 0.0,
        "average_confidence": (
            round(float(average_confidence), 4)
            if average_confidence is not None
            else None
        ),
        "top_operations": [
            {"operation": operation, "count": count}
            for operation, count in top_operations.most_common(5)
        ],
        "top_patterns": top_patterns,
    }


def _cracking_metrics(
    session: Session,
    cutoff: Optional[datetime],
) -> dict[str, Any]:
    query = session.query(CrackAttempt)
    if cutoff is not None:
        query = query.filter(CrackAttempt.created_at >= cutoff)

    total = query.count()
    successes = query.filter(CrackAttempt.success.is_(True)).count()
    cached = query.filter(CrackAttempt.cached.is_(True)).count()
    errors = query.filter(CrackAttempt.error_message.isnot(None)).count()
    elapsed = session.query(func.sum(CrackAttempt.elapsed_seconds))
    if cutoff is not None:
        elapsed = elapsed.filter(CrackAttempt.created_at >= cutoff)
    total_seconds = float(elapsed.scalar() or 0.0)

    tool_rows = (
        session.query(
            CrackAttempt.tool_used,
            func.count(CrackAttempt.id),
            func.sum(case((CrackAttempt.success.is_(True), 1), else_=0)),
        )
        .filter(CrackAttempt.tool_used.isnot(None))
    )
    if cutoff is not None:
        tool_rows = tool_rows.filter(CrackAttempt.created_at >= cutoff)
    tools = [
        {
            "tool": tool,
            "attempts": attempts,
            "successes": int(successes or 0),
        }
        for tool, attempts, successes in tool_rows.group_by(CrackAttempt.tool_used)
        .order_by(func.count(CrackAttempt.id).desc())
        .limit(5)
        .all()
    ]

    pattern_rows = (
        session.query(
            CrackAttempt.pattern_name,
            func.count(CrackAttempt.id),
            func.sum(case((CrackAttempt.success.is_(True), 1), else_=0)),
        )
        .filter(CrackAttempt.pattern_name.isnot(None))
    )
    if cutoff is not None:
        pattern_rows = pattern_rows.filter(CrackAttempt.created_at >= cutoff)
    patterns = [
        {
            "pattern": pattern,
            "attempts": attempts,
            "successes": int(successes or 0),
        }
        for pattern, attempts, successes in pattern_rows.group_by(
            CrackAttempt.pattern_name
        )
        .order_by(func.count(CrackAttempt.id).desc())
        .limit(5)
        .all()
    ]

    return {
        "attempts": total,
        "successes": successes,
        "failures": total - successes,
        "cached": cached,
        "errors": errors,
        "success_rate": round(successes / total, 4) if total else 0.0,
        "total_seconds": round(total_seconds, 3),
        "average_seconds": round(total_seconds / total, 3) if total else 0.0,
        "tools": tools,
        "patterns": patterns,
    }


def _strategy_metrics(
    session: Session,
    cutoff: Optional[datetime],
) -> dict[str, Any]:
    query = session.query(StrategyStat)
    if cutoff is not None:
        query = query.filter(StrategyStat.updated_at >= cutoff)
    rows = query.all()
    ordered = sorted(
        rows,
        key=lambda row: (row.success_rate, row.attempts),
        reverse=True,
    )
    return {
        "rows": len(rows),
        "attempts": sum(row.attempts for row in rows),
        "successes": sum(row.successes for row in rows),
        "top": [
            {
                "pattern": row.pattern_name,
                "tool": row.tool,
                "attack_mode": row.attack_mode,
                "attempts": row.attempts,
                "successes": row.successes,
                "success_rate": round(row.success_rate, 4),
                "average_seconds": round(
                    row.total_seconds / row.attempts if row.attempts else 0.0,
                    3,
                ),
            }
            for row in ordered[:5]
        ],
    }


def _cracked_metrics(
    session: Session,
    cutoff: Optional[datetime],
) -> dict[str, Any]:
    query = session.query(CrackedHash)
    if cutoff is not None:
        query = query.filter(CrackedHash.cracked_at >= cutoff)
    total = query.count()
    unique_hashes = query.with_entities(
        func.count(func.distinct(CrackedHash.normalized_hash))
    ).scalar()

    tool_rows = session.query(CrackedHash.tool_used, func.count(CrackedHash.id))
    if cutoff is not None:
        tool_rows = tool_rows.filter(CrackedHash.cracked_at >= cutoff)
    tools = [
        {"tool": tool, "count": count}
        for tool, count in tool_rows.group_by(CrackedHash.tool_used)
        .order_by(func.count(CrackedHash.id).desc())
        .limit(5)
        .all()
    ]
    return {
        "records": total,
        "unique_hashes": int(unique_hashes or 0),
        "tools": tools,
    }


def _recommendations(report: InsightsReport) -> list[str]:
    suggestions: list[str] = []
    analyses = report.analyses
    cracking = report.cracking
    strategies = report.strategies

    if analyses["total"] == 0:
        suggestions.append(
            "No analysis history yet; run `hashvault analyze` or "
            "`hashvault selftest`."
        )
    elif analyses["resolution_rate"] < 0.5:
        suggestions.append(
            "Most analyses remain ambiguous; add source hints or explicit "
            "patterns before cracking."
        )

    if cracking["attempts"] == 0:
        suggestions.append(
            "No crack attempts are recorded; run `hashvault crack` on "
            "authorized cache misses to build feedback."
        )
    else:
        if cracking["success_rate"] < 0.2:
            suggestions.append(
                "Attempt success is low; review wordlists, rules, hints, "
                "and per-hash budgets."
            )
        if cracking["cached"] / cracking["attempts"] > 0.5:
            suggestions.append(
                "Most attempts were cache hits; test unseen hashes to "
                "measure real engine performance."
            )
        builtin_attempts = next(
            (
                item["attempts"]
                for item in cracking["tools"]
                if item["tool"] == "builtin"
            ),
            0,
        )
        if builtin_attempts / cracking["attempts"] > 0.8:
            suggestions.append(
                "The built-in engine handles most attempts; run "
                "`hashvault doctor --probe` to validate faster backends."
            )

    if strategies["rows"] == 0:
        suggestions.append(
            "Adaptive feedback is empty; completed crack attempts will "
            "populate tool ordering statistics."
        )
    return suggestions


def run_insights(
    session: Session,
    *,
    days: Optional[int] = None,
) -> InsightsReport:
    """Aggregate local audit activity without exposing stored plaintexts."""
    cutoff = _cutoff(days)
    report = InsightsReport(
        days=days if days and days > 0 else None,
        analyses=_analysis_metrics(session, cutoff),
        cracking=_cracking_metrics(session, cutoff),
        cracked=_cracked_metrics(session, cutoff),
        strategies=_strategy_metrics(session, cutoff),
    )
    report.recommendations = _recommendations(report)
    return report
