"""Contextual success tracking for tool and branch selection."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Optional

from sqlalchemy.orm import Session

from hashvault.models.orm import StrategyStat


def _tool_name(tool: Any) -> str:
    return str(getattr(tool, "value", tool))


def strategy_feature(
    pattern_name: Optional[str],
    tool: Any,
    attack_mode: str = "dictionary",
) -> str:
    return f"{pattern_name or 'unknown'}|{_tool_name(tool)}|{attack_mode}"


@dataclass
class StrategyRow:
    feature_key: str
    pattern_name: str
    tool: str
    attack_mode: str
    attempts: int
    successes: int
    success_rate: float
    average_seconds: float
    score: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def record_strategy_outcome(
    session: Session,
    *,
    pattern_name: Optional[str],
    tool: Any,
    attack_mode: str,
    success: bool,
    elapsed_seconds: float,
) -> StrategyStat:
    key = strategy_feature(pattern_name, tool, attack_mode)
    stat = session.query(StrategyStat).filter_by(feature_key=key).first()
    if stat is None:
        stat = StrategyStat(
            feature_key=key,
            pattern_name=pattern_name or "unknown",
            tool=_tool_name(tool),
            attack_mode=attack_mode,
            attempts=0,
            successes=0,
            total_seconds=0.0,
        )
        session.add(stat)
    stat.attempts += 1
    stat.successes += 1 if success else 0
    stat.total_seconds += max(0.0, float(elapsed_seconds))
    session.flush()
    return stat


def _score(stat: Optional[StrategyStat], total_attempts: int) -> float:
    if stat is None or stat.attempts <= 0:
        return 0.5 + math.sqrt(2.0 * math.log(total_attempts + 2.0))
    exploitation = stat.successes / stat.attempts
    exploration = math.sqrt(2.0 * math.log(total_attempts + 2.0) / stat.attempts)
    speed = 1.0 / (1.0 + stat.total_seconds / stat.attempts)
    return exploitation + exploration + 0.05 * speed


def rank_tools(
    session: Session,
    *,
    pattern_name: Optional[str],
    tools: Iterable[Any],
    attack_mode: str = "dictionary",
) -> list[Any]:
    ordered = list(tools)
    if len(ordered) <= 1:
        return ordered
    stats = {
        row.feature_key: row
        for row in session.query(StrategyStat).filter_by(
            pattern_name=pattern_name or "unknown",
            attack_mode=attack_mode,
        ).all()
    }
    total_attempts = sum(row.attempts for row in stats.values())
    scored = [
        (
            _score(stats.get(strategy_feature(pattern_name, tool, attack_mode)), total_attempts),
            index,
            tool,
        )
        for index, tool in enumerate(ordered)
    ]
    scored.sort(key=lambda item: (item[0], -item[1]), reverse=True)
    return [item[2] for item in scored]


def list_strategy_stats(session: Session) -> list[StrategyRow]:
    rows = session.query(StrategyStat).order_by(StrategyStat.attempts.desc()).all()
    total = sum(row.attempts for row in rows)
    result: list[StrategyRow] = []
    for row in rows:
        average = row.total_seconds / row.attempts if row.attempts else 0.0
        result.append(
            StrategyRow(
                feature_key=row.feature_key,
                pattern_name=row.pattern_name,
                tool=row.tool,
                attack_mode=row.attack_mode,
                attempts=row.attempts,
                successes=row.successes,
                success_rate=round(row.success_rate, 4),
                average_seconds=round(average, 4),
                score=round(_score(row, total), 4),
            )
        )
    return result


def reset_strategy_stats(session: Session) -> int:
    count = session.query(StrategyStat).delete()
    session.flush()
    return int(count)
