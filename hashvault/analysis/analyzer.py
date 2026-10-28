"""
High-level entry point for HashVault's deep-analysis pipeline.

The analyzer combines a bounded multi-hypothesis search over CyberChef-style
operations with the existing hash identifier.  It can unwrap encodings, inspect
source/config/JSON, read archive text entries, and apply explicitly-keyed
transforms before identifying the most likely crackable hash.

Also persists an AnalysisLog record (if a DB session is supplied) for quality
tracking and confidence calibration.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from hashvault.analysis.magic import describe_text
from hashvault.analysis.operations import OPERATIONS_BY_CATEGORY
from hashvault.analysis.recipe import AnalysisTrace, unpack_layers
from hashvault.analysis.search import AnalysisListener, DiscoveryResult, SearchConfig, discover_layers
from hashvault.analysis.validators import terminal_confidence
from hashvault.core.identifier import IdentificationResult, SourceContext, identify
from hashvault.exceptions import NoCandidateError

logger = logging.getLogger("hashvault.analyzer")


def _empty_identification() -> IdentificationResult:
    return IdentificationResult(
        candidates=[],
        resolved=False,
        method="unmatched",
        chosen_pattern=None,
        confidence_score=None,
    )


def _identification_summary(identification: Any) -> Dict[str, Any]:
    chosen = getattr(identification, "chosen_pattern", None)
    candidates = getattr(identification, "candidates", []) or []
    confidence = getattr(identification, "confidence_score", None)
    return {
        "resolved": bool(getattr(identification, "resolved", False)),
        "method": str(getattr(identification, "method", "ambiguous")),
        "chosen_pattern": getattr(chosen, "name", None),
        "hashcat_mode": getattr(chosen, "hashcat_mode", None),
        "john_format": getattr(chosen, "john_format", None),
        "confidence_score": round(confidence, 3) if confidence is not None else None,
        "candidates": [
            {
                "pattern": getattr(candidate.pattern, "name", None),
                "confidence": round(candidate.confidence, 3),
                "hashcat_mode": getattr(candidate.pattern, "hashcat_mode", None),
                "john_format": getattr(candidate.pattern, "john_format", None),
            }
            for candidate in candidates[:12]
        ],
    }


@dataclass
class BranchAnalysis:
    """One discovered branch and its identification result."""

    trace: AnalysisTrace
    identification: Any
    rank: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finalized_input": self.trace.finalized_input,
            "chain": self.trace.describe(),
            "layers_applied": self.trace.layers_applied,
            "terminal": self.trace.terminal,
            "score": round(self.trace.score, 4),
            "kind": self.trace.kind,
            "label": self.trace.label,
            "rank": round(self.rank, 4),
            "identification": _identification_summary(self.identification),
        }


class AnalysisResult:
    """Result of running the full deep-analysis pipeline on one input."""

    def __init__(
        self,
        raw_input: str,
        discovery: DiscoveryResult,
        identification: Any,
        selected_trace: Optional[AnalysisTrace] = None,
        branches: Optional[Sequence[BranchAnalysis]] = None,
    ) -> None:
        self.raw_input = raw_input
        self.discovery = discovery
        self.trace = selected_trace or discovery.best
        self.identification = identification
        self.branches: List[BranchAnalysis] = list(branches or [])

    # --- convenience accessors ------------------------------------------ #
    @property
    def finalized_input(self) -> str:
        return self.trace.finalized_input

    @property
    def unwrap_chain(self) -> str:
        return self.trace.describe()

    @property
    def resolved(self) -> bool:
        return bool(getattr(self.identification, "resolved", False))

    @property
    def candidates(self) -> List[str]:
        return self.discovery.candidates

    def to_dict(self) -> Dict[str, Any]:
        base = {
            "raw_input": self.raw_input,
            "finalized_input": self.finalized_input,
            "unwrap_chain": self.unwrap_chain,
            "layers_applied": self.trace.layers_applied,
            "layers": [
                {
                    "operation": layer.operation,
                    "category": layer.category,
                    "depth": layer.depth,
                    "input": layer.input_text,
                    "output": layer.output_text,
                    "confidence": round(layer.confidence, 3),
                    "label": layer.label,
                    "metadata": layer.metadata,
                }
                for layer in self.trace.layers
            ],
            "terminal": self.trace.terminal,
            "kind": self.trace.kind,
            "trace_score": round(self.trace.score, 4),
            "profile": self.discovery.profile.to_dict(),
            "search": self.discovery.to_dict(include_traces=False)["search"],
            "nodes_expanded": self.discovery.nodes_expanded,
            "elapsed_seconds": round(self.discovery.elapsed_seconds, 4),
            "truncated": self.discovery.truncated,
            "warnings": list(self.discovery.warnings),
            "branches": [branch.to_dict() for branch in self.branches],
        }
        base.update(_identification_summary(self.identification))
        return base

    def verbose(self) -> str:
        """Full human-readable report."""
        chosen = getattr(self.identification, "chosen_pattern", None)
        candidates = getattr(self.identification, "candidates", []) or []
        method = getattr(self.identification, "method", "ambiguous")
        conf = getattr(self.identification, "confidence_score", None)

        lines = [
            f"Raw input   : {self.raw_input[:120]}",
            f"Input kind  : {self.discovery.profile.kind} "
            f"({self.discovery.profile.length} chars, entropy {self.discovery.profile.entropy:.2f})",
            f"Finalized   : {self.finalized_input[:120]}",
            f"Unwrap chain: {self.unwrap_chain or '(none — already bare)'}",
            f"Search      : {self.discovery.nodes_expanded} nodes, "
            f"{self.discovery.elapsed_seconds:.3f}s, beam={self.discovery.config.beam_width}",
        ]
        if self.discovery.truncated:
            lines.append("Search note  : budget reached; results may be incomplete.")
        if self.discovery.warnings:
            for warning in self.discovery.warnings:
                lines.append(f"Warning     : {warning}")
        lines.extend(["", self.trace.describe_verbose(), ""])

        if chosen:
            mode = getattr(chosen, "hashcat_mode", None)
            jfmt = getattr(chosen, "john_format", None)
            lines.append(f"Identified  : {chosen.name}  [{method}]")
            if conf is not None:
                lines.append(f"Confidence  : {conf:.0%}")
            if mode is not None:
                lines.append(f"hashcat -m  : {mode}")
            if jfmt:
                lines.append(f"john --format: {jfmt}")
        else:
            lines.append(f"Identified  : ⚠ ambiguous ({len(candidates)} candidates)")
            if candidates:
                lines.append("Top candidates:")
                for candidate in candidates[:8]:
                    pattern = candidate.pattern
                    lines.append(
                        f"  {candidate.confidence:5.0%}  {getattr(pattern, 'name', '?')}"
                        f" | hashcat -m {getattr(pattern, 'hashcat_mode', None)}"
                        f" | john --format={getattr(pattern, 'john_format', None) or 'N/A'}"
                    )

        if len(self.branches) > 1:
            lines.append("")
            lines.append("Alternative branches:")
            for branch in self.branches[1:8]:
                summary = _identification_summary(branch.identification)
                lines.append(
                    f"  [{branch.trace.kind}] {branch.trace.finalized_input[:72]}"
                    f"  ({branch.trace.describe()})"
                    f"  -> {summary['chosen_pattern'] or 'ambiguous'}"
                )
        return "\n".join(lines)


def _branch_rank(trace: AnalysisTrace, identification: Any) -> float:
    confidence = getattr(identification, "confidence_score", None)
    chosen = getattr(identification, "chosen_pattern", None)
    if confidence is None and chosen is not None:
        confidence = 0.75
    if confidence is None:
        candidates = getattr(identification, "candidates", []) or []
        confidence = candidates[0].confidence if candidates else 0.0
    rank = float(confidence or 0.0)
    if getattr(identification, "resolved", False):
        rank += 2.0
    if trace.terminal:
        rank += 1.0 + terminal_confidence(trace.finalized_input) * 0.25
    rank += max(0.0, 0.15 - 0.01 * trace.layers_applied)
    return rank


def _identify_branches(
    discovery: DiscoveryResult,
    db_session: Any,
    config: Any,
    context: Optional[SourceContext],
) -> Tuple[AnalysisTrace, Any, List[BranchAnalysis]]:
    branches: List[BranchAnalysis] = []
    seen: set[str] = set()
    for trace in discovery.traces:
        target = trace.finalized_input or discovery.raw_input
        if target in seen:
            continue
        seen.add(target)
        try:
            identification = identify(target, db_session, config, context)
        except NoCandidateError:
            identification = _empty_identification()
        branches.append(
            BranchAnalysis(
                trace=trace,
                identification=identification,
                rank=_branch_rank(trace, identification),
            )
        )
    if not branches:
        trace = discovery.best
        branches = [
            BranchAnalysis(
                trace=trace,
                identification=_empty_identification(),
                rank=0.0,
            )
        ]
    branches.sort(key=lambda branch: branch.rank, reverse=True)
    primary = branches[0]
    return primary.trace, primary.identification, branches


def _persist_analysis_log(
    db_session: Any,
    result: "AnalysisResult",
    source_context: Optional[SourceContext] = None,
) -> None:
    """
    Write an AnalysisLog row to the database.
    Silently skipped if the table does not exist yet or any error occurs.
    """
    try:
        from hashvault.models.orm import AnalysisLog

        idn = result.identification
        chosen = getattr(idn, "chosen_pattern", None)
        chosen_id = getattr(chosen, "id", None)
        candidates = getattr(idn, "candidates", []) or []

        layers_data = [
            {
                "operation": layer.operation,
                "category": layer.category,
                "depth": layer.depth,
                "input": layer.input_text[:200],
                "output": layer.output_text[:200],
                "confidence": round(layer.confidence, 4),
                "label": layer.label,
            }
            for layer in result.trace.layers
        ]

        candidates_data = [
            {
                "pattern_name": getattr(candidate.pattern, "name", "?"),
                "confidence": round(candidate.confidence, 4),
                "hashcat_mode": getattr(candidate.pattern, "hashcat_mode", None),
            }
            for candidate in candidates[:10]
        ]
        branch_data = [
            {
                "chain": branch.trace.describe(),
                "finalized_input": branch.trace.finalized_input[:500],
                "terminal": branch.trace.terminal,
                "choices": [
                    getattr(candidate.pattern, "name", "?")
                    for candidate in (getattr(branch.identification, "candidates", []) or [])[:5]
                ],
            }
            for branch in result.branches[:10]
        ]
        if branch_data:
            candidates_data.append({"branches": branch_data})

        ctx_str = None
        if source_context is not None:
            try:
                ctx_str = source_context.model_dump_json()
            except Exception:
                ctx_str = str(source_context)

        log_entry = AnalysisLog(
            raw_input=result.raw_input[:500],
            finalized_input=result.finalized_input[:500],
            unwrap_chain=result.unwrap_chain[:200],
            layers_applied=result.trace.layers_applied,
            layers_json=json.dumps(layers_data),
            resolved=result.resolved,
            resolution_method=str(getattr(idn, "method", "ambiguous")),
            chosen_pattern_id=chosen_id,
            confidence_score=getattr(idn, "confidence_score", None),
            candidates_json=json.dumps(candidates_data),
            source_context=ctx_str,
        )
        db_session.add(log_entry)
        db_session.commit()

    except Exception as exc:
        logger.debug(f"AnalysisLog persist skipped: {exc}")


def analyze_input(
    raw_input: str,
    db_session: Any,
    config: Any,
    context: Optional[SourceContext] = None,
    max_layers: int = 12,
    *,
    persist_log: bool = True,
    allow_extractors: bool = False,
    beam_width: int = 8,
    max_nodes: int = 1500,
    keys: Optional[Mapping[str, str]] = None,
    listener: Optional[AnalysisListener] = None,
    max_seconds: float = 8.0,
) -> AnalysisResult:
    """
    Run the full pipeline on a single input:

      1. Explores encoding/envelope/code/archive layers (CyberChef-style).
      2. Identifies every viable terminal branch with the pattern engine.
      3. Selects the strongest resolved/terminal branch.
      4. Optionally persists an AnalysisLog record to the database.

    The search is bounded by ``max_layers``, ``beam_width``, ``max_nodes`` and
    ``max_seconds``.  It is safe for arbitrary text and never executes input.
    """
    discovery = discover_layers(
        raw_input,
        config=SearchConfig(
            max_depth=max_layers,
            beam_width=beam_width,
            max_nodes=max_nodes,
            allow_extractors=allow_extractors,
            max_seconds=max_seconds,
        ),
        keys=keys,
        listener=listener,
    )
    trace, identification, branches = _identify_branches(
        discovery, db_session, config, context
    )
    result = AnalysisResult(
        raw_input=raw_input,
        discovery=discovery,
        identification=identification,
        selected_trace=trace,
        branches=branches,
    )

    if persist_log and db_session is not None:
        _persist_analysis_log(db_session, result, context)

    return result


@dataclass
class AnalysisHandoff:
    """Lightweight no-DB result used by the cracking orchestrator."""

    raw_input: str
    trace: AnalysisTrace
    discovery: DiscoveryResult
    primary: str
    reason: str
    warnings: List[str] = field(default_factory=list)
    alternatives: List[AnalysisTrace] = field(default_factory=list)

    @property
    def unwrapped(self) -> bool:
        return self.trace.layers_applied > 0 and self.primary != self.raw_input

    @property
    def hypotheses(self) -> List[AnalysisTrace]:
        """Selected trace first, then unique terminal alternatives."""
        seen: set[str] = set()
        ordered: List[AnalysisTrace] = []
        for trace in [self.trace, *self.alternatives]:
            if trace.finalized_input in seen:
                continue
            seen.add(trace.finalized_input)
            ordered.append(trace)
        return ordered

    def to_trace_dict(self) -> Dict[str, Any]:
        data = self.trace.to_dict()
        data.update(
            {
                "selected": self.primary,
                "reason": self.reason,
                "profile": self.discovery.profile.to_dict(),
                "nodes_expanded": self.discovery.nodes_expanded,
                "elapsed_seconds": round(self.discovery.elapsed_seconds, 4),
                "warnings": list(self.warnings),
                "branches": [
                    {
                        "chain": trace.describe(),
                        "finalized_input": trace.finalized_input,
                        "layers_applied": trace.layers_applied,
                        "terminal": trace.terminal,
                        "score": round(trace.score, 4),
                        "kind": trace.kind,
                        "label": trace.label,
                        "selected": trace.finalized_input == self.primary,
                    }
                    for trace in self.hypotheses[:8]
                ],
            }
        )
        return data


def prepare_input(
    raw_input: str,
    *,
    max_layers: int = 12,
    beam_width: int = 8,
    max_nodes: int = 1500,
    allow_extractors: bool = False,
    keys: Optional[Mapping[str, str]] = None,
    listener: Optional[AnalysisListener] = None,
    max_seconds: float = 8.0,
) -> AnalysisHandoff:
    """Unwrap/select an input without touching the database.

    The orchestrator uses this before cache lookup and identification so batch
    inputs receive the same layered treatment as single-input ``analyze``.
    """
    discovery = discover_layers(
        raw_input,
        config=SearchConfig(
            max_depth=max_layers,
            beam_width=beam_width,
            max_nodes=max_nodes,
            allow_extractors=allow_extractors,
            max_seconds=max_seconds,
        ),
        keys=keys,
        listener=listener,
    )
    trace = discovery.best
    primary = trace.finalized_input or raw_input

    alternatives: List[AnalysisTrace] = []
    seen = {primary}
    for candidate in discovery.terminals:
        text = candidate.finalized_input or raw_input
        if text in seen:
            continue
        seen.add(text)
        alternatives.append(candidate)
        if len(alternatives) >= 7:
            break

    if trace.terminal:
        reason = "terminal-hash"
    elif trace.layers_applied:
        reason = "best-decoded-candidate"
    else:
        reason = "no-unwrap-needed"
    return AnalysisHandoff(
        raw_input=raw_input,
        trace=trace,
        discovery=discovery,
        primary=primary,
        reason=reason,
        warnings=list(discovery.warnings),
        alternatives=alternatives,
    )


def quick_detect(text: str) -> str:
    """
    Lightweight one-liner: describe what encoding Magic detects in *text*.
    Does NOT require a DB session.  Used by CLI for instant feedback.
    """
    return describe_text(text)


def list_operations(category: Optional[str] = None) -> Dict[str, Any]:
    """
    Return a structured dict of all registered operations, optionally
    filtered by category.  Used by `hashvault analyze --list-ops`.
    """
    result: Dict[str, Any] = {}
    categories = (
        {category: OPERATIONS_BY_CATEGORY[category]}
        if category and category in OPERATIONS_BY_CATEGORY
        else OPERATIONS_BY_CATEGORY
    )
    for cat, ops in categories.items():
        result[cat] = [
            {
                "name": op.name,
                "description": op.description,
                "tier": op.tier,
                "kind": op.kind,
                "auto": op.auto,
                "requires_keys": list(op.requires_keys),
            }
            for op in ops
        ]
    return result


def list_operation_contracts(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Machine-readable operation contracts for UI/coverage tooling."""
    operations = []
    for cat, ops in OPERATIONS_BY_CATEGORY.items():
        if category and cat != category:
            continue
        operations.extend(op.contract() for op in ops)
    return operations


__all__ = [
    "AnalysisHandoff",
    "AnalysisResult",
    "BranchAnalysis",
    "analyze_input",
    "list_operation_contracts",
    "list_operations",
    "prepare_input",
    "quick_detect",
    "unpack_layers",
]
