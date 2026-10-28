"""
Bounded multi-hypothesis analysis search.

The original recipe engine followed one greedy path.  This module implements a
beam search over bytes-aware analysis states so wrapped hashes, split code
literals, archives, and keyed transforms can be explored without wandering
through an exponential operation graph.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence

from hashvault.analysis.keys import require_keys
from hashvault.analysis.magic import OperationCandidate, detect
from hashvault.analysis.operations import Operation, OperationResult, _hash_likeness
from hashvault.analysis.recipe import AnalysisTrace, Layer
from hashvault.analysis.validators import (
    InputProfile,
    is_terminal_hash,
    looks_like_binary,
    looks_like_code,
    looks_like_config,
    looks_like_json,
    looks_like_text,
    profile_input,
    terminal_confidence,
)


class AnalysisListener(Protocol):
    """Observer used by the Rich live view and test instrumentation."""

    def on_start(self, raw_input: str, profile: InputProfile) -> None: ...

    def on_expand(
        self,
        depth: int,
        node: "AnalysisNode",
        operation: Operation,
        score: float,
    ) -> None: ...

    def on_result(
        self,
        depth: int,
        node: "AnalysisNode",
        operation: Operation,
        result: OperationResult,
        terminal: bool,
    ) -> None: ...

    def on_terminal(self, trace: AnalysisTrace) -> None: ...

    def on_complete(self, result: "DiscoveryResult") -> None: ...


class NullListener:
    """No-op listener (default for API/test use)."""

    def on_start(self, raw_input: str, profile: InputProfile) -> None:
        return None

    def on_expand(
        self,
        depth: int,
        node: "AnalysisNode",
        operation: Operation,
        score: float,
    ) -> None:
        return None

    def on_result(
        self,
        depth: int,
        node: "AnalysisNode",
        operation: Operation,
        result: OperationResult,
        terminal: bool,
    ) -> None:
        return None

    def on_terminal(self, trace: AnalysisTrace) -> None:
        return None

    def on_complete(self, result: "DiscoveryResult") -> None:
        return None


@dataclass(frozen=True)
class SearchConfig:
    max_depth: int = 12
    beam_width: int = 8
    max_nodes: int = 1500
    min_score: float = 0.05
    terminal_limit: int = 24
    max_output_chars: int = 2_000_000
    max_seconds: float = 8.0
    allow_extractors: bool = False
    include_near_misses: bool = True


@dataclass
class AnalysisNode:
    """One state in the analysis beam."""

    text: str
    layers: tuple[Layer, ...] = ()
    seen: frozenset[str] = frozenset()
    score: float = 0.0
    kind: str = "text"
    label: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    terminal: bool = False

    @property
    def depth(self) -> int:
        return len(self.layers)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8", "replace")).hexdigest()

    @property
    def chain(self) -> str:
        return " -> ".join(layer.operation for layer in self.layers) or "(none)"


@dataclass
class DiscoveryResult:
    """Complete bounded-search result with all viable terminal branches."""

    raw_input: str
    profile: InputProfile
    traces: List[AnalysisTrace]
    best: AnalysisTrace
    nodes_expanded: int
    elapsed_seconds: float
    truncated: bool
    config: SearchConfig
    warnings: List[str] = field(default_factory=list)

    @property
    def terminals(self) -> List[AnalysisTrace]:
        return [trace for trace in self.traces if trace.terminal]

    @property
    def candidates(self) -> List[str]:
        seen: set[str] = set()
        values: List[str] = []
        for trace in self.terminals:
            if trace.finalized_input not in seen:
                seen.add(trace.finalized_input)
                values.append(trace.finalized_input)
        return values

    def to_dict(self, include_traces: bool = True) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "raw_input": self.raw_input,
            "profile": self.profile.to_dict(),
            "best": self.best.to_dict(),
            "terminal_count": len(self.terminals),
            "nodes_expanded": self.nodes_expanded,
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "search": {
                "max_depth": self.config.max_depth,
                "beam_width": self.config.beam_width,
                "max_nodes": self.config.max_nodes,
                "allow_extractors": self.config.allow_extractors,
            },
        }
        if include_traces:
            data["branches"] = [trace.to_dict() for trace in self.traces]
        return data


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _classify(text: str, terminal: bool) -> str:
    if terminal:
        return "hash"
    if looks_like_json(text):
        return "json"
    if looks_like_code(text):
        return "code"
    if looks_like_config(text):
        return "config"
    if looks_like_binary(text):
        return "binary"
    return "text"


def _trim_output(text: str) -> str:
    if looks_like_text(text):
        return text.strip()
    return text


def _output_score(
    parent: AnalysisNode,
    op_score: float,
    text: str,
    terminal: bool,
    label: str,
) -> float:
    score = parent.score - 0.012 * max(1, parent.depth)
    score += op_score * 0.7
    score += _hash_likeness(text) * 0.12
    if terminal:
        score += 3.0 + terminal_confidence(text)
    else:
        if looks_like_text(text):
            score += 0.08
        if looks_like_code(text) or looks_like_config(text):
            score += 0.18
        elif looks_like_binary(text):
            score -= 0.45
        if label:
            score += 0.02
    return score


def _node_from_result(
    parent: AnalysisNode,
    op: Operation,
    candidate: OperationCandidate,
    result: OperationResult,
) -> AnalysisNode:
    text = _trim_output(str(result.text))
    terminal = is_terminal_hash(text)
    layer = Layer(
        operation=op.name,
        input_text=parent.text,
        output_text=text,
        confidence=max(float(candidate.score), float(result.score or 0.0)),
        depth=parent.depth + 1,
        category=op.category,
        label=result.label,
        metadata=dict(result.metadata),
    )
    metadata = dict(parent.metadata)
    metadata.update(result.metadata)
    if result.label:
        metadata["label"] = result.label
    score = _output_score(parent, candidate.score, text, terminal, result.label)
    return AnalysisNode(
        text=text,
        layers=parent.layers + (layer,),
        seen=parent.seen | {_digest(text)},
        score=score,
        kind=_classify(text, terminal),
        label=result.label,
        metadata=metadata,
        warnings=parent.warnings,
        terminal=terminal,
    )


def _apply_operation(
    op: Operation,
    text: str,
    keys: Optional[Mapping[str, str]],
    max_output_chars: int,
) -> List[OperationResult]:
    try:
        results = op.apply_many(text, keys=keys)
    except TypeError:
        try:
            simple = op.apply(text)
        except Exception:
            return []
        results = [] if simple is None else [OperationResult(text=simple)]
    except Exception:
        return []

    outputs: List[OperationResult] = []
    seen: set[str] = set()
    for item in results:
        if item is None:
            continue
        value = str(item.text)
        if not value or value == text or value in seen:
            continue
        if len(value) > max_output_chars:
            continue
        if len(value.encode("utf-8", "ignore")) > op.max_output_bytes:
            continue
        seen.add(value)
        outputs.append(item)
        if len(outputs) >= 64:
            break
    return outputs


def _dedupe_nodes(nodes: Iterable[AnalysisNode]) -> List[AnalysisNode]:
    best: Dict[str, AnalysisNode] = {}
    for node in nodes:
        key = node.digest
        current = best.get(key)
        if current is None:
            best[key] = node
            continue
        if node.score > current.score:
            best[key] = node
        elif node.score == current.score and node.depth < current.depth:
            best[key] = node
    return list(best.values())


def _make_trace(raw_input: str, node: AnalysisNode) -> AnalysisTrace:
    warnings = list(node.warnings)
    return AnalysisTrace(
        raw_input=raw_input,
        finalized_input=node.text,
        layers=list(node.layers),
        terminal=node.terminal,
        score=node.score,
        kind=node.kind,
        label=node.label,
        metadata=dict(node.metadata),
        warnings=warnings,
    )


def _seed_trace(raw_input: str, node: AnalysisNode, profile: InputProfile) -> AnalysisTrace:
    return AnalysisTrace(
        raw_input=raw_input,
        finalized_input=node.text,
        layers=list(node.layers),
        terminal=node.terminal,
        score=node.score,
        kind=profile.kind,
        metadata=dict(node.metadata),
        warnings=list(profile.warnings),
    )


def discover_layers(
    text: str,
    *,
    config: Optional[SearchConfig] = None,
    keys: Optional[Mapping[str, str]] = None,
    listener: Optional[AnalysisListener] = None,
) -> DiscoveryResult:
    """Explore encoding/keyed/container layers with bounded beam search.

    The search is deterministic, side-effect free, and does not touch the
    database.  Terminal hash branches are ranked by structural confidence;
    non-terminal best paths are returned for diagnostics when no hash is found.
    """
    cfg = config or SearchConfig()
    observer: AnalysisListener = listener or NullListener()
    started = time.monotonic()
    raw = text or ""
    profile = profile_input(raw)
    observer.on_start(raw, profile)

    seed = AnalysisNode(
        text=raw,
        seen=frozenset({_digest(raw)}),
        score=0.0,
        kind=profile.kind,
        terminal=profile.terminal,
        warnings=tuple(profile.warnings),
    )

    warnings = list(profile.warnings)
    if profile.terminal:
        trace = _seed_trace(raw, seed, profile)
        observer.on_terminal(trace)
        result = DiscoveryResult(
            raw_input=raw,
            profile=profile,
            traces=[trace],
            best=trace,
            nodes_expanded=0,
            elapsed_seconds=time.monotonic() - started,
            truncated=False,
            config=cfg,
            warnings=warnings,
        )
        observer.on_complete(result)
        return result

    frontier: List[AnalysisNode] = [seed]
    terminal_nodes: List[AnalysisNode] = []
    all_best: List[AnalysisNode] = [seed]
    nodes_expanded = 0
    truncated = False

    for depth in range(1, cfg.max_depth + 1):
        next_nodes: List[AnalysisNode] = []

        for node in frontier:
            if time.monotonic() - started > cfg.max_seconds:
                truncated = True
                warnings.append(
                    f"Search time budget ({cfg.max_seconds:.1f}s) reached; "
                    "results may be incomplete."
                )
                break
            if nodes_expanded >= cfg.max_nodes:
                truncated = True
                warnings.append(
                    f"Search node budget ({cfg.max_nodes}) reached; "
                    "results may be incomplete."
                )
                break

            candidates = detect(node.text, min_score=cfg.min_score)
            for candidate in candidates:
                op = candidate.operation
                if op.name == "HashDetector":
                    continue
                if op.category == "Extractors" and not cfg.allow_extractors:
                    continue
                if op.requires_keys and not require_keys(keys, *op.requires_keys):
                    continue
                if not op.auto and not (op.requires_keys and keys):
                    continue

                observer.on_expand(depth, node, op, float(candidate.score))
                outputs = _apply_operation(op, node.text, keys, cfg.max_output_chars)
                nodes_expanded += 1
                for output in outputs:
                    if output.text in node.seen or _digest(output.text) in node.seen:
                        continue
                    child = _node_from_result(node, op, candidate, output)
                    if child.text == node.text:
                        continue
                    observer.on_result(depth, node, op, output, child.terminal)
                    if child.terminal:
                        terminal_nodes.append(child)
                        observer.on_terminal(_make_trace(raw, child))
                    else:
                        next_nodes.append(child)

        if terminal_nodes:
            # Keep exploring in parallel; a deeper branch may be the real hash
            # after an outer envelope (e.g. archive containing base64 wrapped
            # hash).  The beam remains bounded.
            pass

        next_nodes = _dedupe_nodes(next_nodes)
        next_nodes.sort(key=lambda item: item.score, reverse=True)
        all_best.extend(next_nodes[: cfg.beam_width])
        frontier = next_nodes[: cfg.beam_width]
        if not frontier:
            break

    # Terminal branches that converge on the same hash are equivalent for
    # cracking.  Prefer the shortest explanation, then the best score, rather
    # than letting a long ROT chain outrank a direct extractor.
    terminal_by_text: Dict[str, AnalysisNode] = {}
    for node in terminal_nodes:
        current = terminal_by_text.get(node.text)
        if current is None:
            terminal_by_text[node.text] = node
        elif node.depth < current.depth:
            terminal_by_text[node.text] = node
        elif node.depth == current.depth and node.score > current.score:
            terminal_by_text[node.text] = node
    terminals = list(terminal_by_text.values())
    terminals.sort(
        key=lambda item: (
            terminal_confidence(item.text),
            -item.depth,
            item.score,
        ),
        reverse=True,
    )
    terminal_traces = [_make_trace(raw, node) for node in terminals[: cfg.terminal_limit]]

    if terminal_traces:
        best = terminal_traces[0]
        traces = list(terminal_traces)
        if cfg.include_near_misses:
            for node in sorted(all_best, key=lambda item: item.score, reverse=True):
                if len(traces) >= len(terminal_traces) + 4:
                    break
                if node.terminal or not node.layers:
                    continue
                if any(trace.finalized_input == node.text for trace in traces):
                    continue
                traces.append(_make_trace(raw, node))
    else:
        viable = _dedupe_nodes(all_best)
        viable.sort(key=lambda item: item.score, reverse=True)
        traces = [_make_trace(raw, node) for node in viable[: cfg.terminal_limit]]
        if not traces:
            traces = [_seed_trace(raw, seed, profile)]
        best = traces[0]
        if len(profile.warnings) == 0:
            warnings.append("No terminal hash structure was found.")

    result = DiscoveryResult(
        raw_input=raw,
        profile=profile,
        traces=traces,
        best=best,
        nodes_expanded=nodes_expanded,
        elapsed_seconds=time.monotonic() - started,
        truncated=truncated,
        config=cfg,
        warnings=warnings,
    )
    observer.on_complete(result)
    return result


def discover_trace(
    text: str,
    *,
    max_depth: int = 12,
    beam_width: int = 8,
    allow_extractors: bool = False,
    keys: Optional[Mapping[str, str]] = None,
    listener: Optional[AnalysisListener] = None,
    max_nodes: int = 1500,
    max_seconds: float = 8.0,
) -> AnalysisTrace:
    """Convenience wrapper returning only the best trace."""
    config = SearchConfig(
        max_depth=max_depth,
        beam_width=beam_width,
        allow_extractors=allow_extractors,
        max_nodes=max_nodes,
        max_seconds=max_seconds,
    )
    return discover_layers(text, config=config, keys=keys, listener=listener).best
