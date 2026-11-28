"""Compile corpus evidence into staged recovery campaigns."""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from hashvault.campaign.models import (
    CampaignPlan,
    CampaignReport,
    Evidence,
    Recovery,
    Stage,
    Target,
    utc_now,
)
from hashvault.campaign.mutations import generate_candidates
from hashvault.core.builtin import builtin_supports, verify_plaintext


class CampaignEngine:
    def __init__(
        self,
        targets: Iterable[Target],
        *,
        known_plaintexts: dict[str, str] | None = None,
        wordlist: str | Path | None = None,
        max_candidates: int = 50_000,
        max_patterns: int = 5,
        include_slow: bool = False,
        known_origins: dict[str, str] | None = None,
    ) -> None:
        self.targets = list(targets)
        self.known_plaintexts = dict(known_plaintexts or {})
        self.known_origins = dict(known_origins or {})
        self.wordlist = Path(wordlist) if wordlist else None
        self.max_candidates = max(1, int(max_candidates))
        self.max_patterns = max(1, int(max_patterns))
        self.include_slow = include_slow
        self.notes: list[str] = []
        self.candidates_generated = 0
        self.checks = 0
        self._recoveries: list[Recovery] = []
        self._known: list[tuple[str, str]] = []
        self._pattern_cache: dict[int, list[Any]] = {}
        self._elapsed_offset = 0.0
        self._last_plan_stages: list[Stage] = []
        self._checkpoint_stage_stats: dict[str, dict[str, Any]] = {}
        self._seed_targets()
        self._add_coverage_notes()

    def _patterns_for(self, target: Target) -> list[Any]:
        key = id(target)
        cached = self._pattern_cache.get(key)
        if cached is not None:
            return cached
        supported = [
            pattern for pattern in target.patterns if builtin_supports(pattern)
        ][: self.max_patterns]
        self._pattern_cache[key] = supported
        return supported

    def _target_supported(self, target: Target) -> bool:
        return bool(self._patterns_for(target))

    def _seed_targets(self) -> None:
        for target in self.targets:
            value = self._lookup_known(target)
            if value is None:
                continue
            pattern_name = self._verify(target, value, include_slow=True)
            if pattern_name is None:
                self.notes.append(f"known plaintext rejected for {target.target_id}")
                continue
            origin = self._lookup_known_origin(target)
            self._resolve(target, value, pattern_name, "known-plaintext", origin)
            self._known.append((value, target.target_id))

    def _lookup_known(self, target: Target) -> str | None:
        keys = [target.target_id, target.normalized_hash, target.raw_hash]
        if target.username:
            keys.extend([target.username, target.username.lower()])
        for key in keys:
            if key and key in self.known_plaintexts:
                return self.known_plaintexts[key]
        return None

    def _lookup_known_origin(self, target: Target) -> str:
        keys = [target.target_id, target.normalized_hash, target.raw_hash]
        if target.username:
            keys.extend([target.username, target.username.lower()])
        for key in keys:
            if key and key in self.known_origins:
                return self.known_origins[key]
        return "seed"

    def _add_coverage_notes(self) -> None:
        ambiguous = [
            target for target in self.targets if len(target.pattern_names()) > 1
        ]
        unsupported = [
            target for target in self.targets if not self._target_supported(target)
        ]
        slow = [target for target in self.targets if target.is_slow()]
        if ambiguous:
            self.notes.append(
                f"{len(ambiguous)} targets have multiple candidate patterns; all supported patterns are tested"
            )
        if unsupported:
            self.notes.append(
                f"{len(unsupported)} targets require an external backend; no built-in verifier is available"
            )
        if slow:
            suffix = (
                "included"
                if self.include_slow
                else "skipped during mutation and wordlist stages"
            )
            self.notes.append(f"{len(slow)} slow targets: {suffix}")

    def _verify(
        self, target: Target, candidate: str, *, include_slow: bool
    ) -> str | None:
        if target.resolved:
            return None
        if target.is_slow() and not include_slow:
            return None
        for pattern in self._patterns_for(target):
            self.checks += 1
            try:
                result = verify_plaintext(target.normalized_hash, pattern, candidate)
            except (AttributeError, KeyError, TypeError, ValueError):
                continue
            if result:
                return str(getattr(pattern, "name", "unknown"))
        return None

    def _resolve(
        self,
        target: Target,
        plaintext: str,
        pattern_name: str,
        method: str,
        evidence: str,
    ) -> None:
        target.status = "resolved"
        target.plaintext = plaintext
        target.pattern_name = pattern_name
        target.method = method
        target.confidence = 1.0
        target.evidence.append(
            Evidence(kind=method, value=evidence, origin=target.target_id)
        )
        self._recoveries.append(
            Recovery(
                target_id=target.target_id,
                plaintext=plaintext,
                pattern_name=pattern_name,
                method=method,
                evidence=[evidence],
            )
        )

    def _known_values(self) -> list[str]:
        values: list[str] = []
        seen: set[str] = set()
        for plaintext, _ in self._known:
            if plaintext not in seen:
                seen.add(plaintext)
                values.append(plaintext)
        return values

    def _mutation_candidates(self) -> list[str]:
        return generate_candidates(
            self._known_values(),
            usernames=[target.username for target in self.targets if target.username],
            sources=[target.source for target in self.targets if target.source],
            limit=self.max_candidates,
        )

    def _wordlist_candidates(self) -> list[str]:
        if self.wordlist is None:
            return []
        candidates: list[str] = []
        try:
            with self.wordlist.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    value = line.rstrip("\r\n")
                    if not value:
                        continue
                    candidates.append(value)
                    if len(candidates) >= self.max_candidates:
                        break
        except OSError as exc:
            self.notes.append(f"wordlist unavailable: {exc}")
        return candidates

    def plan(self) -> CampaignPlan:
        unresolved = [target for target in self.targets if not target.resolved]
        exact_candidates = len(self._known_values())
        mutation_candidates = len(self._mutation_candidates())
        wordlist_candidates = len(self._wordlist_candidates())
        exact_cost = max(0.001, len(unresolved) * exact_candidates * 0.0001)
        mutation_cost = max(0.001, len(unresolved) * mutation_candidates * 0.00001)
        wordlist_cost = max(0.001, len(unresolved) * wordlist_candidates * 0.00001)
        stages = [
            Stage(
                name="exact-reuse",
                kind="reuse",
                target_ids=[target.target_id for target in unresolved],
                candidates=exact_candidates,
                expected_recoveries=len(unresolved) * 0.2,
                cost_seconds=exact_cost,
                priority=(len(unresolved) * 0.2) / exact_cost,
            ),
            Stage(
                name="context-mutations",
                kind="mutation",
                target_ids=[target.target_id for target in unresolved],
                candidates=mutation_candidates,
                expected_recoveries=len(unresolved) * 0.15,
                cost_seconds=mutation_cost,
                priority=(len(unresolved) * 0.15) / mutation_cost,
            ),
            Stage(
                name="wordlist",
                kind="wordlist",
                target_ids=[target.target_id for target in unresolved],
                candidates=wordlist_candidates,
                expected_recoveries=len(unresolved) * 0.05,
                cost_seconds=wordlist_cost,
                priority=(len(unresolved) * 0.05) / wordlist_cost,
            ),
        ]
        self._last_plan_stages = stages
        return CampaignPlan(
            stages=stages,
            total_targets=len(self.targets),
            supported_targets=sum(
                1 for target in self.targets if self._target_supported(target)
            ),
            slow_targets=sum(1 for target in self.targets if target.is_slow()),
            notes=list(self.notes),
        )

    def _run_exact_reuse(self, stage: Stage) -> None:
        start = time.perf_counter()
        changed = True
        while changed:
            changed = False
            unresolved = [target for target in self.targets if not target.resolved]
            for target in unresolved:
                for plaintext, source_id in list(self._known):
                    stage.tested += 1
                    pattern_name = self._verify(target, plaintext, include_slow=True)
                    if pattern_name is None:
                        continue
                    self._resolve(
                        target,
                        plaintext,
                        pattern_name,
                        "exact-reuse",
                        f"reuse:{source_id}",
                    )
                    self._known.append((plaintext, target.target_id))
                    stage.recoveries += 1
                    changed = True
                    break
        stage.elapsed_seconds = time.perf_counter() - start

    def _run_candidates(
        self, stage: Stage, candidates: list[str], method: str, evidence: str
    ) -> None:
        start = time.perf_counter()
        self.candidates_generated += len(candidates)
        unresolved = [target for target in self.targets if not target.resolved]
        for candidate in candidates:
            resolved_any = False
            for target in unresolved:
                if target.is_slow() and not self.include_slow:
                    continue
                stage.tested += 1
                pattern_name = self._verify(
                    target, candidate, include_slow=self.include_slow
                )
                if pattern_name is None:
                    continue
                self._resolve(target, candidate, pattern_name, method, evidence)
                self._known.append((candidate, target.target_id))
                stage.recoveries += 1
                resolved_any = True
            if resolved_any:
                unresolved = [target for target in unresolved if not target.resolved]
        stage.elapsed_seconds = time.perf_counter() - start

    def run(
        self,
        *,
        checkpoint_path: str | Path | None = None,
        resume_path: str | Path | None = None,
        progress: Any = None,
    ) -> CampaignReport:
        from hashvault.campaign.checkpoint import (
            build_snapshot,
            load_checkpoint,
            restore_snapshot,
            write_checkpoint,
        )

        start = time.perf_counter()
        campaign_id = uuid.uuid4().hex[:12]
        completed: set[str] = set()
        if resume_path is not None:
            snapshot = load_checkpoint(resume_path)
            campaign_id = str(snapshot.get("campaign_id") or campaign_id)
            completed = restore_snapshot(self, snapshot)
            self.notes.append(f"resumed campaign from {resume_path}")

        plan = self.plan()
        for stage in plan.stages:
            saved = self._checkpoint_stage_stats.get(stage.name)
            if saved:
                stage.tested = int(saved.get("tested", 0) or 0)
                stage.recoveries = int(saved.get("recoveries", 0) or 0)
                stage.elapsed_seconds = float(saved.get("elapsed_seconds", 0.0) or 0.0)

        def emit(stage_name: str, event: str) -> None:
            if callable(progress):
                progress(stage_name, event)

        for stage in plan.stages:
            if stage.name in completed:
                emit(stage.name, "skipped")
                continue
            emit(stage.name, "started")
            if stage.kind == "reuse":
                self._run_exact_reuse(stage)
            elif stage.kind == "mutation":
                self._run_candidates(
                    stage,
                    self._mutation_candidates(),
                    "context-mutation",
                    "mutation:corpus",
                )
            elif stage.kind == "wordlist":
                self._run_candidates(
                    stage,
                    self._wordlist_candidates(),
                    "wordlist",
                    f"wordlist:{self.wordlist.name if self.wordlist else 'none'}",
                )
            completed.add(stage.name)
            emit(stage.name, "completed")
            if checkpoint_path is not None:
                write_checkpoint(
                    build_snapshot(
                        self,
                        completed_stages=completed,
                        campaign_id=campaign_id,
                        elapsed_seconds=self._elapsed_offset
                        + (time.perf_counter() - start),
                    ),
                    checkpoint_path,
                )

        elapsed = self._elapsed_offset + (time.perf_counter() - start)
        if checkpoint_path is not None:
            write_checkpoint(
                build_snapshot(
                    self,
                    completed_stages=completed,
                    campaign_id=campaign_id,
                    elapsed_seconds=elapsed,
                ),
                checkpoint_path,
            )
        return CampaignReport(
            campaign_id=campaign_id,
            created_at=utc_now(),
            targets=self.targets,
            recoveries=self._recoveries,
            stages=plan.stages,
            elapsed_seconds=elapsed,
            candidates_generated=self.candidates_generated,
            checks=self.checks,
            notes=list(self.notes),
        )
