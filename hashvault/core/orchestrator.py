"""
Central pipeline orchestrator for HashVault v2.0.
Coordinates: normalizer → deep-analysis (CyberChef unwrap) → DB cache lookup
→ identifier scoring → canonicalization → tool routing → session isolation
→ execution → output reporting.
"""
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from hashvault.analysis.analyzer import AnalysisHandoff, prepare_input
from hashvault.analysis.replay import recipe_to_dict
from hashvault.config import Config
from hashvault.core.ambiguity import ambiguity_payload
from hashvault.core.builtin import BuiltinCracker, builtin_supports
from hashvault.core.canonicalizer import canonicalize, CrackPayload
from hashvault.core.cracker import (
    HashcatCracker,
    JohnCracker,
    CrackResult,
    create_crack_session,
    release_session_artifacts,
)
from hashvault.core.disambiguation import trial_disambiguate
from hashvault.core.format_parsers import parse_source_file
from hashvault.core.identifier import IdentificationResult, identify
from hashvault.core.integrity import verify_cached_plaintext
from hashvault.core.normalizer import normalize_hash
from hashvault.core.registry import CrackTool, ResolutionMethod, SourceFormat
from hashvault.core.router import route_tool
from hashvault.core.strategies import rank_tools, record_strategy_outcome
from hashvault.core.wordlist_manager import get_default_wordlist, resolve_rule, resolve_wordlist
from hashvault.exceptions import NoCandidateError, ToolNotFoundError, ToolSelectionError
from hashvault.models.orm import CrackAttempt, CrackedHash, CrackSession, Pattern
from hashvault.models.schemas import CandidateDTO, CrackedHashSchema, Pattern as PatternSchema, SourceContext
from hashvault.utils.system import find_executable

logger = logging.getLogger("hashvault.orchestrator")


def _engine_available(tool: CrackTool, config: Config) -> bool:
    if tool == CrackTool.HASHCAT:
        try:
            find_executable("hashcat", config.paths.hashcat_bin)
            return True
        except ToolNotFoundError:
            return False
    if tool == CrackTool.JOHN:
        try:
            find_executable("john", config.paths.john_bin)
            return True
        except ToolNotFoundError:
            return False
    if tool == CrackTool.BUILTIN:
        return bool(getattr(config.strategy, "builtin_enabled", True))
    return False


def _make_cracker(tool: CrackTool, config: Config):
    if tool == CrackTool.HASHCAT:
        return HashcatCracker(config)
    if tool == CrackTool.JOHN:
        return JohnCracker(config)
    return BuiltinCracker(config)


def _input_for_tool(tool: CrackTool, payload: CrackPayload) -> str:
    if tool == CrackTool.JOHN:
        return payload.john_input
    return payload.hashcat_input


def _finalize_session(session: CrackSession, success: bool) -> None:
    """Close sessions left 'running' by an early cracker validation failure."""
    if session.status == "running":
        session.status = "completed" if success else "failed"
        session.finished_at = datetime.now(timezone.utc)


def _identify_alternative(
    alternatives: List[Any],
    db_session: Session,
    config: Config,
    context: SourceContext,
    *,
    require_resolved: bool,
) -> Optional[Tuple[Any, Any]]:
    """Identify the first alternative analysis branch that maps to a pattern."""
    fallback: Optional[Tuple[Any, Any]] = None
    for trace in alternatives:
        target = getattr(trace, "finalized_input", "")
        if not target:
            continue
        try:
            alternative = identify(target, db_session, config, context)
        except NoCandidateError:
            continue
        if alternative.resolved:
            return trace, alternative
        if fallback is None:
            fallback = (trace, alternative)
    return None if require_resolved else fallback


def _select_analysis_branch(analysis_data: Optional[dict], trace: Any, reason: str) -> None:
    """Mark the active hypothesis in the public analysis payload."""
    if analysis_data is None:
        return
    analysis_data["selected"] = trace.finalized_input
    analysis_data["chain"] = trace.describe()
    analysis_data["layers_applied"] = trace.layers_applied
    analysis_data["terminal"] = trace.terminal
    analysis_data["analysis_fallback"] = reason
    selected = trace.finalized_input
    for branch in analysis_data.get("branches") or []:
        branch["selected"] = branch.get("finalized_input") == selected


def _remaining_budget(started: float, budget_seconds: Optional[float]) -> Optional[float]:
    if budget_seconds is None or budget_seconds <= 0:
        return None
    return max(0.0, float(budget_seconds) - (time.monotonic() - started))


def _attempt_timeout(started: float, budget_seconds: Optional[float]) -> Optional[int]:
    remaining = _remaining_budget(started, budget_seconds)
    if remaining is None:
        return None
    return max(1, int(remaining))


def _record_attempt(
    db_session: Session,
    attempts: List[dict],
    *,
    session: CrackSession,
    raw_input: str,
    normalized_hash: str,
    pattern_name: Optional[str],
    tool: CrackTool,
    attempt_index: int,
    success: bool,
    elapsed_seconds: float,
    budget_seconds: Optional[float],
    branch_chain: Optional[str] = None,
    error_message: Optional[str] = None,
) -> None:
    elapsed = round(max(0.0, elapsed_seconds), 4)
    record = CrackAttempt(
        session_id=getattr(session, "session_id", None),
        raw_input=raw_input,
        normalized_hash=normalized_hash,
        pattern_name=pattern_name,
        branch_chain=branch_chain,
        tool_used=tool.value if isinstance(tool, CrackTool) else str(tool),
        attempt_index=attempt_index,
        success=success,
        cached=False,
        elapsed_seconds=elapsed,
        budget_seconds=budget_seconds,
        error_message=error_message,
    )
    db_session.add(record)
    attempts.append(
        {
            "index": attempt_index,
            "pattern": pattern_name,
            "tool": record.tool_used,
            "success": success,
            "elapsed_seconds": elapsed,
            "chain": branch_chain,
            "error": error_message,
        }
    )


def _record_strategy(
    db_session: Session,
    *,
    pattern_name: Optional[str],
    tool: CrackTool,
    attack_mode: str,
    success: bool,
    elapsed_seconds: float,
) -> None:
    try:
        record_strategy_outcome(
            db_session,
            pattern_name=pattern_name,
            tool=tool,
            attack_mode=attack_mode,
            success=success,
            elapsed_seconds=elapsed_seconds,
        )
    except Exception as exc:
        logger.debug("Strategy feedback skipped: %s", exc)


def _tool_options(
    pattern: Any,
    requested: CrackTool,
    config: Config,
    *,
    adaptive: bool,
    attack_mode: str,
    db_session: Optional[Session] = None,
) -> List[CrackTool]:
    if requested != CrackTool.AUTO:
        return [requested]
    options: List[CrackTool] = []
    if getattr(pattern, "hashcat_mode", None) is not None and _engine_available(
        CrackTool.HASHCAT, config
    ):
        options.append(CrackTool.HASHCAT)
    if getattr(pattern, "john_format", None) is not None and _engine_available(
        CrackTool.JOHN, config
    ):
        options.append(CrackTool.JOHN)
    if builtin_supports(pattern) and _engine_available(CrackTool.BUILTIN, config):
        options.append(CrackTool.BUILTIN)
    if not options:
        options = [CrackTool.HASHCAT]
    if adaptive and db_session is not None:
        try:
            options = rank_tools(
                db_session,
                pattern_name=getattr(pattern, "name", None),
                tools=options,
                attack_mode=attack_mode,
            )
        except Exception as exc:
            logger.debug("Adaptive tool ranking skipped: %s", exc)
    return options


def _run_trial_disambiguation(
    id_result: Any,
    normalized: str,
    config: Config,
    strategy_config: Any,
) -> Optional[Any]:
    """Try the top ambiguous candidates with the built-in engine.

    Returns a :class:`DisambiguationResult` or ``None`` when trials cannot run
    (no quick wordlist, or the engine is disabled).
    """
    if not getattr(strategy_config, "builtin_enabled", True):
        return None

    quick = Path(getattr(config.paths, "quick_wordlist", "") or "")
    if not quick.is_file():
        logger.debug("Trial disambiguation skipped: quick wordlist missing.")
        return None

    max_trials = int(getattr(strategy_config, "trial_max_candidates", 3) or 3)
    budget = float(getattr(strategy_config, "trial_budget_seconds", 20.0) or 0.0)

    def attempt(candidate: Any, remaining: Optional[int]) -> bool:
        pattern = getattr(candidate, "pattern", None)
        if pattern is None or not builtin_supports(pattern):
            return False
        session = create_crack_session(
            config.paths.sessions_dir,
            target_hash=normalized,
            pattern_id=getattr(pattern, "id", None),
            tool_used="builtin",
        )
        try:
            result = BuiltinCracker(config).crack(
                hash_value=normalized,
                pattern=pattern,
                wordlist_path=quick,
                session=session,
                timeout_seconds=remaining,
            )
            return bool(result.success)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Trial for %s failed: %s", getattr(pattern, "name", "?"), exc)
            return False
        finally:
            release_session_artifacts(
                session,
                keep=getattr(config.strategy, "keep_session_artifacts", False),
            )

    return trial_disambiguate(
        id_result.candidates,
        attempt,
        max_trials=max_trials,
        budget_seconds=budget or None,
        tool="builtin",
    )


@dataclass
class ProcessResult:
    raw_input: str
    normalized_hash: str
    username: Optional[str]
    candidate: Optional[CandidateDTO]
    plaintext: Optional[str]
    cracked: bool
    cached: bool
    tool_used: str
    error_message: Optional[str] = None
    # Canonicalization / routing metadata
    hashcat_input: Optional[str] = None
    john_input: Optional[str] = None
    route_reason: Optional[str] = None
    confidence: Optional[float] = None
    candidates: Optional[List[CandidateDTO]] = None
    analysis: Optional[dict] = None
    attempts: Optional[List[dict]] = None
    ambiguity: Optional[dict] = None
    budget_seconds: Optional[float] = None
    recipe: Optional[dict] = None


def process_single_hash(
    raw_hash: str,
    db_session: Session,
    config: Config,
    tool: CrackTool = CrackTool.AUTO,
    wordlist_name: Optional[str] = None,
    rule_name: Optional[str] = None,
    hint_category: Optional[str] = None,
    source_format: SourceFormat = SourceFormat.AUTO_DETECT,
    auto_confirm: bool = True,
    forced_pattern: Optional[str] = None,
    *,
    identify_only: bool = False,
    use_cache: bool = True,
    attack_mode: str = "dictionary",
    mask: Optional[str] = None,
    unwrap: bool = True,
    max_layers: int = 12,
    beam_width: int = 8,
    allow_extractors: bool = False,
    analysis_keys: Optional[dict[str, str]] = None,
    analysis_listener: Optional[object] = None,
    retry_alternatives: Optional[bool] = None,
    max_alternative_attempts: Optional[int] = None,
    budget_seconds: Optional[float] = None,
    adaptive_tool_selection: Optional[bool] = None,
) -> ProcessResult:
    """
    Full pipeline execution for a single raw hash input.

    Parameters
    ----------
    forced_pattern:
        If provided (e.g. 'MD5', 'NTLM', 'bcrypt'), bypasses the identifier
        and forces the named pattern to be used for cracking.
    """
    # 1. Normalize
    original_raw = raw_hash
    normalized, username = normalize_hash(raw_hash)
    original_normalized, original_username = normalized, username
    effective_raw = raw_hash
    analysis_handoff: Optional[AnalysisHandoff] = None
    analysis_data: Optional[dict] = None
    analysis_alternatives: List[Any] = []
    selected_trace: Optional[Any] = None
    started = time.monotonic()
    attempts: List[dict] = []
    strategy_config = getattr(config, "strategy", None)
    retry_alternatives = (
        bool(getattr(strategy_config, "retry_alternatives", True))
        if retry_alternatives is None
        else retry_alternatives
    )
    max_alternative_attempts = (
        int(getattr(strategy_config, "max_alternative_attempts", 3))
        if max_alternative_attempts is None
        else max_alternative_attempts
    )
    if budget_seconds is None:
        budget_seconds = float(
            getattr(strategy_config, "default_budget_seconds", 0.0) or 0.0
        )
    if budget_seconds is not None and budget_seconds <= 0:
        budget_seconds = None
    adaptive_tool_selection = (
        bool(getattr(strategy_config, "adaptive_tool_selection", True))
        if adaptive_tool_selection is None
        else adaptive_tool_selection
    )

    # 1b. Layered pre-analysis.  A clean hash exits immediately, while encoded
    # payloads and code/config blobs are unwrapped before cache/identification.
    if unwrap:
        analysis_source = normalized if username else raw_hash
        try:
            analysis_handoff = prepare_input(
                analysis_source,
                max_layers=max_layers,
                beam_width=beam_width,
                allow_extractors=allow_extractors,
                keys=analysis_keys,
                listener=analysis_listener,  # type: ignore[arg-type]
            )
            analysis_alternatives = list(getattr(analysis_handoff, "alternatives", []) or [])
            selected_trace = analysis_handoff.trace
            if analysis_handoff.trace.layers_applied:
                analysis_data = analysis_handoff.to_trace_dict()
            if analysis_handoff.trace.terminal and analysis_handoff.primary:
                effective_raw = analysis_handoff.primary
                normalized, decoded_username = normalize_hash(effective_raw)
                username = username or decoded_username
        except Exception as exc:
            logger.debug("Layer analysis skipped: %s", exc)

    # Public callers may pass the enum's string value (e.g. from JSON/CLI
    # adapters).  Coerce once so routing and result reporting always operate
    # on CrackTool members.
    if not isinstance(tool, CrackTool):
        try:
            tool = CrackTool(str(tool).lower())
        except ValueError:
            return ProcessResult(
                raw_input=raw_hash,
                normalized_hash=normalized,
                username=username,
                candidate=None,
                plaintext=None,
                cracked=False,
                cached=False,
                tool_used="none",
                error_message=f"Unknown cracking tool: {tool!r}",
                analysis=analysis_data,
            )

    # 2. Cache Lookup in cracked_hashes (not used by identify-only checks)
    existing = None
    if use_cache:
        existing = (
            db_session.query(CrackedHash)
            .filter(CrackedHash.normalized_hash == normalized)
            .first()
        )
    if existing:
        # A cache hit used to be trusted unconditionally, so a stale or
        # corrupted row was served as a valid result forever (``audit`` could
        # detect it but was never consulted here).  Re-verify when enabled.
        trust_cache = True
        if getattr(strategy_config, "verify_cache_entries", False):
            # Verifying a slow hash costs a full KDF (bcrypt cost 12 is ~250ms,
            # argon2 more), which would dominate a batch re-run.  Fast formats
            # are always checked; slow ones only when explicitly asked for.
            pattern_for_cache = getattr(existing, "pattern", None)
            is_slow_hash = bool(getattr(pattern_for_cache, "is_slow", False))
            should_verify = is_slow_hash is False or bool(
                getattr(strategy_config, "verify_slow_hashes", False)
            )
            if should_verify:
                verdict = verify_cached_plaintext(
                    existing.normalized_hash, pattern_for_cache, existing.plaintext
                )
                if verdict is False:
                    trust_cache = False
                    logger.warning(
                        "Cached plaintext for %s failed verification; re-cracking.",
                        existing.normalized_hash,
                    )

        if trust_cache:
            pattern_dto = None
            if existing.pattern:
                pattern_dto = PatternSchema.model_validate(existing.pattern)
                candidate = CandidateDTO(pattern=pattern_dto, confidence=1.0)
            else:
                candidate = None

            return ProcessResult(
                raw_input=raw_hash,
                normalized_hash=normalized,
                username=username or existing.username,
                candidate=candidate,
                plaintext=existing.plaintext,
                cracked=True,
                cached=True,
                tool_used=existing.tool_used,
                analysis=analysis_data,
                budget_seconds=budget_seconds,
                recipe=(
                    recipe_to_dict(selected_trace)
                    if selected_trace is not None
                    else None
                ),
            )

    # 3. Hash Pattern Identification
    # ── forced_pattern override ─────────────────────────────────────────
    if forced_pattern:
        # Exact (case-insensitive) match first, then prefix, then substring.
        # This prevents "--pattern md5" from silently selecting "MD5(APR)".
        pat_orm = (
            db_session.query(Pattern)
            .filter(Pattern.name.ilike(forced_pattern))
            .first()
        )
        if not pat_orm:
            pat_orm = (
                db_session.query(Pattern)
                .filter(Pattern.name.ilike(f"{forced_pattern}%"))
                .order_by(Pattern.popularity.desc())
                .first()
            )
        if not pat_orm:
            pat_orm = (
                db_session.query(Pattern)
                .filter(Pattern.name.ilike(f"%{forced_pattern}%"))
                .order_by(Pattern.popularity.desc())
                .first()
            )
        if pat_orm:
            from hashvault.core.identifier import IdentificationResult, Candidate
            forced_cand_native = Candidate(pattern=pat_orm, confidence=1.0)
            id_result = IdentificationResult(
                candidates=[forced_cand_native],
                resolved=True,
                method="forced",
                chosen_pattern=pat_orm,
                confidence_score=1.0,
            )
        else:
            return ProcessResult(
                raw_input=raw_hash,
                normalized_hash=normalized,
                username=username,
                candidate=None,
                plaintext=None,
                cracked=False,
                cached=False,
                tool_used="none",
                error_message=f"--pattern '{forced_pattern}' not found in pattern database.",
                analysis=analysis_data,
            )
    else:
        context = SourceContext(
            associated_format=source_format if source_format != SourceFormat.AUTO_DETECT else None,
            user_declared_hint=hint_category,  # type: ignore
        )
        try:
            id_result = identify(normalized, db_session, config, context)
        except NoCandidateError as e:
            # An over-eager analysis branch may produce a terminal-looking
            # string that the identifier cannot map to any pattern.  Try the
            # other terminal hypotheses before falling back to the raw input.
            recovered = False
            alternative = _identify_alternative(
                analysis_alternatives,
                db_session,
                config,
                context,
                require_resolved=False,
            )
            if alternative is not None:
                trace, id_result = alternative
                effective_raw = trace.finalized_input
                normalized, decoded_username = normalize_hash(effective_raw)
                username = original_username or decoded_username
                selected_trace = trace
                _select_analysis_branch(analysis_data, trace, "analysis-alternative")
                recovered = True

            if not recovered and normalized != original_normalized:
                try:
                    id_result = identify(original_normalized, db_session, config, context)
                except NoCandidateError:
                    pass
                else:
                    normalized = original_normalized
                    username = original_username
                    effective_raw = original_raw
                    selected_trace = None
                    if analysis_data is not None:
                        analysis_data["analysis_fallback"] = "original-input"
                        analysis_data["selected"] = original_normalized
                        analysis_data["chain"] = "(original input)"
                        analysis_data["layers_applied"] = 0
                        for branch in analysis_data.get("branches") or []:
                            branch["selected"] = False
                    recovered = True
            if not recovered:
                return ProcessResult(
                    raw_hash=raw_hash,
                    normalized_hash=normalized,
                    username=username,
                    candidate=None,
                    plaintext=None,
                    cracked=False,
                    cached=False,
                    tool_used="none",
                    error_message=str(e),
                    analysis=analysis_data,
                )
        else:
            if not id_result.resolved:
                alternative = _identify_alternative(
                    analysis_alternatives,
                    db_session,
                    config,
                    context,
                    require_resolved=True,
                )
                if alternative is not None:
                    trace, id_result = alternative
                    effective_raw = trace.finalized_input
                    normalized, decoded_username = normalize_hash(effective_raw)
                    username = original_username or decoded_username
                    selected_trace = trace
                    _select_analysis_branch(
                        analysis_data, trace, "analysis-alternative-resolved"
                    )
    # ────────────────────────────────────────────────────────────────────

    candidate_dtos: List[CandidateDTO] = [
        CandidateDTO(pattern=PatternSchema.model_validate(c.pattern), confidence=c.confidence)
        for c in id_result.candidates
    ]
    ambiguity = ambiguity_payload(id_result) if id_result.candidates else None

    if identify_only:
        if not id_result.candidates:
            return ProcessResult(
                raw_input=raw_hash,
                normalized_hash=normalized,
                username=username,
                candidate=None,
                plaintext=None,
                cracked=False,
                cached=False,
                tool_used="none",
                error_message="No matching hash pattern found.",
                route_reason="identify-only",
                analysis=analysis_data,
                ambiguity=ambiguity,
                budget_seconds=budget_seconds,
            )
        top = id_result.candidates[0]
        return ProcessResult(
            raw_input=raw_hash,
            normalized_hash=normalized,
            username=username,
            candidate=candidate_dtos[0],
            plaintext=None,
            cracked=False,
            cached=False,
            tool_used="none",
            route_reason="identify-only",
            confidence=top.confidence,
            candidates=candidate_dtos,
            error_message=(
                None if id_result.resolved
                else f"Ambiguous hash candidates (top: {top.pattern.name})."
            ),
            analysis=analysis_data,
            ambiguity=ambiguity,
            budget_seconds=budget_seconds,
        )

    # 3b. Optional empirical disambiguation.  Formats that share a regex cannot
    # be separated by shape; a short, bounded cracking trial can separate them
    # by *behaviour*.  Only the built-in engine is used so this never depends on
    # an external binary being installed.
    trial_result = None
    if (
        not id_result.resolved
        and id_result.candidates
        and not identify_only
        and getattr(strategy_config, "enable_trial_disambiguation", False)
    ):
        trial_result = _run_trial_disambiguation(
            id_result, normalized, config, strategy_config
        )
        if trial_result is not None and trial_result.resolved:
            chosen_pattern = trial_result.chosen.pattern
            # Keep the full ranked list but promote the empirically proven
            # pattern to the front.
            reordered = [trial_result.chosen] + [
                candidate
                for candidate in id_result.candidates
                if candidate.pattern.id != chosen_pattern.id
            ]
            id_result = IdentificationResult(
                candidates=reordered,
                resolved=True,
                method=ResolutionMethod.EMPIRICAL_TRIAL.value,
                chosen_pattern=chosen_pattern,
                confidence_score=1.0,
            )

    if not id_result.resolved and not auto_confirm:
        # Ambiguous candidate requiring user interaction or --auto flag
        top_name = id_result.candidates[0].pattern.name if id_result.candidates else "unknown"
        return ProcessResult(
            raw_input=raw_hash,
            normalized_hash=normalized,
            username=username,
            candidate=id_result.candidates[0] if id_result.candidates else None,
            plaintext=None,
            cracked=False,
            cached=False,
            tool_used="none",
            error_message=f"Ambiguous hash candidates (top: {top_name}); add --auto to select top candidate.",
            analysis=analysis_data,
            ambiguity=ambiguity,
            budget_seconds=budget_seconds,
        )

    top_candidate = id_result.candidates[0]
    pattern_orm = db_session.query(Pattern).filter(Pattern.id == top_candidate.pattern.id).first()

    # 4. Canonicalize the payload (separate username, format for tools)
    payload: CrackPayload = canonicalize(
        raw=effective_raw,
        pattern=pattern_orm or top_candidate.pattern,
        source_format=source_format if source_format != SourceFormat.AUTO_DETECT else None,
        username=username,
        normalized=normalized,
    )

    # 5. Route to best tool via Router
    hashcat_available = _engine_available(CrackTool.HASHCAT, config)
    john_available = _engine_available(CrackTool.JOHN, config)
    builtin_available = _engine_available(CrackTool.BUILTIN, config)
    try:
        route = route_tool(
            capability=payload.capability,
            requested=tool if tool != CrackTool.AUTO else None,
            default_tool=getattr(config.strategy, 'default_tool', CrackTool.HASHCAT),
            prefer_john=False,
            hashcat_available=hashcat_available,
            john_available=john_available,
            builtin_available=builtin_available,
        )
        selected_tool = route.tool
        route_reason = route.reason
    except ToolSelectionError as exc:
        if tool != CrackTool.AUTO:
            return ProcessResult(
                raw_input=raw_hash,
                normalized_hash=normalized,
                username=username or payload.username,
                candidate=top_candidate,
                plaintext=None,
                cracked=False,
                cached=False,
                tool_used="none",
                error_message=str(exc),
                hashcat_input=payload.hashcat_input,
                john_input=payload.john_input,
                confidence=top_candidate.confidence,
                analysis=analysis_data,
            )
        # AUTO: fall back to the first supported engine if routing found no match.
        if top_candidate.pattern.hashcat_mode is not None and hashcat_available:
            selected_tool = CrackTool.HASHCAT
        elif top_candidate.pattern.john_format is not None and john_available:
            selected_tool = CrackTool.JOHN
        elif builtin_supports(top_candidate.pattern) and builtin_available:
            selected_tool = CrackTool.BUILTIN
        else:
            selected_tool = CrackTool.HASHCAT
        route_reason = "router-fallback (no mode/format match)"

    # 6. Resolve Wordlist and Rules
    try:
        wordlist_path = resolve_wordlist(wordlist_name, db_session, config)
    except Exception:
        wordlist_path = get_default_wordlist(config)

    rule_path = None
    if rule_name:
        try:
            rule_path = resolve_rule(rule_name, config)
        except Exception as exc:
            return ProcessResult(
                raw_input=raw_hash,
                normalized_hash=normalized,
                username=username or payload.username,
                candidate=top_candidate,
                plaintext=None,
                cracked=False,
                cached=False,
                tool_used="none",
                error_message=f"Invalid rule: {exc}",
                hashcat_input=payload.hashcat_input,
                john_input=payload.john_input,
                confidence=top_candidate.confidence,
                analysis=analysis_data,
            )

    # 7. Session Isolation setup
    tool_order = _tool_options(
        top_candidate.pattern,
        tool,
        config,
        adaptive=adaptive_tool_selection,
        attack_mode=attack_mode,
        db_session=db_session,
    )
    if tool != CrackTool.AUTO:
        tool_order = [selected_tool]
    elif adaptive_tool_selection:
        if selected_tool not in tool_order:
            tool_order.insert(0, selected_tool)
        if tool_order[0] != selected_tool:
            route_reason = f"{route_reason}; adaptive order"
    elif selected_tool in tool_order:
        tool_order.remove(selected_tool)
        tool_order.insert(0, selected_tool)
    else:
        tool_order.insert(0, selected_tool)

    # 8. Execute cracking attempts in adaptive order.  Once a tool reports a
    # normal exhausted wordlist, other engines are not replayed unless a
    # distinct analysis branch is tried later.
    crack_res: Optional[CrackResult] = None
    session_record: Optional[CrackSession] = None
    budget_exhausted = False
    attempt_index = 0
    for order_index, attempt_tool in enumerate(tool_order, 1):
        remaining = _remaining_budget(started, budget_seconds)
        if remaining is not None and remaining <= 0:
            budget_exhausted = True
            break
        attempt_index += 1
        attempt_started = time.monotonic()
        attempt_session = create_crack_session(
            config.paths.sessions_dir,
            target_hash=normalized,
            pattern_id=getattr(top_candidate.pattern, "id", None),
            tool_used=getattr(attempt_tool, "value", str(attempt_tool)),
        )
        db_session.add(attempt_session)
        db_session.commit()
        attempt_res = _make_cracker(attempt_tool, config).crack(
            hash_value=_input_for_tool(attempt_tool, payload),
            pattern=top_candidate.pattern,
            wordlist_path=wordlist_path,
            session=attempt_session,
            rule_path=rule_path,
            attack_mode=attack_mode,
            mask=mask,
            timeout_seconds=_attempt_timeout(started, budget_seconds),
        )
        _finalize_session(attempt_session, attempt_res.success)
        release_session_artifacts(
            attempt_session,
            keep=getattr(config.strategy, "keep_session_artifacts", False),
        )
        elapsed = time.monotonic() - attempt_started
        _record_attempt(
            db_session,
            attempts,
            session=attempt_session,
            raw_input=original_raw,
            normalized_hash=normalized,
            pattern_name=getattr(top_candidate.pattern, "name", None),
            tool=attempt_tool,
            attempt_index=attempt_index,
            success=attempt_res.success,
            elapsed_seconds=elapsed,
            budget_seconds=budget_seconds,
            branch_chain=(analysis_data or {}).get("chain"),
            error_message=attempt_res.error_message,
        )
        _record_strategy(
            db_session,
            pattern_name=getattr(top_candidate.pattern, "name", None),
            tool=attempt_tool,
            attack_mode=attack_mode,
            success=attempt_res.success,
            elapsed_seconds=elapsed,
        )
        if attempt_res.success:
            crack_res = attempt_res
            session_record = attempt_session
            selected_tool = attempt_tool
            break
        if crack_res is None:
            crack_res = attempt_res
        if order_index > 1:
            route_reason = f"{route_reason}; fallback to {attempt_tool.value}"
        if not attempt_res.engine_error:
            break

    tried_alternatives = 0
    seen_targets = {effective_raw}
    if (
        (crack_res is None or not crack_res.success)
        and retry_alternatives
        and analysis_alternatives
        and max_alternative_attempts > 0
    ):
        context = SourceContext(
            associated_format=source_format if source_format != SourceFormat.AUTO_DETECT else None,
            user_declared_hint=hint_category,  # type: ignore
        )
        for trace in analysis_alternatives:
            if tried_alternatives >= max_alternative_attempts:
                break
            remaining = _remaining_budget(started, budget_seconds)
            if remaining is not None and remaining <= 0:
                budget_exhausted = True
                break
            target = getattr(trace, "finalized_input", "")
            if not target or target in seen_targets:
                continue
            seen_targets.add(target)
            try:
                alternative_id = identify(target, db_session, config, context)
            except NoCandidateError:
                continue
            if not alternative_id.candidates:
                continue
            tried_alternatives += 1
            alternative_candidate = alternative_id.candidates[0]
            alternative_pattern = (
                db_session.query(Pattern)
                .filter(Pattern.id == alternative_candidate.pattern.id)
                .first()
            )
            alternative_payload = canonicalize(
                raw=target,
                pattern=alternative_pattern or alternative_candidate.pattern,
                source_format=source_format if source_format != SourceFormat.AUTO_DETECT else None,
                username=username,
                normalized=target,
            )
            alt_options = _tool_options(
                alternative_candidate.pattern,
                tool,
                config,
                adaptive=adaptive_tool_selection,
                attack_mode=attack_mode,
                db_session=db_session,
            )
            alt_success = False
            for alt_tool in alt_options:
                remaining = _remaining_budget(started, budget_seconds)
                if remaining is not None and remaining <= 0:
                    budget_exhausted = True
                    break
                attempt_index += 1
                attempt_started = time.monotonic()
                alt_session = create_crack_session(
                    config.paths.sessions_dir,
                    target_hash=target,
                    pattern_id=getattr(alternative_candidate.pattern, "id", None),
                    tool_used=getattr(alt_tool, "value", str(alt_tool)),
                )
                db_session.add(alt_session)
                db_session.commit()
                alt_res = _make_cracker(alt_tool, config).crack(
                    hash_value=_input_for_tool(alt_tool, alternative_payload),
                    pattern=alternative_candidate.pattern,
                    wordlist_path=wordlist_path,
                    session=alt_session,
                    rule_path=rule_path,
                    attack_mode=attack_mode,
                    mask=mask,
                    timeout_seconds=_attempt_timeout(started, budget_seconds),
                )
                _finalize_session(alt_session, alt_res.success)
                release_session_artifacts(
                    alt_session,
                    keep=getattr(config.strategy, "keep_session_artifacts", False),
                )
                elapsed = time.monotonic() - attempt_started
                _record_attempt(
                    db_session,
                    attempts,
                    session=alt_session,
                    raw_input=original_raw,
                    normalized_hash=target,
                    pattern_name=getattr(
                        alternative_candidate.pattern, "name", None
                    ),
                    tool=alt_tool,
                    attempt_index=attempt_index,
                    success=alt_res.success,
                    elapsed_seconds=elapsed,
                    budget_seconds=budget_seconds,
                    branch_chain=trace.describe(),
                    error_message=alt_res.error_message,
                )
                _record_strategy(
                    db_session,
                    pattern_name=getattr(
                        alternative_candidate.pattern, "name", None
                    ),
                    tool=alt_tool,
                    attack_mode=attack_mode,
                    success=alt_res.success,
                    elapsed_seconds=elapsed,
                )
                if alt_res.success:
                    crack_res = alt_res
                    session_record = alt_session
                    selected_tool = alt_tool
                    top_candidate = alternative_candidate
                    payload = alternative_payload
                    effective_raw = target
                    normalized, decoded_username = normalize_hash(target)
                    username = original_username or decoded_username
                    selected_trace = trace
                    _select_analysis_branch(
                        analysis_data, trace, "analysis-retry-success"
                    )
                    route_reason = f"{route_reason}; retry branch {trace.describe()}"
                    alt_success = True
                    break
                if crack_res is None:
                    crack_res = alt_res
                if not alt_res.engine_error:
                    break
            if alt_success:
                break

    if crack_res is None:
        return ProcessResult(
            raw_input=raw_hash,
            normalized_hash=normalized,
            username=username,
            candidate=top_candidate,
            plaintext=None,
            cracked=False,
            cached=False,
            tool_used="none",
            route_reason=route_reason,
            error_message="Crack budget expired before any attempt could run." if budget_exhausted else "No cracking engine was available.",
            analysis=analysis_data,
            attempts=attempts,
            ambiguity=ambiguity,
            budget_seconds=budget_seconds,
        )

    recipe_payload = (
        recipe_to_dict(selected_trace) if selected_trace is not None else None
    )

    # 9. Transactional persistence on success
    if crack_res.success and crack_res.plaintext and session_record is not None:
        cracked_entry = CrackedHash(
            hash_value=raw_hash,
            normalized_hash=normalized,
            pattern_id=top_candidate.pattern.id, # type: ignore
            plaintext=crack_res.plaintext,
            username=username or payload.username,
            tool_used=selected_tool.value,
            source="pipeline",
            raw_input=raw_hash,
        )
        db_session.add(cracked_entry)
        session_record.cracked_count = 1
        session_record.status = "completed"
        try:
            db_session.commit()
        except IntegrityError:
            # The (normalized_hash, pattern_id, username) unique constraint can
            # fire on concurrent runs.  SQLite treats NULL usernames as
            # distinct, so the constraint does not always catch duplicates
            # either; either way the record already exists and the result is
            # still valid, so keep it instead of failing the whole call.
            db_session.rollback()
            logger.debug("Cracked hash already stored; keeping existing record.")
            existing_entry = (
                db_session.query(CrackedHash)
                .filter(CrackedHash.normalized_hash == normalized)
                .first()
            )
            if existing_entry is None:
                # Fall back to a merge-style insert without the conflicting key.
                db_session.add(cracked_entry)
                try:
                    db_session.commit()
                except IntegrityError:
                    db_session.rollback()

        return ProcessResult(
            raw_input=raw_hash,
            normalized_hash=normalized,
            username=username or payload.username,
            candidate=top_candidate,
            plaintext=crack_res.plaintext,
            cracked=True,
            cached=False,
            tool_used=selected_tool.value,
            hashcat_input=payload.hashcat_input,
            john_input=payload.john_input,
            route_reason=route_reason,
            analysis=analysis_data,
            attempts=attempts,
            ambiguity=ambiguity,
            budget_seconds=budget_seconds,
            recipe=recipe_payload,
        )

    db_session.commit()
    failure_message = crack_res.error_message or "Hash could not be cracked."
    if budget_exhausted:
        failure_message = f"{failure_message} (crack budget expired)"
    return ProcessResult(
        raw_input=raw_hash,
        normalized_hash=normalized,
        username=username or payload.username,
        candidate=top_candidate,
        plaintext=None,
        cracked=False,
        cached=False,
        tool_used=selected_tool.value,
        hashcat_input=payload.hashcat_input,
        john_input=payload.john_input,
        route_reason=route_reason,
        error_message=failure_message,
        analysis=analysis_data,
        attempts=attempts,
        ambiguity=ambiguity,
        budget_seconds=budget_seconds,
        recipe=recipe_payload,
    )


def process_batch(
    content_or_file: str,
    db_session: Session,
    config: Config,
    tool: CrackTool = CrackTool.AUTO,
    wordlist_name: Optional[str] = None,
    rule_name: Optional[str] = None,
    hint_category: Optional[str] = None,
    source_format: SourceFormat = SourceFormat.AUTO_DETECT,
    auto_confirm: bool = True,
    *,
    identify_only: bool = False,
    use_cache: bool = True,
    attack_mode: str = "dictionary",
    mask: Optional[str] = None,
    unwrap: bool = True,
    max_layers: int = 12,
    beam_width: int = 8,
    allow_extractors: bool = False,
    analysis_keys: Optional[dict[str, str]] = None,
    analysis_listener: Optional[object] = None,
    retry_alternatives: Optional[bool] = None,
    max_alternative_attempts: Optional[int] = None,
    budget_seconds: Optional[float] = None,
    adaptive_tool_selection: Optional[bool] = None,
) -> List[ProcessResult]:
    """
    Process a batch of hashes from raw text or dumped file content.
    Failures on individual hashes are recorded without halting batch execution.
    """
    parsed_records = parse_source_file(content_or_file, source_format)
    results: List[ProcessResult] = []

    for rec in parsed_records:
        res = process_single_hash(
            raw_hash=rec.raw_input,
            db_session=db_session,
            config=config,
            tool=tool,
            wordlist_name=wordlist_name,
            rule_name=rule_name,
            hint_category=hint_category,
            source_format=rec.detected_format,
            auto_confirm=auto_confirm,
            identify_only=identify_only,
            use_cache=use_cache,
            attack_mode=attack_mode,
            mask=mask,
            unwrap=unwrap,
            max_layers=max_layers,
            beam_width=beam_width,
            allow_extractors=allow_extractors,
            analysis_keys=analysis_keys,
            analysis_listener=analysis_listener,
            retry_alternatives=retry_alternatives,
            max_alternative_attempts=max_alternative_attempts,
            budget_seconds=budget_seconds,
            adaptive_tool_selection=adaptive_tool_selection,
        )
        results.append(res)

    return results
