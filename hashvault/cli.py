"""
Typer-based Command Line Interface for HashVault v2.0.
Provides subcommands for identifying, cracking, checking cache, managing sessions,
converting encrypted files, and interactive shell entry.
"""
import json
import os
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table
from rich import box

from hashvault.analysis.analyzer import AnalysisHandoff, analyze_input, prepare_input
from hashvault.analysis.replay import (
    RecipeReplayError,
    load_recipe,
    recipe_to_dict,
    replay_recipe,
    write_recipe,
)
from hashvault.config import load_config
from hashvault.corpus import DEFAULT_CORPUS_FILES
from hashvault.core.cracker import purge_session_dirs
from hashvault.core.database import (
    get_db_session,
    init_db,
    resolve_resource_path,
    seed_patterns,
)
from hashvault.core.doctor import DoctorReport, FAIL, OK, WARN, run_doctor
from hashvault.core.identifier import identify
from hashvault.core.insights import run_insights
from hashvault.core.integrity import (
    ERROR,
    MISMATCH,
    UNSUPPORTED,
    VERIFIED,
    verify_cracked_hashes,
)
from hashvault.core.orchestrator import process_batch, process_single_hash
from hashvault.core.parameters import analyze_parameters
from hashvault.core.registry import CrackTool, HashCategory, OutputFormat, SessionStatus, SourceFormat
from hashvault.core.strategies import list_strategy_stats, reset_strategy_stats
from hashvault.core.reporter import (
    identification_payload,
    render_crack_results,
    render_identification_report,
    render_sessions_report,
)
from hashvault.core.wordlist_manager import import_wordlist as mgr_import_wordlist, list_rules, list_wordlists
from hashvault.exceptions import HashVaultError, NoCandidateError
from hashvault.ingestors.converters import convert_file, detect_file_type
from hashvault.ingestors.john_catalog import (
    build_hashcat_command,
    build_john_command,
    build_john_show_command,
    convert_with_profile,
    discover_converters,
    find_profiles_for_path,
    gallery_rows,
    get_profile,
)
from hashvault.layers import benchmark_layers, load_layer_vectors
from hashvault.models.orm import CrackAttempt, CrackedHash, CrackSession, Pattern, StrategyStat
from hashvault.models.schemas import CrackSessionSchema, SourceContext
from hashvault.mutation.context import ContextProfile
from hashvault.mutation.rules import write_rule_file
from hashvault.mutation.service import build_mutation
from hashvault.ui.conversion_gallery import render_conversion_gallery
from hashvault.ui.interactive import start_interactive_shell

app = typer.Typer(
    name="hashvault",
    help="HashVault — Enterprise Password Hash Identification & Auditing Framework v2.0",
    add_completion=False,
)
console = Console(highlight=False, width=120, force_jupyter=False)
strategies_app = typer.Typer(help="Adaptive strategy feedback statistics.")
app.add_typer(strategies_app, name="strategies")


@app.command("banner")
def banner_cmd(
    json_output: bool = typer.Option(
        False, "--json", help="Emit the identity block as JSON (no colour)"
    ),
    plain: bool = typer.Option(
        False, "--plain", help="Print the wordmark without ANSI colour"
    ),
) -> None:
    """Show the project wordmark, author and repository link."""
    from hashvault.ui.banner import banner_payload, banner_text, render_banner

    if json_output:
        console.print_json(data=banner_payload())
        return
    if plain:
        from hashvault.ui.banner import credits_lines

        console.print(banner_text())
        console.print()
        for credit in credits_lines():
            console.print(credit, markup=False, highlight=False)
        return

    render_banner(console)


def _read_input_file(path: Path) -> str:
    """Read text while preserving arbitrary bytes for archive/cipher analysis."""
    # Analysis loads the payload into memory, so an unbounded read lets a huge
    # file (or a mis-specified path) exhaust RAM before any search limit
    # applies.  64 MiB is far above any realistic hash/archive payload.
    max_bytes = int(os.environ.get("HASHVAULT_MAX_INPUT_BYTES", 64 * 1024 * 1024))
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise typer.BadParameter(f"Cannot read {path}: {exc}") from exc
    if size > max_bytes:
        raise typer.BadParameter(
            f"Input file is {size:,} bytes; the limit is {max_bytes:,} "
            f"(set HASHVAULT_MAX_INPUT_BYTES to raise it)."
        )

    raw = path.read_bytes()
    binary_magic = raw.startswith(
        (b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")
    ) or raw[257:262] == b"ustar"
    if binary_magic or b"\x00" in raw:
        return raw.decode("latin-1")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _parse_cli_keys(key_specs: Optional[List[str]]) -> dict[str, str]:
    from hashvault.analysis.keys import KeyError as AnalysisKeyError, parse_key_options

    try:
        return parse_key_options(key_specs)
    except AnalysisKeyError as exc:
        console.print(f"[bold red]Invalid key:[/bold red] {exc}")
        raise typer.Exit(1)


def _prepare_cli_target(
    target: str,
    *,
    no_unwrap: bool,
    max_layers: int,
    beam_width: int,
    extractors: bool,
    key_specs: Optional[List[str]],
    live: bool = False,
    quiet: bool = False,
) -> Optional[AnalysisHandoff]:
    """Prepare an input for identify/crack while sharing analyze's search."""
    if no_unwrap:
        return None
    keys = _parse_cli_keys(key_specs)
    try:
        if live:
            from hashvault.analysis.live import RichAnalysisLive

            with RichAnalysisLive(console=console) as view:
                handoff = prepare_input(
                    target,
                    max_layers=max_layers,
                    beam_width=beam_width,
                    allow_extractors=extractors,
                    keys=keys,
                    listener=view,
                )
        else:
            handoff = prepare_input(
                target,
                max_layers=max_layers,
                beam_width=beam_width,
                allow_extractors=extractors,
                keys=keys,
            )
    except Exception as exc:
        if not quiet:
            console.print(f"[yellow]Analysis warning:[/yellow] {exc}")
        return None

    return handoff


@app.command("identify")
def identify_cmd(
    target: str = typer.Argument(..., help="Raw hash string or file path if --file is set"),
    file: bool = typer.Option(False, "--file", "-f", help="Treat target as a file path containing hashes"),
    hint: Optional[HashCategory] = typer.Option(None, "--hint", help="Category hint to refine candidate scoring"),
    format: SourceFormat = typer.Option(SourceFormat.AUTO_DETECT, "--format", help="Dump format hint"),
    json: bool = typer.Option(False, "--json", help="Format output as JSON"),
    no_unwrap: bool = typer.Option(False, "--no-unwrap", help="Disable layered pre-analysis"),
    max_layers: int = typer.Option(12, "--max-layers", help="Maximum analysis depth"),
    beam_width: int = typer.Option(8, "--beam-width", help="Analysis beam width"),
    extractors: bool = typer.Option(False, "--extractors", help="Enable generic extractor operations"),
    key: Optional[List[str]] = typer.Option(None, "--key", help="Keyed transform: name=value"),
    live: bool = typer.Option(False, "--live", help="Show the live Rich analysis view"),
) -> None:
    """Identify hash algorithm patterns and display scoring candidates."""
    config = load_config()
    init_db(
        config.paths.database,
        seed_patterns_path="data/patterns/patterns.json",
        seed_corpus_paths=DEFAULT_CORPUS_FILES,
    )

    try:
        with get_db_session() as session:
            if file:
                content = _read_input_file(Path(target))
                from hashvault.core.format_parsers import parse_source_file
                records = parse_source_file(content, format)
                payloads = []
                for rec in records:
                    handoff = _prepare_cli_target(
                        rec.normalized_hash,
                        no_unwrap=no_unwrap,
                        max_layers=max_layers,
                        beam_width=beam_width,
                        extractors=extractors,
                        key_specs=key,
                        live=False,
                        quiet=json,
                    )
                    effective = handoff.primary if handoff else rec.normalized_hash
                    ctx = SourceContext(
                        user_declared_hint=hint,
                        associated_format=rec.detected_format,
                    )
                    res = identify(effective, session, config, ctx)
                    analysis = None
                    if handoff is not None and (
                        handoff.trace.layers_applied or len(handoff.hypotheses) > 1
                    ):
                        analysis = handoff.to_trace_dict()
                    if json:
                        payloads.append(identification_payload(res, analysis))
                    else:
                        render_identification_report(res, analysis=analysis)
                if json:
                    import json as json_lib
                    print(json_lib.dumps(payloads, indent=2))
            else:
                handoff = _prepare_cli_target(
                    target,
                    no_unwrap=no_unwrap,
                    max_layers=max_layers,
                    beam_width=beam_width,
                    extractors=extractors,
                    key_specs=key,
                    live=live and not json,
                    quiet=json,
                )
                effective = handoff.primary if handoff else target
                ctx = SourceContext(user_declared_hint=hint, associated_format=format if format != SourceFormat.AUTO_DETECT else None)
                res = identify(effective, session, config, ctx)
                analysis = None
                if handoff is not None and (
                    handoff.trace.layers_applied or len(handoff.hypotheses) > 1
                ):
                    analysis = handoff.to_trace_dict()
                render_identification_report(res, json_output=json, analysis=analysis)
    except NoCandidateError as e:
        if json:
            import json as json_lib
            print(json_lib.dumps({"resolved": False, "method": "unmatched", "candidates": [], "error": str(e)}, indent=2))
        else:
            console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command("crack")
def crack_cmd(
    target: str = typer.Argument(..., help="Raw hash string or file path if --file is set"),
    file: bool = typer.Option(False, "--file", "-f", help="Treat target as a file path"),
    tool: CrackTool = typer.Option(CrackTool.AUTO, "--tool", help="Cracking engine backend"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Registered wordlist name"),
    rules: Optional[str] = typer.Option(None, "--rules", "-r", help="Registered rule file name"),
    hint: Optional[HashCategory] = typer.Option(None, "--hint", help="Category hint (windows/linux_unix/web_app/...)"),
    pattern: Optional[str] = typer.Option(None, "--pattern", help="Force a specific pattern name (e.g. MD5, NTLM, bcrypt)"),
    format: SourceFormat = typer.Option(SourceFormat.AUTO_DETECT, "--format", help="Dump format hint"),
    silent: bool = typer.Option(False, "--silent", help="Suppress progress output"),
    json: bool = typer.Option(False, "--json", help="Format output as JSON"),
    auto: bool = typer.Option(False, "--auto", help="Automatically select top candidate without prompting"),
    attack_mode: str = typer.Option(
        "dictionary",
        "--attack-mode",
        help="Attack mode: dictionary, mask, or hybrid",
    ),
    mask: Optional[str] = typer.Option(
        None,
        "--mask",
        help="Hashcat mask for mask/hybrid attacks (e.g. '?u?l?l?l?d?d')",
    ),
    no_unwrap: bool = typer.Option(False, "--no-unwrap", help="Disable layered pre-analysis"),
    max_layers: int = typer.Option(12, "--max-layers", help="Maximum analysis depth"),
    beam_width: int = typer.Option(8, "--beam-width", help="Analysis beam width"),
    extractors: bool = typer.Option(False, "--extractors", help="Enable generic extractor operations"),
    key: Optional[List[str]] = typer.Option(None, "--key", help="Keyed transform: name=value"),
    live: bool = typer.Option(False, "--live", help="Show the live Rich analysis view"),
    no_retry: bool = typer.Option(False, "--no-retry", help="Disable retries across analysis branches"),
    max_alternative_attempts: Optional[int] = typer.Option(None, "--max-alternative-attempts", min=0, help="Maximum alternative branches to retry"),
    budget_seconds: Optional[float] = typer.Option(None, "--budget-seconds", min=0.0, help="Total cracking budget in seconds"),
    no_adaptive: bool = typer.Option(False, "--no-adaptive", help="Disable adaptive tool ordering"),
    resolve_trials: bool = typer.Option(
        False,
        "--resolve-trials",
        help="Resolve ambiguous formats by trial-cracking the top candidates",
    ),
    trial_budget: Optional[float] = typer.Option(
        None,
        "--trial-budget",
        min=0.0,
        help="Total seconds for trial disambiguation (implies --resolve-trials)",
    ),
    recipe_out: Optional[Path] = typer.Option(None, "--recipe-out", help="Write the successful analysis recipe as JSON"),
) -> None:
    """Audit password hashes using Hashcat, John the Ripper, or the built-in engine."""
    if attack_mode not in ("dictionary", "mask", "hybrid"):
        console.print("[bold red]Error:[/bold red] --attack-mode must be dictionary, mask, or hybrid.")
        raise typer.Exit(1)
    if attack_mode in ("mask", "hybrid") and not mask:
        console.print("[bold red]Error:[/bold red] --mask is required for mask/hybrid attacks.")
        raise typer.Exit(1)
    config = load_config()
    if resolve_trials or trial_budget is not None:
        # Trial disambiguation is off by default because it spends real
        # cracking time; asking for it explicitly enables it.
        config.strategy.enable_trial_disambiguation = True
    if trial_budget is not None:
        config.strategy.trial_budget_seconds = trial_budget
    init_db(
        config.paths.database,
        seed_patterns_path=str(resolve_resource_path("data/patterns/patterns.json")),
        seed_corpus_paths=DEFAULT_CORPUS_FILES,
    )

    with get_db_session() as session:
        analysis_keys = _parse_cli_keys(key)
        if file:
            content = _read_input_file(Path(target))
            results = process_batch(
                content_or_file=content,
                db_session=session,
                config=config,
                tool=tool,
                wordlist_name=wordlist,
                rule_name=rules,
                hint_category=hint.value if hint else None,
                source_format=format,
                auto_confirm=auto,
                attack_mode=attack_mode,
                mask=mask,
                unwrap=not no_unwrap,
                max_layers=max_layers,
                beam_width=beam_width,
                allow_extractors=extractors,
                analysis_keys=analysis_keys,
                retry_alternatives=False if no_retry else None,
                max_alternative_attempts=max_alternative_attempts,
                budget_seconds=budget_seconds,
                adaptive_tool_selection=False if no_adaptive else None,
            )
        else:
            # --pattern or --hint imply auto-confirm (no need for --auto)
            effective_auto = auto or bool(pattern) or bool(hint)
            process_kwargs = dict(
                raw_hash=target,
                db_session=session,
                config=config,
                tool=tool,
                wordlist_name=wordlist,
                rule_name=rules,
                hint_category=hint.value if hint else None,
                source_format=format,
                auto_confirm=effective_auto,
                forced_pattern=pattern,
                attack_mode=attack_mode,
                mask=mask,
                unwrap=not no_unwrap,
                max_layers=max_layers,
                beam_width=beam_width,
                allow_extractors=extractors,
                analysis_keys=analysis_keys,
                retry_alternatives=False if no_retry else None,
                max_alternative_attempts=max_alternative_attempts,
                budget_seconds=budget_seconds,
                adaptive_tool_selection=False if no_adaptive else None,
            )
            if live and not json:
                from hashvault.analysis.live import RichAnalysisLive

                with RichAnalysisLive(console=console) as view:
                    res = process_single_hash(analysis_listener=view, **process_kwargs)
            else:
                res = process_single_hash(**process_kwargs)
            results = [res]

        render_crack_results(results, json_output=json)

    if recipe_out is not None:
        recipe = next(
            (item.recipe for item in results if item.cracked and item.recipe),
            next((item.recipe for item in results if item.recipe), None),
        )
        if recipe is None:
            console.print(
                "[bold red]Recipe error:[/bold red] no analyzed result to export."
            )
            raise typer.Exit(1)
        write_recipe(recipe_out, recipe)
        if not json:
            console.print(f"[green]Recipe written to[/green] {recipe_out}")


@app.command("check")
def check_cmd(
    target: str = typer.Argument(..., help="Raw hash string or file path if --file is set"),
    file: bool = typer.Option(False, "--file", "-f", help="Treat target as a file path"),
) -> None:
    """Check database cache for cracked records without launching cracking session."""
    config = load_config()
    init_db(
        config.paths.database,
        seed_patterns_path="data/patterns/patterns.json",
        seed_corpus_paths=DEFAULT_CORPUS_FILES,
    )

    with get_db_session() as session:
        if file:
            lines = [l.strip() for l in _read_input_file(Path(target)).splitlines() if l.strip()]
        else:
            lines = [target]

        found_count = 0
        from hashvault.core.normalizer import normalize_hash
        for raw in lines:
            norm, _username = normalize_hash(raw)
            rec = session.query(CrackedHash).filter(CrackedHash.normalized_hash == norm).first()
            if rec:
                found_count += 1
                console.print(f"[bold green]FOUND[/bold green] Hash: [cyan]{norm}[/cyan] -> Plaintext: [white]{rec.plaintext}[/white]")
            else:
                console.print(f"[bold red]MISSING[/bold red] Hash: {norm}")

        console.print(f"\n[bold blue]Cache Check Summary:[/bold blue] Found {found_count}/{len(lines)} records in local DB.")


@app.command("analyze")
def analyze_cmd(
    target: str = typer.Argument(default="", help="Raw hash string, encoded payload, or leave empty with --list-ops"),
    hint: Optional[HashCategory] = typer.Option(None, "--hint", help="Category hint (windows/linux_unix/web_app/...)"),
    pattern: Optional[str] = typer.Option(None, "--pattern", help="Force a specific pattern name (e.g. MD5, NTLM, bcrypt)"),
    format: SourceFormat = typer.Option(SourceFormat.AUTO_DETECT, "--format", help="Dump format hint"),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
    max_layers: int = typer.Option(12, "--max-layers", help="Maximum analysis depth"),
    beam_width: int = typer.Option(8, "--beam-width", help="Analysis beam width"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show full layer-by-layer report"),
    extractors: bool = typer.Option(False, "--extractors", help="Enable Extractors category (IP, email, URL, MAC)"),
    list_ops: bool = typer.Option(False, "--list-ops", help="List all registered CyberChef operations and exit"),
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter --list-ops by category"),
    file: bool = typer.Option(False, "--file", "-f", help="Treat target as a file path to analyse"),
    live: bool = typer.Option(False, "--live", help="Show the live Rich analysis view"),
    key: Optional[List[str]] = typer.Option(None, "--key", help="Keyed transform: name=value"),
    crack: bool = typer.Option(False, "--crack", help="Crack the finalized hash after analysis"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Wordlist for --crack"),
    tool: CrackTool = typer.Option(CrackTool.AUTO, "--tool", help="Engine for --crack"),
    recipe_out: Optional[Path] = typer.Option(None, "--recipe-out", help="Write the analysis recipe as JSON"),
) -> None:
    """Deep-analyse any input: unwrap encoding layers (CyberChef-style), then identify the hash."""
    from hashvault.analysis.analyzer import list_operations
    from rich.table import Table

    # --list-ops: show all operations grouped by category and exit
    if list_ops:
        ops = list_operations(category)
        for cat_name, op_list in ops.items():
            tbl = Table(
                title=f"[bold cyan]{cat_name}[/bold cyan]",
                box=box.SIMPLE_HEAD,
                show_header=True,
            )
            tbl.add_column("Operation", style="bold green", min_width=20)
            tbl.add_column("Description", style="white")
            for op in op_list:
                tbl.add_row(op["name"], op["description"])
            console.print(tbl)
        return

    if not target:
        console.print("[red]Error:[/red] provide a target string or use --list-ops.")
        raise typer.Exit(1)

    if file:
        path = Path(target)
        if not path.exists():
            console.print(f"[bold red]Error:[/bold red] File not found: {target}")
            raise typer.Exit(1)
        target = _read_input_file(path)

    analysis_keys = _parse_cli_keys(key)
    config = load_config()
    init_db(
        config.paths.database,
        seed_patterns_path="data/patterns/patterns.json",
        seed_corpus_paths=DEFAULT_CORPUS_FILES,
    )

    with get_db_session() as session:
        ctx = SourceContext(
            user_declared_hint=hint,
            associated_format=format if format != SourceFormat.AUTO_DETECT else None,
        )
        try:
            analysis_kwargs = dict(
                max_layers=max_layers,
                beam_width=beam_width,
                allow_extractors=extractors,
                keys=analysis_keys,
            )
            if live and not json_out:
                from hashvault.analysis.live import RichAnalysisLive

                with RichAnalysisLive(console=console) as view:
                    res = analyze_input(
                        target, session, config, ctx,
                        listener=view,
                        **analysis_kwargs,
                    )
            else:
                res = analyze_input(
                    target, session, config, ctx,
                    **analysis_kwargs,
                )
        except NoCandidateError:
            if json_out:
                import json as _json
                print(_json.dumps({"resolved": False, "error": "No matching pattern candidate found"}, indent=2))
            else:
                console.print("[bold red]No matching pattern candidate found for the finalized input.[/bold red]")
            raise typer.Exit(1)

        analysis_recipe = recipe_to_dict(res.trace)
        if recipe_out is not None:
            write_recipe(recipe_out, analysis_recipe)
            if not json_out:
                console.print(f"[green]Recipe written to[/green] {recipe_out}")

        crack_result = None
        if crack:
            chosen = getattr(res.identification, "chosen_pattern", None)
            crack_result = process_single_hash(
                raw_hash=res.finalized_input,
                db_session=session,
                config=config,
                tool=tool,
                wordlist_name=wordlist,
                hint_category=hint.value if hint is not None else None,
                source_format=format,
                auto_confirm=True,
                forced_pattern=pattern or getattr(chosen, "name", None),
                unwrap=False,
            )

        if json_out:
            import json as _json
            d = res.to_dict()
            d["recipe"] = analysis_recipe
            # If --pattern forced, override chosen_pattern in JSON too
            if pattern:
                d["forced_pattern"] = pattern
            if crack_result is not None:
                d["crack"] = {
                    "cracked": crack_result.cracked,
                    "plaintext": crack_result.plaintext,
                    "pattern": crack_result.candidate.pattern.name if crack_result.candidate else None,
                    "tool_used": crack_result.tool_used,
                    "cached": crack_result.cached,
                    "error_message": crack_result.error_message,
                }
            print(_json.dumps(d, indent=2))
            return

        if verbose:
            console.print(res.verbose())
            if crack_result is not None:
                render_crack_results([crack_result])
            return

        console.print("[bold blue]\u2550\u2550\u2550\u2550\u2550\u2550\u2550 Deep Analysis Result \u2550\u2550\u2550\u2550\u2550\u2550\u2550[/bold blue]")
        console.print(f"Raw input      : [white]{res.raw_input[:120]}[/white]")
        console.print(f"Unwrap chain   : [cyan]{res.unwrap_chain or '(none \u2014 already bare)'}[/cyan]")
        console.print(f"Layers applied : {res.trace.layers_applied}")
        for layer in res.trace.layers:
            console.print(
                f"  [dim]({layer.depth})[/dim] [[{layer.category}]] [bold]{layer.operation}[/bold] "
                f"{layer.input_text[:40]!r} \u2192 {layer.output_text[:40]!r} "
                f"[dim]conf={layer.confidence:.0%}[/dim]"
            )
        console.print(f"Finalized hash : [green]{res.finalized_input}[/green]")

        idn = res.identification
        chosen = getattr(idn, "chosen_pattern", None)
        candidates = getattr(idn, "candidates", []) or []

        # --pattern override: find the named pattern in candidates
        if pattern and candidates:
            forced = next(
                (c for c in candidates if getattr(c.pattern, "name", "").lower() == pattern.lower()),
                None,
            )
            if forced:
                chosen = forced.pattern
                console.print(f"Pattern forced : [bold yellow]{pattern}[/bold yellow] (--pattern override)")
            else:
                console.print(f"[yellow]Warning: pattern '{pattern}' not in candidates — showing all[/yellow]")

        if chosen:
            hm = getattr(chosen, 'hashcat_mode', None)
            jf = getattr(chosen, 'john_format', None)
            conf_score = getattr(idn, 'confidence_score', None)
            console.print(
                f"Best pattern   : [bold green]{chosen.name}[/bold green] "
                f"(hashcat=[yellow]-m {hm}[/yellow], john=[yellow]{jf or 'N/A'}[/yellow])"
            )
            if conf_score is not None:
                console.print(f"Confidence     : {conf_score:.0%}")
        else:
            console.print(f"[yellow]\u26a0  Ambiguous — {len(candidates)} candidates:[/yellow]")

        console.print("[bold cyan]Top candidates:[/bold cyan]")
        for cand in candidates[:8]:
            p = cand.pattern
            name = getattr(p, 'name', '?')
            hm   = getattr(p, 'hashcat_mode', None)
            jf   = getattr(p, 'john_format', None)
            hm_s = f"  hashcat [yellow]-m {hm}[/yellow]" if hm is not None else ""
            jf_s = f"  john [yellow]--format={jf}[/yellow]" if jf else ""
            console.print(f"  [dim]{cand.confidence:4.0%}[/dim]  [bold]{name}[/bold]{hm_s}{jf_s}")

        alternatives = [
            branch for branch in res.branches
            if branch.trace.finalized_input != res.finalized_input
        ]
        if alternatives:
            console.print("[bold cyan]Alternative hypotheses:[/bold cyan]")
            for branch in alternatives[:5]:
                branch_candidates = getattr(branch.identification, "candidates", []) or []
                top = branch_candidates[0] if branch_candidates else None
                pattern_name = getattr(getattr(top, "pattern", None), "name", "unidentified")
                confidence = f"{top.confidence:4.0%}  " if top else ""
                preview = branch.trace.finalized_input[:56].replace("\n", " ")
                console.print(
                    f"  {confidence}[bold]{pattern_name}[/bold] "
                    f"[dim]{branch.trace.describe()} -> {preview}[/dim]"
                )

        if crack_result is not None:
            render_crack_results([crack_result])


@app.command("parameters")
def parameters_cmd(
    target: str = typer.Argument(default="", help="Hash string, or file path with --file"),
    file: bool = typer.Option(False, "--file", "-f", help="Treat target as a file of hashes"),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Inspect encoded hash parameters and estimate offline work factor."""
    if not target:
        console.print("[bold red]Error:[/bold red] provide a hash or --file.")
        raise typer.Exit(1)
    if file:
        values = [
            line.strip()
            for line in _read_input_file(Path(target)).splitlines()
            if line.strip()
        ]
    else:
        values = [target]
    reports = [analyze_parameters(value) for value in values]
    if json_out:
        print(json.dumps([report.to_dict() for report in reports], indent=2))
        return
    table = Table(title="Hash Parameter Analysis", header_style="bold blue")
    table.add_column("Hash", style="dim", max_width=32, no_wrap=True)
    table.add_column("Format", style="cyan", no_wrap=True)
    table.add_column("Work factor", style="green", justify="right")
    table.add_column("Cost", style="yellow")
    table.add_column("Slow", justify="center")
    table.add_column("Parameters", max_width=44)
    for value, report in zip(values, reports):
        preview = value if len(value) <= 32 else value[:18] + "..." + value[-10:]
        params = ", ".join(
            f"{key}={val}" for key, val in report.parameters.items()
        )
        table.add_row(
            preview,
            report.format,
            f"{report.work_factor:,.0f}" if report.work_factor is not None else "-",
            report.cost_class,
            "yes" if report.is_slow else "no",
            params or "-",
        )
    console.print(table)


@app.command("mutate")
def mutate_cmd(
    context: Optional[Path] = typer.Argument(None, help="JSON/YAML context profile"),
    term: Optional[List[str]] = typer.Option(None, "--term", help="Extra seed term (repeatable)"),
    context_json: Optional[str] = typer.Option(None, "--context-json", help="Inline context JSON object"),
    history: bool = typer.Option(False, "--history", help="Use cracked history as local seeds"),
    enrich: Optional[List[Path]] = typer.Option(None, "--enrich", help="Local wordlist for enrichment"),
    llm: bool = typer.Option(False, "--llm", help="Use configured local Ollama seeder"),
    limit: Optional[int] = typer.Option(None, "--limit", min=0, help="Maximum candidates"),
    language: Optional[str] = typer.Option(None, "--language", help="Arabic/Arabizi mode: auto, arabic, arabizi, both, off"),
    year: Optional[List[str]] = typer.Option(None, "--year", help="Extra year (repeatable)"),
    no_years: bool = typer.Option(False, "--no-years", help="Disable year mutations"),
    wordlist_out: Optional[Path] = typer.Option(None, "--wordlist-out", help="Write candidates to a wordlist"),
    rules_out: Optional[Path] = typer.Option(None, "--rules-out", help="Write generated Hashcat rules"),
    json_out: bool = typer.Option(False, "--json", help="Output the full mutation plan as JSON"),
) -> None:
    """Generate targeted, authorized password-audit candidates from local context."""
    try:
        profile = ContextProfile.from_file(context) if context else ContextProfile()
        if context_json:
            inline = json.loads(context_json)
            if not isinstance(inline, dict):
                raise ValueError("--context-json must be a JSON object")
            profile = ContextProfile.from_mapping({**profile.to_dict(), **inline})
    except Exception as exc:
        console.print(f"[bold red]Invalid context:[/bold red] {exc}")
        raise typer.Exit(1)
    if term:
        profile = profile.merged(keywords=[*profile.keywords, *term])

    config = load_config()
    if history:
        init_db(
            config.paths.database,
            seed_patterns_path="data/patterns/patterns.json",
            seed_corpus_paths=DEFAULT_CORPUS_FILES,
        )
    session_context = get_db_session() if history else nullcontext(None)
    with session_context as session:
        result = build_mutation(
            profile,
            session=session,
            config=config,
            use_history=history,
            enrich_paths=enrich or (),
            use_llm=llm,
            limit=limit,
            language=language,
            years=year or (),
            include_years=not no_years,
        )

    if wordlist_out is not None:
        wordlist_out.parent.mkdir(parents=True, exist_ok=True)
        wordlist_out.write_text(
            "\n".join(result.candidates) + ("\n" if result.candidates else ""),
            encoding="utf-8",
        )
    if rules_out is not None:
        write_rule_file(rules_out, result.rules)

    if json_out:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return

    summary = result.metadata
    console.print(
        f"[bold blue]Mutation plan:[/bold blue] {summary.get('seed_count', 0)} seeds, "
        f"{summary.get('candidate_count', 0)} candidates, "
        f"{len(result.rules)} rules"
    )
    if summary.get("enrichment_sources"):
        console.print(f"[dim]Sources: {', '.join(summary['enrichment_sources'])}[/dim]")
    for warning in summary.get("warnings") or []:
        console.print(f"[yellow]Warning:[/yellow] {warning}")
    table = Table(title="Generated Candidates", header_style="bold green")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Candidate", style="white")
    for index, candidate in enumerate(result.candidates[:100], 1):
        table.add_row(str(index), candidate)
    console.print(table)
    if len(result.candidates) > 100:
        console.print(f"[dim]Showing 100 of {len(result.candidates)} candidates.[/dim]")
    if wordlist_out is not None:
        console.print(f"[green]Wordlist written to[/green] {wordlist_out}")
    if rules_out is not None:
        console.print(f"[green]Rules written to[/green] {rules_out}")


@app.command("replay")
def replay_cmd(
    recipe_file: Path = typer.Argument(..., help="Recipe JSON exported by crack --recipe-out"),
    input_value: Optional[str] = typer.Option(None, "--input", help="Override the recipe raw input"),
    key: Optional[List[str]] = typer.Option(None, "--key", help="Keyed transform: name=value"),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Replay a saved analysis recipe deterministically."""
    try:
        recipe = load_recipe(recipe_file)
        keys = _parse_cli_keys(key)
        raw_input = input_value if input_value is not None else recipe["raw_input"]
        trace = replay_recipe(raw_input, recipe, keys=keys)
    except (OSError, ValueError, RecipeReplayError) as exc:
        console.print(f"[bold red]Replay error:[/bold red] {exc}")
        raise typer.Exit(1)
    payload = recipe_to_dict(trace)
    payload["expected_finalized_input"] = recipe["finalized_input"]
    payload["verified"] = trace.finalized_input == recipe["finalized_input"]
    if json_out:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    table = Table(title=f"Recipe Replay: {recipe_file.name}", header_style="bold cyan")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Operation", style="cyan")
    table.add_column("Input", max_width=34)
    table.add_column("Output", max_width=34)
    for layer in trace.layers:
        table.add_row(
            str(layer.depth),
            layer.operation,
            layer.input_text[:34],
            layer.output_text[:34],
        )
    console.print(table)
    console.print(f"[bold]Finalized:[/bold] [green]{trace.finalized_input}[/green]")
    console.print(
        f"[bold]Verified:[/bold] {'yes' if payload['verified'] else 'no'}"
    )


@app.command("benchmark-layers")
def benchmark_layers_cmd(
    corpus: Optional[Path] = typer.Option(None, "--corpus", help="Layer vector JSON path"),
    limit: Optional[int] = typer.Option(None, "--limit", min=0, help="Maximum vectors"),
    crack: bool = typer.Option(False, "--crack", help="Crack each layered plaintext with built-in engine"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write full JSON report"),
    show: int = typer.Option(25, "--show", min=1, help="Rows to display"),
) -> None:
    """Benchmark deterministic layered-recipe discovery and optional cracking."""
    config = load_config()
    init_db(
        config.paths.database,
        seed_patterns_path="data/patterns/patterns.json",
        seed_corpus_paths=DEFAULT_CORPUS_FILES,
    )
    vectors = load_layer_vectors(corpus) if corpus else load_layer_vectors()
    if limit is not None:
        vectors = vectors[:limit]
    with get_db_session() as session:
        report = benchmark_layers(vectors, session, config, crack=crack)
    payload = report.to_dict()
    if json_out is not None:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    table = Table(title="Layer Recipe Benchmark", header_style="bold cyan")
    table.add_column("Case", style="cyan", no_wrap=True)
    table.add_column("Expected", style="dim")
    table.add_column("Actual", style="yellow")
    table.add_column("Pattern", style="green")
    table.add_column("Status", justify="center")
    table.add_column("Crack", justify="center")
    for outcome in report.outcomes[:show]:
        crack_status = (
            "-" if outcome.cracked is None else ("yes" if outcome.cracked else "no")
        )
        table.add_row(
            outcome.id,
            " -> ".join(outcome.expected_operations) or "(bare)",
            " -> ".join(outcome.chain) or "(bare)",
            outcome.pattern or "-",
            "[green]PASS[/green]" if outcome.passed else "[red]FAIL[/red]",
            crack_status,
        )
    console.print(table)
    summary = payload["summary"]
    console.print(
        f"[bold]{summary['passed']}/{summary['total']} passed[/bold], "
        f"chain {summary['chain_ok']}/{summary['total']}, "
        f"hash {summary['hash_ok']}/{summary['total']}, "
        f"mode {summary['mode_ok']}/{summary['total']}"
    )
    if json_out is not None:
        console.print(f"[green]Report written to[/green] {json_out}")
    if summary["failed"]:
        raise typer.Exit(1)


@strategies_app.command("stats")
def strategies_stats_cmd(
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Show adaptive tool/pattern success statistics."""
    config = load_config()
    init_db(
        config.paths.database,
        seed_patterns_path="data/patterns/patterns.json",
        seed_corpus_paths=DEFAULT_CORPUS_FILES,
    )
    with get_db_session() as session:
        rows = list_strategy_stats(session)
    if json_out:
        print(json.dumps([row.to_dict() for row in rows], indent=2))
        return
    table = Table(title="Adaptive Strategy Statistics", header_style="bold magenta")
    table.add_column("Pattern", style="cyan")
    table.add_column("Tool", style="blue")
    table.add_column("Mode", style="dim")
    table.add_column("Attempts", justify="right")
    table.add_column("Successes", justify="right", style="green")
    table.add_column("Rate", justify="right")
    table.add_column("Avg seconds", justify="right")
    table.add_column("Score", justify="right", style="yellow")
    for row in rows:
        table.add_row(
            row.pattern_name,
            row.tool,
            row.attack_mode,
            str(row.attempts),
            str(row.successes),
            f"{row.success_rate:.1%}",
            f"{row.average_seconds:.2f}",
            f"{row.score:.3f}",
        )
    console.print(table)


@strategies_app.command("reset")
def strategies_reset_cmd(
    yes: bool = typer.Option(False, "--yes", help="Confirm deleting strategy feedback"),
) -> None:
    """Delete all adaptive strategy feedback."""
    if not yes:
        console.print("[yellow]Refusing to reset without --yes.[/yellow]")
        raise typer.Exit(1)
    config = load_config()
    init_db(config.paths.database)
    with get_db_session() as session:
        removed = reset_strategy_stats(session)
    console.print(f"[green]Removed {removed} strategy rows.[/green]")


@app.command("setup")
def setup_cmd(
    fetch_resources: bool = typer.Option(
        True, help="Run fetch_resources automatically if resources are missing"
    )
) -> None:
    """Initialize SQLite WAL database tables, seed pattern rules, and index wordlists/rules."""
    config = load_config()
    data_dir = Path(config.paths.wordlist_dir).parent
    hashcat_rules_dir = data_dir / "rules" / "hashcat-rules"

    if fetch_resources and not hashcat_rules_dir.exists():
        console.print("[yellow]Hashcat rules not found — executing resource fetcher script now...[/yellow]")
        project_root = Path(__file__).resolve().parent.parent
        script_py = project_root / "scripts" / "fetch_resources.py"
        if script_py.exists():
            subprocess.run(
                [sys.executable, str(script_py)],
                shell=False,
                check=True,
                cwd=str(project_root),
            )

    console.print("[yellow]Initializing HashVault SQLite database, patterns, and benchmark corpus...[/yellow]")
    init_db(
        config.paths.database,
        seed_patterns_path=str(resolve_resource_path("data/patterns/patterns.json")),
        seed_corpus_paths=DEFAULT_CORPUS_FILES,
    )

    from hashvault.core.wordlist_manager import import_rule
    with get_db_session() as session:
        wordlist_dir = Path(config.paths.wordlist_dir)
        if wordlist_dir.exists():
            for wf in wordlist_dir.glob("**/*.txt"):
                mgr_import_wordlist(wf, wf.name, session, config)

        rules_dir = Path(config.paths.rules_dir)
        if rules_dir.exists():
            for rf in rules_dir.glob("**/*.rule"):
                import_rule(rf, rf.name, session, config)

    console.print("[bold green]Setup completed successfully.[/bold green]")


@app.command("fetch-resources")
def fetch_resources_cmd() -> None:
    """Fetch default wordlists and rule files from remote repository sources."""
    console.print("[yellow]Fetching HashVault wordlists and rule resources...[/yellow]")
    project_root = Path(__file__).resolve().parent.parent
    script_py = project_root / "scripts" / "fetch_resources.py"
    if script_py.exists():
        subprocess.run(
            [sys.executable, str(script_py)],
            check=False,
            shell=False,
            cwd=str(project_root),
        )
    else:
        console.print(f"[yellow]Resource fetcher not found at {script_py}[/yellow]")
    setup_cmd()


@app.command("import-patterns")
def import_patterns_cmd(
    path: str = typer.Argument(..., help="Path to patterns JSON file")
) -> None:
    """Import or update hash pattern definitions from a JSON dataset file."""
    config = load_config()
    engine = init_db(config.paths.database)
    from hashvault.core.database import get_session_factory
    factory = get_session_factory(engine)
    count = seed_patterns(factory, path)
    console.print(f"[bold green]Successfully imported {count} new patterns.[/bold green]")


@app.command("import-wordlist")
def import_wordlist_cmd(
    path: str = typer.Argument(..., help="Path to wordlist dictionary file"),
    name: Optional[str] = typer.Option(None, "--name", help="Custom alias name for wordlist"),
) -> None:
    """Import and index an external wordlist dictionary file."""
    config = load_config()
    init_db(config.paths.database)

    with get_db_session() as session:
        dto = mgr_import_wordlist(path, name, session, config)
        console.print(f"[bold green]Wordlist '{dto.name}' registered successfully ({dto.line_count} lines).[/bold green]")


@app.command("export-db")
def export_db_cmd(
    format: OutputFormat = typer.Option(OutputFormat.JSON, "--format", help="Export format (json/csv)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Export cracked hash database records."""
    config = load_config()
    init_db(config.paths.database)

    with get_db_session() as session:
        records = session.query(CrackedHash).all()
        data = [
            {
                "id": r.id,
                "normalized_hash": r.normalized_hash,
                "plaintext": r.plaintext,
                "username": r.username,
                "tool_used": r.tool_used,
                "cracked_at": str(r.cracked_at),
            }
            for r in records
        ]

        if format == OutputFormat.JSON:
            dump_str = json.dumps(data, indent=2)
            if output:
                Path(output).write_text(dump_str, encoding="utf-8")
                console.print(f"[bold green]Exported {len(records)} entries to {output}[/bold green]")
            else:
                print(dump_str)


@app.command("stats")
def stats_cmd() -> None:
    """Display HashVault database, analysis log, and session statistics."""
    config = load_config()
    init_db(config.paths.database)

    with get_db_session() as session:
        from hashvault.models.orm import AnalysisLog
        import json as json_lib

        patterns_count = session.query(Pattern).count()
        cracked_count = session.query(CrackedHash).count()
        sessions_count = session.query(CrackSession).count()
        attempts_count = session.query(CrackAttempt).count()
        strategy_rows = session.query(StrategyStat).count()
        wordlists_count = len(list_wordlists(session))

        # Analysis log stats
        total_analyses = 0
        resolved_count = 0
        top_ops: dict = {}
        try:
            total_analyses = session.query(AnalysisLog).count()
            resolved_count = session.query(AnalysisLog).filter(AnalysisLog.resolved == True).count()
            # Count unwrap operations from layers_json
            logs_with_layers = session.query(AnalysisLog).filter(
                AnalysisLog.layers_applied > 0
            ).limit(200).all()
            for log in logs_with_layers:
                if log.layers_json:
                    try:
                        layers = json_lib.loads(log.layers_json)
                        for layer in layers:
                            op = layer.get("operation", "?")
                            top_ops[op] = top_ops.get(op, 0) + 1
                    except Exception:
                        pass
        except Exception:
            pass

        console.print("[bold blue]=== HashVault Statistics ===[/bold blue]")
        console.print(f"Registered Hash Patterns   : [cyan]{patterns_count}[/cyan]")
        console.print(f"Cracked Hash Records       : [green]{cracked_count}[/green]")
        console.print(f"Total Cracking Sessions    : [magenta]{sessions_count}[/magenta]")
        console.print(f"Recorded Crack Attempts    : [cyan]{attempts_count}[/cyan]")
        console.print(f"Adaptive Strategy Rows     : [cyan]{strategy_rows}[/cyan]")
        console.print(f"Registered Wordlists       : [yellow]{wordlists_count}[/yellow]")

        if total_analyses > 0:
            resolution_rate = (resolved_count / total_analyses * 100) if total_analyses else 0
            console.print()
            console.print("[bold blue]=== Analysis Pipeline Stats ===[/bold blue]")
            console.print(f"Total Deep Analyses        : [cyan]{total_analyses}[/cyan]")
            console.print(f"Resolved (confident)       : [green]{resolved_count}[/green] ({resolution_rate:.1f}%)")
            console.print(f"Ambiguous                  : [yellow]{total_analyses - resolved_count}[/yellow]")
            if top_ops:
                top_sorted = sorted(top_ops.items(), key=lambda x: x[1], reverse=True)[:5]
                console.print(f"Top Unwrap Operations      : {', '.join(f'{op}({n})' for op, n in top_sorted)}")

        console.print()
        console.print("[dim]Use `hashvault insights` for trends and recommendations.[/dim]")


@app.command("doctor")
def doctor_cmd(
    json_out: bool = typer.Option(False, "--json", help="Output diagnostics as JSON"),
    probe: bool = typer.Option(
        False,
        "--probe",
        help="Run hashcat backend detection (no external network access)",
    ),
) -> None:
    """Check database, data, engines, paths, and optional integrations."""
    config = load_config()
    report: DoctorReport
    try:
        init_db(config.paths.database)
        with get_db_session() as session:
            report = run_doctor(config, session, probe=probe)
    except Exception as exc:
        report = run_doctor(config, None, db_error=str(exc))

    if json_out:
        print(json.dumps(report.to_dict(), indent=2))
        if not report.ok:
            raise typer.Exit(1)
        return

    colors = {OK: "green", WARN: "yellow", FAIL: "red"}
    table = Table(title="HashVault Doctor", header_style="bold blue")
    table.add_column("Section", style="magenta", no_wrap=True)
    table.add_column("Check", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Details", style="white", max_width=72)
    for check in report.checks:
        table.add_row(
            check.section,
            check.name,
            f"[{colors.get(check.status, 'white')}]{check.status.upper()}[/]",
            check.detail,
        )
    console.print(table)
    summary = report.summary()
    console.print(
        f"[bold]Doctor:[/bold] {summary['ok']} ok, "
        f"{summary['warnings']} warning(s), {summary['failures']} failure(s)"
    )
    if not report.ok:
        raise typer.Exit(1)


@app.command("audit")
def audit_cmd(
    pattern: Optional[str] = typer.Option(
        None,
        "--pattern",
        help="Only audit records for this pattern name",
    ),
    limit: Optional[int] = typer.Option(
        None,
        "--limit",
        min=0,
        help="Maximum records to verify (0 = all)",
    ),
    json_out: bool = typer.Option(
        False,
        "--json",
        help="Output audit results as JSON",
    ),
) -> None:
    """Re-verify stored cracked plaintexts against their canonical hashes."""
    config = load_config()
    init_db(config.paths.database)
    with get_db_session() as session:
        report = verify_cracked_hashes(
            session,
            pattern_name=pattern,
            limit=limit,
        )

    if json_out:
        print(json.dumps(report.to_dict(), indent=2))
        if not report.ok:
            raise typer.Exit(1)
        return

    colors = {
        VERIFIED: "green",
        MISMATCH: "red",
        UNSUPPORTED: "yellow",
        ERROR: "red",
    }
    table = Table(title="Cracked Record Integrity Audit", header_style="bold blue")
    table.add_column("ID", justify="right", style="dim")
    table.add_column("Hash", style="cyan", no_wrap=True)
    table.add_column("Pattern", style="magenta", no_wrap=True)
    table.add_column("Tool", style="blue", no_wrap=True)
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Details", style="white", max_width=48)
    for item in report.results:
        table.add_row(
            str(item.record_id),
            item.hash_preview,
            item.pattern,
            item.tool,
            f"[{colors.get(item.status, 'white')}]{item.status.upper()}[/]",
            item.detail or "-",
        )
    if report.results:
        console.print(table)
    else:
        console.print("[yellow]No cracked records matched the audit query.[/yellow]")

    counts = report.counts()
    console.print(
        f"[bold]Audit:[/bold] {counts['verified']} verified, "
        f"{counts['mismatch']} mismatch, {counts['unsupported']} unsupported, "
        f"{counts['errors']} error(s)"
    )
    if not report.ok:
        raise typer.Exit(1)


@app.command("insights")
def insights_cmd(
    days: Optional[int] = typer.Option(
        None,
        "--days",
        min=1,
        help="Only include activity from the last N days",
    ),
    json_out: bool = typer.Option(False, "--json", help="Output insights as JSON"),
) -> None:
    """Summarize local analysis, cracking, and adaptive strategy activity."""
    config = load_config()
    init_db(config.paths.database)
    with get_db_session() as session:
        report = run_insights(session, days=days)

    if json_out:
        print(json.dumps(report.to_dict(), indent=2))
        return

    analyses = report.analyses
    cracking = report.cracking
    cracked = report.cracked
    strategies = report.strategies

    table = Table(title="HashVault Audit Insights", header_style="bold blue")
    table.add_column("Area", style="magenta", no_wrap=True)
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_row("Analysis", "Total", str(analyses["total"]))
    table.add_row(
        "Analysis",
        "Resolved",
        f"{analyses['resolved']} ({analyses['resolution_rate']:.1%})",
    )
    table.add_row("Analysis", "Ambiguous", str(analyses["ambiguous"]))
    if analyses["average_confidence"] is not None:
        table.add_row(
            "Analysis",
            "Average confidence",
            f"{analyses['average_confidence']:.1%}",
        )
    table.add_row("Cracking", "Attempts", str(cracking["attempts"]))
    table.add_row(
        "Cracking",
        "Success rate",
        f"{cracking['success_rate']:.1%}",
    )
    table.add_row("Cracking", "Cached attempts", str(cracking["cached"]))
    table.add_row("Cracking", "Attempt time", f"{cracking['total_seconds']:.2f}s")
    table.add_row("Cracked", "Records", str(cracked["records"]))
    table.add_row("Cracked", "Unique hashes", str(cracked["unique_hashes"]))
    table.add_row("Strategy", "Feedback rows", str(strategies["rows"]))
    console.print(table)

    if analyses["top_operations"]:
        console.print(
            "[bold]Top unwrap operations:[/bold] "
            + ", ".join(
                f"{item['operation']} ({item['count']})"
                for item in analyses["top_operations"]
            )
        )
    if analyses["top_patterns"]:
        console.print(
            "[bold]Top resolved patterns:[/bold] "
            + ", ".join(
                f"{item['pattern']} ({item['count']})"
                for item in analyses["top_patterns"]
            )
        )
    if cracking["tools"]:
        console.print(
            "[bold]Top cracking tools:[/bold] "
            + ", ".join(
                f"{item['tool']} ({item['attempts']}, "
                f"{item['successes']} ok)"
                for item in cracking["tools"]
            )
        )
    if cracking["patterns"]:
        console.print(
            "[bold]Top attempted patterns:[/bold] "
            + ", ".join(
                f"{item['pattern']} ({item['attempts']}, "
                f"{item['successes']} ok)"
                for item in cracking["patterns"]
            )
        )
    if cracked["tools"]:
        console.print(
            "[bold]Top success tools:[/bold] "
            + ", ".join(
                f"{item['tool']} ({item['count']})"
                for item in cracked["tools"]
            )
        )
    if strategies["top"]:
        console.print(
            "[bold]Adaptive leaders:[/bold] "
            + ", ".join(
                f"{item['pattern']}/{item['tool']} "
                f"({item['success_rate']:.0%})"
                for item in strategies["top"]
            )
        )

    if report.recommendations:
        console.print("[bold yellow]Recommendations:[/bold yellow]")
        for recommendation in report.recommendations:
            console.print(f"  [dim]- {recommendation}[/dim]")


@app.command("sessions")
def sessions_cmd(
    status: Optional[SessionStatus] = typer.Option(None, "--status", help="Filter by session status"),
    json: bool = typer.Option(False, "--json", help="Format output as JSON"),
    purge: bool = typer.Option(
        False, "--purge", help="Delete session working directories from disk"
    ),
    older_than_days: int = typer.Option(
        0, "--older-than-days", help="Only purge directories older than N days"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the purge confirmation"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="List what --purge would delete"
    ),
) -> None:
    """List isolated cracking sessions, or purge their working directories."""
    config = load_config()

    if purge:
        root = Path(config.paths.sessions_dir)
        if not root.is_dir():
            console.print("[yellow]No sessions directory found.[/yellow]")
            raise typer.Exit(0)

        min_age = older_than_days * 86400 if older_than_days > 0 else 0
        # Dry run first so the user sees exactly what a real purge removes.
        targets = purge_session_dirs(root, min_age_seconds=min_age, dry_run=True)
        if not targets:
            console.print("[green]Nothing to purge.[/green]")
            raise typer.Exit(0)

        if dry_run:
            for entry in targets:
                console.print(f"[dim]{entry}[/dim]")
            console.print(
                f"[bold]{len(targets)} session directories would be removed.[/bold]"
            )
            raise typer.Exit(0)

        if not yes:
            confirmed = typer.confirm(
                f"Delete {len(targets)} session directories under {root}?"
            )
            if not confirmed:
                console.print("[yellow]Aborted.[/yellow]")
                raise typer.Exit(1)

        removed = purge_session_dirs(root, min_age_seconds=min_age)
        console.print(f"[bold green]Removed {len(removed)} session directories.[/bold green]")
        raise typer.Exit(0)

    init_db(config.paths.database)

    with get_db_session() as session:
        query = session.query(CrackSession)
        if status:
            query = query.filter(CrackSession.status == status)

        records = query.all()
        schemas = [CrackSessionSchema.model_validate(r) for r in records]
        render_sessions_report(schemas, json_output=json)


# ---------------------------------------------------------------------------
# Catalogue quality, calibration, planning, and evidence
# ---------------------------------------------------------------------------


@app.command("patterns-audit")
def patterns_audit_cmd(
    json_output: bool = typer.Option(False, "--json", help="Machine-readable report"),
    strict: bool = typer.Option(
        False, "--strict", help="Exit non-zero when any error-level issue is found"
    ),
    include_known: bool = typer.Option(
        False,
        "--include-known",
        help="Also list defects documented in audit_allowlist.json",
    ),
) -> None:
    """Audit the hash pattern catalogue for regex and ranking defects."""
    from hashvault.core.pattern_audit import audit_patterns, render_audit_report

    config = load_config()
    init_db(config.paths.database)
    data_dir = Path(config.paths.wordlist_dir).parent
    patterns_file = data_dir / "patterns" / "patterns.json"

    with get_db_session() as session:
        patterns = session.query(Pattern).all()

    report = audit_patterns(
        patterns,
        patterns_file=patterns_file,
        allow_known=not include_known,
    )

    if json_output:
        console.print_json(data=report.to_dict())
    else:
        for line in render_audit_report(report):
            console.print(line)

    if strict and not report.ok:
        raise typer.Exit(1)


@app.command("calibrate")
def calibrate_cmd(
    json_output: bool = typer.Option(False, "--json", help="Machine-readable report"),
    out: Optional[Path] = typer.Option(
        None, "--out", help="Write suggested confidence weights to this JSON file"
    ),
    min_samples: int = typer.Option(
        5, "--min-samples", help="Minimum top-1 observations before re-weighting"
    ),
    force_weights: bool = typer.Option(
        False, "--force-weights", help="Re-weight patterns even with few samples"
    ),
    limit: int = typer.Option(
        0, "--limit", help="Evaluate at most N corpus entries (0 = all)"
    ),
) -> None:
    """Measure identification confidence against corpus ground truth."""
    from hashvault.core.calibration import (
        calibrate,
        suggested_weights,
        summary_lines as calibration_lines,
    )
    from hashvault.corpus import evaluate_identification, load_default_corpora
    from hashvault.core.identifier import get_identifier

    config = load_config()
    # Measure against the shipped weights, never against this command's own
    # previous output: feeding calibration back into itself drifted the weights
    # on every run and dropped patterns out of the suggested set.
    init_db(
        config.paths.database,
        seed_patterns_path=str(
            resolve_resource_path("data/patterns/patterns.json")
        ),
        apply_calibration=False,
    )

    with get_db_session() as session:
        entries = load_default_corpora()
        if limit > 0:
            entries = entries[:limit]
        report = evaluate_identification(entries, get_identifier(session))

    cal = calibrate(report.outcomes)

    if json_output:
        payload = cal.to_dict()
        payload["suggested_weights"] = suggested_weights(
            cal, min_samples=min_samples, force=force_weights
        )
        console.print_json(data=payload)
    else:
        for line in calibration_lines(cal):
            console.print(line)

    if out:
        from hashvault.core.calibration import save_calibration

        target = save_calibration(cal, out)
        console.print(
            f"[green]Wrote calibration curve ({len(cal.isotonic)} points) to "
            f"{target}[/green]"
        )
        if out.name == "calibration.json":
            console.print(
                "[dim]Identification now reports calibrated confidence; "
                "candidate ranking is unchanged.[/dim]"
            )
        else:
            console.print(
                "[dim]Copy it to data/patterns/calibration.json for the "
                "identifier to pick it up automatically.[/dim]"
            )


@app.command("plan")
def plan_cmd(
    target: str = typer.Argument(..., help="Hash to plan a cracking run for"),
    wordlist: Optional[Path] = typer.Option(
        None, "--wordlist", "-w", help="Wordlist to size the keyspace from"
    ),
    rules: int = typer.Option(
        1, "--rules", "-r", help="Number of rule lines applied per word"
    ),
    mask: Optional[str] = typer.Option(
        None, "--mask", help="Hashcat mask, e.g. '?l?l?l?l?d?d'"
    ),
    keyspace: Optional[int] = typer.Option(
        None, "--keyspace", help="Explicit candidate count (overrides wordlist)"
    ),
    budget: Optional[float] = typer.Option(
        None, "--budget", help="Audit budget in seconds"
    ),
    rate: Optional[float] = typer.Option(
        None, "--rate", help="Measured hashes/second for this device"
    ),
    measure: bool = typer.Option(
        False,
        "--measure",
        help="Benchmark hashcat for this mode instead of using a reference rate",
    ),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable plan"),
) -> None:
    """Estimate cracking time and decide whether a job fits the audit budget."""
    from hashvault.core.parameters import analyze_parameters
    from hashvault.core.planner import (
        count_wordlist,
        measure_rate,
        plan_crack,
        summary_lines as plan_lines,
    )

    if measure and rate is None:
        config = load_config()
        mode = None
        # Prefer an explicitly forced pattern, then whatever the identifier
        # would pick; benchmarking the wrong mode gives a meaningless number.
        try:
            init_db(config.paths.database)
            with get_db_session() as session:
                from hashvault.core.identifier import identify

                result = identify(target, session, config)
                if result.candidates:
                    mode = result.candidates[0].pattern.hashcat_mode
        except Exception as exc:  # noqa: BLE001 - planning must not crash
            console.print(f"[yellow]Could not identify the hash: {exc}[/yellow]")

        if mode is None:
            console.print(
                "[yellow]No hashcat mode for this input; falling back to a "
                "reference rate.[/yellow]"
            )
        else:
            console.print(f"[dim]Benchmarking hashcat mode {mode}...[/dim]")
            measured, explanation = measure_rate(config.paths.hashcat_bin, mode)
            if measured is None:
                console.print(f"[yellow]Benchmark unavailable: {explanation}[/yellow]")
            else:
                rate = measured
                console.print(f"[dim]{explanation}: {measured:,.0f} H/s[/dim]")

    entries = keyspace
    if entries is None and wordlist is not None:
        if not wordlist.is_file():
            console.print(f"[red]Wordlist not found: {wordlist}[/red]")
            raise typer.Exit(1)
        entries = count_wordlist(wordlist)
        console.print(f"[dim]Counted {entries:,} words in {wordlist}[/dim]")

    plan = plan_crack(
        target,
        wordlist_entries=entries,
        rule_count=rules,
        mask=mask,
        measured_rate=rate,
        budget_seconds=budget,
    )

    if json_output:
        console.print_json(data=plan.to_dict())
    else:
        for line in plan_lines(plan):
            console.print(line)


@app.command("evidence")
def evidence_cmd(
    out: Optional[Path] = typer.Option(
        None, "--out", help="Write the signed report to this path"
    ),
    sign_key: Optional[Path] = typer.Option(
        None, "--sign-key", help="Ed25519 private key (PEM) used to sign"
    ),
    gen_key: Optional[Path] = typer.Option(
        None, "--generate-key", help="Create an Ed25519 keypair at this path"
    ),
    verify: Optional[Path] = typer.Option(
        None, "--verify", help="Verify an existing evidence report"
    ),
    public_key: Optional[Path] = typer.Option(
        None, "--public-key", help="Public key (PEM) for verification"
    ),
    limit: int = typer.Option(0, "--limit", help="Include at most N records"),
    json_output: bool = typer.Option(False, "--json", help="Print the document"),
) -> None:
    """Build or verify a signed, plaintext-free audit evidence report."""
    from hashvault.core.evidence import (
        EvidenceError,
        build_evidence_report,
        generate_keypair,
        sign_report,
        verify_report,
        write_report,
    )

    if gen_key is not None:
        private_pem, public_pem = generate_keypair()
        gen_key.parent.mkdir(parents=True, exist_ok=True)
        gen_key.write_bytes(private_pem)
        public_path = gen_key.with_suffix(".pub.pem")
        public_path.write_bytes(public_pem)
        try:
            gen_key.chmod(0o600)
        except OSError:  # pragma: no cover - Windows ACLs
            pass
        console.print(f"[green]Private key: {gen_key}[/green]")
        console.print(f"[green]Public key : {public_path}[/green]")
        raise typer.Exit(0)

    if verify is not None:
        document = json.loads(verify.read_text(encoding="utf-8"))
        pem = public_key.read_bytes() if public_key else None
        try:
            ok, reasons = verify_report(document, pem)
        except EvidenceError as exc:
            console.print(f"[red]Verification error: {exc}[/red]")
            raise typer.Exit(2)
        if ok:
            console.print("[bold green]Report integrity verified.[/bold green]")
            if pem is None:
                console.print(
                    "[yellow]No --public-key supplied: payload integrity was "
                    "checked, the signature was not.[/yellow]"
                )
            raise typer.Exit(0)
        console.print("[bold red]Report verification FAILED[/bold red]")
        for reason in reasons:
            console.print(f"  - {reason}")
        raise typer.Exit(1)

    config = load_config()
    init_db(config.paths.database)
    data_dir = Path(config.paths.wordlist_dir).parent
    corpus_dir = data_dir / "corpus"

    with get_db_session() as session:
        report = build_evidence_report(
            session,
            patterns_file=data_dir / "patterns" / "patterns.json",
            corpus_files=sorted(corpus_dir.glob("*.json")),
            limit=limit or None,
            metadata={"command": "hashvault evidence"},
        )

    if sign_key is None:
        console.print(
            "[yellow]No --sign-key: the report is unsigned and only proves "
            "the payload was not edited in transit.[/yellow]"
        )
        document = report.payload()
        document["signature"] = {"algorithm": "none", "value": ""}
    else:
        try:
            document = sign_report(report, sign_key.read_bytes())
        except EvidenceError as exc:
            console.print(f"[red]Signing failed: {exc}[/red]")
            raise typer.Exit(2)

    if out is not None:
        target = write_report(document, out)
        console.print(f"[bold green]Wrote evidence report to {target}[/bold green]")
    if json_output or out is None:
        console.print_json(data=document)


def _gallery_payload(rows) -> list[dict]:
    return [
        {
            "profile": row.profile.key,
            "title": row.profile.title,
            "category": row.profile.category,
            "input": row.profile.source_label,
            "extensions": list(row.profile.extensions),
            "converter": row.converter_name,
            "john_format": row.profile.john_format,
            "hashcat_mode": row.profile.hashcat_mode,
            "runtime": row.runtime,
            "available": row.available,
            "status": "ready" if row.available else row.reason,
            "description": row.profile.description,
            "notes": list(row.profile.notes),
        }
        for row in rows
    ]


def _resolve_wordlist_reference(config, wordlist: Optional[str]) -> str:
    if not wordlist:
        return config.paths.quick_wordlist
    candidate = Path(wordlist)
    if candidate.exists():
        return str(candidate)
    base = Path(config.paths.wordlist_dir)
    direct = base / wordlist
    if direct.exists():
        return str(direct)
    matches = sorted(base.glob(f"{wordlist}.*"))
    return str(matches[0]) if matches else str(direct)


def _write_extracted_hashes(path: Path, result) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [item.raw_hash for item in result.hashes if item.raw_hash]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


@app.command("convert")
def convert_cmd(
    target: str = typer.Argument("", help="Path to encrypted file to extract a hash from"),
    format: str = typer.Option("", "--format", "-f", help="Force the automatic converter format"),
    profile: str = typer.Option("", "--profile", "-p", help="John conversion profile key from --gallery"),
    gallery: bool = typer.Option(False, "--gallery", "-g", help="Browse or inspect John conversion profiles"),
    filter: str = typer.Option("", "--filter", help="Filter the gallery by profile, format, category, or extension"),
    hash_out: Optional[Path] = typer.Option(None, "--hash-out", help="Write extracted hash lines to this file"),
    analyze: bool = typer.Option(False, "--analyze", "-a", help="Pipe extracted hash through deep analysis"),
    crack: bool = typer.Option(False, "--crack", "-c", help="Attempt to crack the extracted hash immediately"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w", help="Wordlist name for cracking"),
    tool: CrackTool = typer.Option(CrackTool.AUTO, "--tool", help="Cracking engine backend"),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
    list_formats: bool = typer.Option(False, "--list-formats", help="List all John conversion profiles"),
) -> None:
    """Convert encrypted files to John/hashcat input, with a selectable converter gallery."""

    config = load_config()
    john_bin = config.paths.john_bin

    if list_formats or gallery:
        if target and not list_formats:
            path = Path(target)
            matching = {item.key for item in find_profiles_for_path(path)}
            rows = tuple(
                row
                for row in gallery_rows(john_bin, query=filter)
                if row.profile.key in matching
            )
            title = f"John Conversion Gallery: {path.name}"
        else:
            rows = gallery_rows(john_bin, query=filter)
            title = "John Conversion Gallery"
        if json_out:
            print(json.dumps({"profiles": _gallery_payload(rows)}, indent=2))
        else:
            render_conversion_gallery(console, rows, title=title)
            discovered = len(discover_converters(john_bin))
            ready = sum(1 for row in rows if row.available)
            console.print(
                f"[dim]{len(rows)} profile(s), {ready} ready, "
                f"{discovered} bundled converter(s) discovered.[/dim]"
            )
            if not target:
                console.print(
                    "[dim]Select a profile with --profile KEY, or run "
                    "`convert FILE --gallery` to see matching input types.[/dim]"
                )
        return

    if not target:
        console.print("[bold red]Error:[/bold red] Provide a file path or use --gallery.")
        raise typer.Exit(1)

    path = Path(target)
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {target}")
        raise typer.Exit(1)

    selected_profile = get_profile(profile) if profile else None
    if profile and selected_profile is None:
        console.print(f"[bold red]Unknown profile:[/bold red] {profile}")
        console.print("[dim]Run `hashvault convert --gallery` to list profile keys.[/dim]")
        raise typer.Exit(1)

    if selected_profile is not None:
        if not json_out:
            console.print(f"[bold blue]Converting:[/bold blue] {path.name}")
            console.print(
                f"[dim]Profile:[/dim] {selected_profile.key} — "
                f"{selected_profile.title}"
            )
        result = convert_with_profile(
            selected_profile, path, john_bin=john_bin
        )
    else:
        if not json_out:
            console.print(f"[bold blue]Converting:[/bold blue] {path.name}")
        detected_fmt = format or detect_file_type(path)
        if not json_out:
            console.print(
                f"[dim]Detected format:[/dim] {detected_fmt or 'unknown'}"
            )
        result = convert_file(path, john_bin=john_bin, format_override=format)

    if not result.success:
        if json_out:
            print(
                json.dumps(
                    {"success": False, "error": result.error, "file": str(path)},
                    indent=2,
                )
            )
        else:
            console.print(f"[bold red]Conversion failed:[/bold red] {result.error}")
            if selected_profile is None:
                console.print(
                    "[dim]Try the John gallery for additional formats: "
                    "`hashvault convert --gallery`.[/dim]"
                )
        raise typer.Exit(1)

    suggested_hash_path = hash_out or Path("hashes.john")
    wordlist_path = _resolve_wordlist_reference(config, wordlist)
    active_profile = selected_profile or get_profile(result.format_detected)
    john_command = ""
    show_command = ""
    hashcat_command = ""
    if active_profile is not None:
        john_command = build_john_command(
            active_profile,
            suggested_hash_path,
            wordlist_path,
            session=f"hashvault-{active_profile.key}",
        )
        show_command = build_john_show_command(active_profile, suggested_hash_path)
        hashcat_command = build_hashcat_command(
            active_profile, suggested_hash_path, wordlist_path
        )

    if hash_out:
        try:
            _write_extracted_hashes(hash_out, result)
        except OSError as exc:
            console.print(f"[bold red]Failed to write hash file:[/bold red] {exc}")
            raise typer.Exit(1)

    if json_out:
        out_data = {
            "success": True,
            "source_file": result.source_file,
            "format": result.format_detected,
            "profile": active_profile.key if active_profile else None,
            "john_format": active_profile.john_format if active_profile else None,
            "hashcat_mode": active_profile.hashcat_mode if active_profile else None,
            "hash_file": str(hash_out) if hash_out else None,
            "commands": {
                "john": john_command,
                "john_show": show_command,
                "hashcat": hashcat_command,
            },
            "hashes": [
                {
                    "raw_hash": item.raw_hash,
                    "format_hint": item.format_hint,
                    "tool_used": item.tool_used,
                    "hashcat_mode": item.hashcat_mode,
                    "john_format": item.john_format,
                    "notes": item.notes,
                }
                for item in result.hashes
            ],
        }
        print(json.dumps(out_data, indent=2))
    else:
        console.print(
            f"[bold green]✓ Extracted {len(result.hashes)} hash(es):[/bold green]"
        )
        for index, item in enumerate(result.hashes, 1):
            preview = item.raw_hash[:120]
            suffix = "…" if len(item.raw_hash) > 120 else ""
            console.print(f"  [cyan][{index}][/cyan] {preview}{suffix}")
            if item.hashcat_mode:
                console.print(
                    f"      hashcat -m [yellow]{item.hashcat_mode}[/yellow]  "
                    f"john --format=[yellow]{item.john_format or 'auto'}[/yellow]"
                )
            for note in item.notes:
                console.print(f"      [dim]Note: {note}[/dim]")
        if john_command:
            console.print("\n[bold blue]Suggested John workflow[/bold blue]")
            if not hash_out:
                console.print(
                    "[dim]Save the extracted lines first with "
                    "--hash-out hashes.john.[/dim]"
                )
            console.print(f"  [cyan]{john_command}[/cyan]")
            console.print(f"  [cyan]{show_command}[/cyan]")
            if hashcat_command:
                console.print(f"  [dim]{hashcat_command}[/dim]")

    if (analyze or crack) and result.hashes:
        init_db(
            config.paths.database,
            seed_patterns_path="data/patterns/patterns.json",
            seed_corpus_paths=DEFAULT_CORPUS_FILES,
        )
        with get_db_session() as session:
            for item in result.hashes:
                if not item.raw_hash:
                    continue
                if analyze or not crack:
                    console.print("\n[bold blue]══ Deep Analysis ══[/bold blue]")
                    try:
                        analysis_result = analyze_input(item.raw_hash, session, config)
                        identification = analysis_result.identification
                        chosen = getattr(identification, "chosen_pattern", None)
                        console.print(
                            f"  Resolved : "
                            f"{'[green]yes[/green]' if analysis_result.resolved else '[red]no — ambiguous[/red]'}"
                        )
                        if chosen:
                            console.print(
                                f"  Pattern  : [bold]{chosen.name}[/bold]  "
                                f"(mode={getattr(chosen, 'hashcat_mode', None)}, "
                                f"john={getattr(chosen, 'john_format', None)})"
                            )
                    except NoCandidateError:
                        console.print("  [red]No matching pattern found.[/red]")

                if crack:
                    console.print("\n[bold blue]══ Cracking ══[/bold blue]")
                    crack_result = process_single_hash(
                        raw_hash=item.raw_hash,
                        db_session=session,
                        config=config,
                        tool=tool,
                        wordlist_name=wordlist,
                        auto_confirm=True,
                    )
                    render_crack_results([crack_result])


@app.command("selftest")
def selftest_cmd(
    matrix: bool = typer.Option(False, "--matrix", help="Run the full analysis matrix (default)"),
    crack: bool = typer.Option(False, "--crack", help="Also exercise the built-in cracking handoff"),
    report: Optional[Path] = typer.Option(None, "--report", help="Write the full report as JSON"),
    json_out: bool = typer.Option(False, "--json", help="Print the full report as JSON"),
    max_layers: int = typer.Option(12, "--max-layers", help="Maximum analysis depth"),
    beam_width: int = typer.Option(8, "--beam-width", help="Analysis beam width"),
    archives: bool = typer.Option(True, "--archives/--no-archives", help="Include ZIP/TAR matrix cases"),
    live: bool = typer.Option(False, "--live", help="Stream each matrix case as it completes"),
) -> None:
    """Run the end-to-end analysis/cracking coverage matrix."""
    from hashvault.selftest import run_matrix

    if not matrix and not crack:
        matrix = True

    table = Table(
        title="HashVault Analysis / Cracking Matrix",
        header_style="bold cyan",
        expand=True,
        show_lines=False,
    )
    table.add_column("Category", style="magenta", no_wrap=True)
    table.add_column("Case", style="cyan", no_wrap=True)
    table.add_column("Detected path", style="yellow", max_width=35)
    table.add_column("Status", justify="center", width=8)
    table.add_column("Actual", style="green", max_width=32)
    table.add_column("Time", justify="right", width=7)

    def add_result(item) -> None:
        if item.status == "pass":
            status = "[bold green]PASS[/bold green]"
        elif item.status == "skip":
            status = "[yellow]SKIP[/yellow]"
        else:
            status = "[bold red]FAIL[/bold red]"
        actual = item.actual or item.detail or "-"
        table.add_row(
            item.category,
            item.name,
            item.operation or "-",
            status,
            actual[:32],
            f"{item.elapsed:.3f}s",
        )

    live_view = None
    if live and not json_out:
        from rich.live import Live

        live_view = Live(table, console=console, refresh_per_second=10, transient=True)
        live_view.start()
    try:
        result = run_matrix(
            max_layers=max_layers,
            beam_width=beam_width,
            check_crack=crack,
            include_archives=archives,
            on_result=add_result,
        )
    finally:
        if live_view is not None:
            live_view.stop()

    data = result.to_dict()
    if report is not None:
        report.write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"[green]Report written to[/green] {report}")
    if json_out:
        print(json.dumps(data, indent=2))
        if result.failed:
            raise typer.Exit(1)
        return

    console.print(table)
    console.print(
        f"[bold]Matrix:[/bold] {result.passed}/{len(result.results)} passed, "
        f"{result.failed} failed, {result.elapsed:.2f}s  |  "
        f"operation coverage {len(result.covered_operations)}/{result.total_operations}"
    )
    if result.missing_operations:
        console.print(f"[yellow]Missing operations:[/yellow] {', '.join(result.missing_operations)}")
    if result.failed_operations:
        console.print(f"[red]Failing operations:[/red] {', '.join(result.failed_operations)}")
    if result.failed:
        raise typer.Exit(1)


@app.command("interactive")
def interactive_cmd() -> None:
    """Enter HashVault interactive shell prompt mode."""
    config = load_config()
    init_db(
        config.paths.database,
        seed_patterns_path="data/patterns/patterns.json",
        seed_corpus_paths=DEFAULT_CORPUS_FILES,
    )
    start_interactive_shell(config)
