"""
Output reporting layer for HashVault v2.0.
Renders visually rich tables using Rich console or structured JSON responses.
"""
import json
from typing import Any, List
from rich.console import Console
from rich.table import Table

from hashvault.core.ambiguity import ambiguity_payload
from hashvault.core.orchestrator import ProcessResult
from hashvault.models.schemas import IdentificationResult, CrackSessionSchema

import os
import sys

console = Console(highlight=False, width=120)



def get_value_str(val: Any) -> str:
    """Safely extract string value whether attribute is an Enum or a primitive str."""
    if val is None:
        return ""
    if hasattr(val, "value"):
        return str(val.value)
    return str(val)


def _render_analysis_hypotheses(analysis: dict | None) -> None:
    branches = (analysis or {}).get("branches") or []
    if len(branches) <= 1:
        return
    console.print("[dim]Analysis hypotheses:[/dim]")
    for branch in branches[:4]:
        marker = "[bold green]>[/bold green]" if branch.get("selected") else " "
        preview = (branch.get("finalized_input") or "").replace("\n", " ")[:56]
        console.print(
            f"  {marker} [cyan]{branch.get('chain', '?')}[/cyan] "
            f"[dim]-> {preview} "
            f"({branch.get('score', 0.0):.2f}, "
            f"{branch.get('layers_applied', 0)} layers)[/dim]"
        )


def identification_payload(
    result: IdentificationResult,
    analysis: dict | None = None,
) -> dict:
    data = {
        "resolved": result.resolved,
        "method": get_value_str(result.method),
        "candidates": [
            {
                "name": c.pattern.name,
                "confidence": round(c.confidence, 4),
                "category": get_value_str(c.pattern.category),
                "hashcat_mode": c.pattern.hashcat_mode,
                "john_format": c.pattern.john_format,
            }
            for c in result.candidates
        ],
    }
    if analysis is not None:
        data["analysis"] = analysis
    data["ambiguity"] = ambiguity_payload(result)
    return data


def render_identification_report(
    result: IdentificationResult,
    json_output: bool = False,
    analysis: dict | None = None,
) -> None:
    """Render pattern identification candidate results."""
    if json_output:
        print(json.dumps(identification_payload(result, analysis), indent=2))
        return

    if analysis is not None:
        selected = analysis.get("selected") or analysis.get("finalized_input") or ""
        console.print(
            f"[dim]Prepared input:[/dim] [cyan]{analysis.get('chain', '(none)')}[/cyan]  "
            f"[dim]→[/dim] [green]{selected[:80]}[/green]"
        )

    table = Table(title="Hash Pattern Identification Candidates", header_style="bold blue")
    table.add_column("Pattern Name", style="cyan", no_wrap=True)
    table.add_column("Confidence Score", justify="right", style="green")
    table.add_column("Category", style="magenta")
    table.add_column("Hashcat Mode", justify="center")
    table.add_column("John Format", justify="center")

    for c in result.candidates:
        conf_str = f"{c.confidence * 100:.1f}%"
        table.add_row(
            c.pattern.name,
            conf_str,
            get_value_str(c.pattern.category),
            str(c.pattern.hashcat_mode or "-"),
            c.pattern.john_format or "-",
        )

    console.print(table)
    ambiguity = ambiguity_payload(result)
    if ambiguity.get("requires_confirmation"):
        console.print(
            "[yellow]Ambiguity warning:[/yellow] "
            f"top={ambiguity.get('top_name') or '?'} "
            f"({ambiguity.get('top_confidence')}), "
            f"margin={ambiguity.get('margin')}, "
            f"entropy={ambiguity.get('entropy')}"
        )
        for recommendation in ambiguity.get("recommendations") or []:
            console.print(f"  [dim]- {recommendation}[/dim]")
    _render_analysis_hypotheses(analysis)


def render_crack_results(results: List[ProcessResult], json_output: bool = False) -> None:
    """Render cracking attempt results."""
    if json_output:
        data = [
            {
                "raw_input": r.raw_input,
                "normalized_hash": r.normalized_hash,
                "username": r.username,
                "pattern": r.candidate.pattern.name if r.candidate else None,
                "cracked": r.cracked,
                "plaintext": r.plaintext,
                "cached": r.cached,
                "tool_used": r.tool_used,
                "error_message": r.error_message,
                "analysis": r.analysis,
                "attempts": r.attempts,
                "ambiguity": r.ambiguity,
                "budget_seconds": r.budget_seconds,
                "recipe": r.recipe,
            }
            for r in results
        ]
        print(json.dumps(data, indent=2))
        return

    table = Table(
        title="HashVault Cracking Results Summary",
        header_style="bold green",
        expand=True,
        show_lines=False,
    )
    table.add_column("Target Hash / Input", style="dim", min_width=12, max_width=28, no_wrap=True)
    table.add_column("Username", style="yellow", min_width=6, no_wrap=True)
    table.add_column("Pattern", style="cyan", min_width=10, max_width=28, no_wrap=True)
    table.add_column("Status", justify="center", min_width=12, max_width=18, no_wrap=True)
    table.add_column("Plaintext Result", style="bold white", min_width=12, max_width=36, no_wrap=False)
    table.add_column("Engine Tool", style="blue", min_width=7, no_wrap=True)

    for r in results:
        status_str = "[bold green]CRACKED[/bold green]" if r.cracked else "[bold red]FAILED[/bold red]"
        if r.cached:
            status_str += " [dim](cache)[/dim]"

        user_str = r.username or "-"
        pattern_str = r.candidate.pattern.name if r.candidate else "Unknown"
        plain_str = r.plaintext if r.plaintext else f"[dim]{r.error_message or 'Uncracked'}[/dim]"

        # Format display hash safely to avoid layout distortion
        disp_hash = r.normalized_hash
        if len(disp_hash) > 34:
            disp_hash = disp_hash[:16] + "…" + disp_hash[-14:]

        table.add_row(
            disp_hash,
            user_str,
            pattern_str,
            status_str,
            plain_str,
            r.tool_used,
        )

    console.print(table)
    for result in results:
        analysis = result.analysis or {}
        chain = analysis.get("chain")
        if chain:
            console.print(
                f"[dim]Prepared input:[/dim] [cyan]{chain}[/cyan] "
                f"[dim]({analysis.get('layers_applied', 0)} layers, "
                f"terminal={analysis.get('terminal', False)})[/dim]"
            )
        _render_analysis_hypotheses(analysis)
        ambiguity = result.ambiguity or {}
        attempts = result.attempts or []
        if ambiguity.get("requires_confirmation"):
            console.print(
                "[yellow]Ambiguity:[/yellow] "
                f"{ambiguity.get('top_name') or '?'} "
                f"({ambiguity.get('top_confidence')}), margin "
                f"{ambiguity.get('margin')}; provide --pattern or --hint."
            )
        if len(attempts) > 1:
            attempted = ", ".join(
                f"{item.get('tool')}:{item.get('pattern')}" for item in attempts[:5]
            )
            console.print(f"[dim]Attempts ({len(attempts)}): {attempted}[/dim]")
        if result.budget_seconds:
            console.print(
                f"[dim]Crack budget: {result.budget_seconds:.1f}s[/dim]"
            )


def render_sessions_report(sessions: List[CrackSessionSchema], json_output: bool = False) -> None:
    """Render active or past session statuses."""
    if json_output:
        data = [s.model_dump(mode="json") for s in sessions]
        print(json.dumps(data, indent=2))
        return

    table = Table(title="HashVault Isolated Cracking Sessions", header_style="bold magenta")
    table.add_column("Session ID", style="cyan")
    table.add_column("Started At", style="dim")
    table.add_column("Processed", justify="right")
    table.add_column("Cracked", justify="right", style="green")
    table.add_column("Status", justify="center")

    for s in sessions:
        status_val = get_value_str(s.status)
        status_color = "green" if status_val == "completed" else "yellow"
        if status_val in ("failed", "timeout"):
            status_color = "red"

        table.add_row(
            s.session_id[:8] + "...",
            str(s.started_at),
            str(s.hashes_processed),
            str(s.cracked_count),
            f"[{status_color}]{status_val.upper()}[/{status_color}]",
        )

    console.print(table)
