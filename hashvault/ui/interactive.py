"""
Interactive Prompt Shell mode for HashVault v2.0.
Features confirmation prompts on direct hash pastes, sanitized prompt_toolkit history permissions (0o600), and custom keybindings.
"""
import os
import shlex
import sys
from pathlib import Path
import platformdirs
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings, merge_key_bindings
from rich.console import Console

from hashvault.config import Config
from hashvault.core.database import get_db_session
from hashvault.core.normalizer import normalize_hash
from hashvault.core.orchestrator import process_single_hash
from hashvault.core.reporter import render_crack_results
from hashvault.ui.completers import RefreshableCompleter
from hashvault.ui.keybindings import kb
from hashvault.ui.styles import hashvault_style
from hashvault.utils.helpers import sanitize_cmd_args

console = Console()


def get_secure_history_path() -> Path:
    """Return secure history file path with 0o600 POSIX permissions enforcement."""
    user_dir = Path(platformdirs.user_data_dir("hashvault"))
    user_dir.mkdir(parents=True, exist_ok=True)
    history_file = user_dir / "history"

    if not history_file.exists():
        history_file.touch(mode=0o600)
    elif os.name == "posix":
        os.chmod(history_file, 0o600)

    return history_file


def start_interactive_shell(config: Config) -> None:
    """Launch the interactive REPL shell mode."""
    history_path = get_secure_history_path()
    completer = RefreshableCompleter()
    auto_crack_enabled = False
    adaptive_enabled = bool(getattr(config.strategy, "adaptive_tool_selection", True))
    retry_enabled = bool(getattr(config.strategy, "retry_alternatives", True))
    trial_disambiguation_enabled = bool(
        getattr(config.strategy, "enable_trial_disambiguation", True)
    )
    verify_cache_enabled = bool(
        getattr(config.strategy, "verify_cache_entries", True)
    )
    default_budget = float(
        getattr(config.strategy, "default_budget_seconds", 0.0) or 0.0
    )
    budget_seconds: float | None = default_budget if default_budget > 0 else None
    status_message = "ready"

    shell_bindings = KeyBindings()

    @shell_bindings.add("f1")
    def _show_help(event):  # type: ignore
        buffer = event.app.current_buffer
        buffer.text = "help"
        buffer.cursor_position = len(buffer.text)
        buffer.validate_and_handle()

    @shell_bindings.add("f2")
    def _toggle_auto_crack(event):  # type: ignore
        nonlocal auto_crack_enabled, status_message
        auto_crack_enabled = not auto_crack_enabled
        status_message = f"auto-crack {'on' if auto_crack_enabled else 'off'}"
        event.app.invalidate()

    @shell_bindings.add("f3")
    def _refresh(event):  # type: ignore
        nonlocal status_message
        completer.refresh()
        status_message = "completions refreshed"
        event.app.invalidate()

    @shell_bindings.add("f4")
    def _strategies(event):  # type: ignore
        buffer = event.app.current_buffer
        buffer.text = "strategies stats"
        buffer.cursor_position = len(buffer.text)
        buffer.validate_and_handle()

    @shell_bindings.add("f5")
    def _parameters(event):  # type: ignore
        buffer = event.app.current_buffer
        buffer.text = "parameters "
        buffer.cursor_position = len(buffer.text)

    @shell_bindings.add("f6")
    def _mutate(event):  # type: ignore
        buffer = event.app.current_buffer
        buffer.text = "mutate "
        buffer.cursor_position = len(buffer.text)

    def bottom_toolbar() -> HTML:
        mode = "ON" if auto_crack_enabled else "OFF"
        adaptive = "ON" if adaptive_enabled else "OFF"
        retry = "ON" if retry_enabled else "OFF"
        trials = "ON" if trial_disambiguation_enabled else "OFF"
        budget = f"{budget_seconds:g}s" if budget_seconds else "unlimited"
        return HTML(
            f" <b>HashVault</b>  auto-crack: <b>{mode}</b>"
            f"  adaptive: <b>{adaptive}</b>  retry: <b>{retry}</b>"
            f"  trials: <b>{trials}</b>  budget: <b>{budget}</b>"
            f"  <i>{status_message}</i>"
            "   F1 help  F2 auto-crack  F3 refresh  F4 strategies"
            "  Tab complete  Ctrl+R history  Ctrl+C cancel  Ctrl+D exit"
        )

    combined_bindings = merge_key_bindings([kb, shell_bindings])
    session = PromptSession(
        history=FileHistory(str(history_path)),
        completer=completer,
        style=hashvault_style,
        key_bindings=combined_bindings,
        auto_suggest=AutoSuggestFromHistory(),
        bottom_toolbar=bottom_toolbar,
        complete_while_typing=True,
        enable_history_search=True,
        search_ignore_case=True,
    )

    from hashvault.ui.banner import render_banner

    render_banner(console)
    console.print("[bold blue]=== HashVault Interactive Shell v2.0 ===[/bold blue]")
    console.print("Type [cyan]help[/cyan] for command list or [cyan]exit[/cyan] to quit.\n")

    while True:
        try:
            raw_input = session.prompt("HashVault> ")
            if raw_input is None:
                console.print("[yellow]Exiting HashVault session.[/yellow]")
                break

            line = raw_input.strip()
            if not line:
                continue

            if line.lower() in ("exit", "quit"):
                console.print("[yellow]Exiting HashVault session.[/yellow]")
                break

            if line.lower() == "help":
                console.print("[bold blue]Available Shell Commands:[/bold blue]")
                console.print("  crack <hash>        - Run password auditing cracking session")
                console.print("  identify <hash>     - Identify algorithm patterns")
                console.print("  analyze <input>     - Deep analysis (unwrap layers + identify; add --live)")
                console.print("  parameters <hash>   - Inspect cost parameters and work factor")
                console.print("  mutate [context]    - Generate targeted candidates from local context")
                console.print("  replay <recipe>     - Replay a saved analysis recipe")
                console.print("  strategies stats    - Show adaptive tool/pattern feedback")
                console.print("  doctor [--probe]    - Check database, data, engines, and paths")
                console.print("  audit [--pattern]   - Re-verify stored cracked records")
                console.print("  insights [--days N] - Summarize local audit activity")
                console.print("  benchmark-layers    - Run the layered recipe benchmark")
                console.print("  selftest            - Run the 68-case analysis matrix")
                console.print("  convert <file>      - Extract hash from encrypted file")
                console.print("  gallery [file]      - Select a John converter for a file")
                console.print("  check <hash>        - Query database cache")
                console.print("  set auto-crack on/off - Toggle auto-crack on paste confirmation")
                console.print("  set adaptive on/off - Toggle adaptive tool ordering")
                console.print("  set retry on/off    - Toggle analysis branch retries")
                console.print("  set budget <seconds> - Set per-hash crack budget (0 = unlimited)")
                console.print("  set trials on/off   - Toggle trial-cracking of ambiguous formats")
                console.print("  set verify-cache on/off - Toggle cached-plaintext re-verification")
                console.print("  patterns-audit      - Check the pattern catalogue for defects")
                console.print("  calibrate           - Measure identification confidence vs corpus")
                console.print("  plan <hash> --mask ... - Estimate cracking time vs a budget")
                console.print("  evidence [--out F]  - Build a signed, plaintext-free audit report")
                console.print("  refresh             - Reload completions from database")
                console.print("  F1 help  F2 auto-crack  F3 refresh  F4 strategies  F5 parameters  F6 mutate")
                console.print("  exit / quit         - Exit shell session\n")
                continue

            if line.lower() == "refresh":
                completer.refresh()
                console.print("[green]Completer resources refreshed.[/green]")
                continue

            if line.lower() == "gallery" or line.lower().startswith("gallery "):
                from hashvault.ingestors.john_catalog import (
                    find_profiles_for_path,
                    gallery_rows,
                )
                from hashvault.ui.conversion_gallery import render_conversion_gallery

                try:
                    parts = shlex.split(line, posix=False)
                except ValueError as exc:
                    console.print(f"[bold red]Invalid gallery arguments:[/bold red] {exc}")
                    continue
                target = parts[1].strip("\"'") if len(parts) > 1 else ""
                if not target:
                    target = session.prompt("File path: ").strip().strip("\"'")
                if not target:
                    continue
                path = Path(target)
                if not path.exists():
                    console.print(f"[bold red]File not found:[/bold red] {path}")
                    continue
                matching = {item.key for item in find_profiles_for_path(path)}
                rows = tuple(
                    row
                    for row in gallery_rows(config.paths.john_bin)
                    if row.profile.key in matching
                )
                if not rows:
                    console.print(
                        "[yellow]No gallery profile matches that path.[/yellow] "
                        "Run `convert --gallery --filter <term>` to browse."
                    )
                    continue
                render_conversion_gallery(
                    console,
                    rows,
                    title=f"John Conversion Gallery: {path.name}",
                    include_numbers=True,
                )
                selection = session.prompt(
                    "Select conversion number (Enter to cancel): "
                ).strip()
                if not selection:
                    continue
                try:
                    index = int(selection)
                    if index < 1 or index > len(rows):
                        raise IndexError
                    selected_row = rows[index - 1]
                except (ValueError, IndexError):
                    console.print("[yellow]Invalid selection.[/yellow]")
                    continue
                if not selected_row.available:
                    console.print(
                        f"[yellow]Profile unavailable:[/yellow] "
                        f"{selected_row.reason}"
                    )
                    continue
                from hashvault.cli import app as cli_app

                try:
                    cli_app(
                        ["convert", str(path), "--profile", selected_row.profile.key],
                        standalone_mode=False,
                    )
                except Exception as exc:
                    console.print(f"[bold red]Command Error:[/bold red] {exc}")
                continue

            if line.lower().startswith("set "):
                parts = line.split()
                setting = parts[1].lower() if len(parts) >= 2 else ""
                value = parts[2].lower() if len(parts) >= 3 else ""
                if setting == "auto-crack":
                    auto_crack_enabled = value == "on"
                    status_message = f"auto-crack {'on' if auto_crack_enabled else 'off'}"
                    console.print(
                        f"[{'green' if auto_crack_enabled else 'yellow'}]"
                        f"Auto-crack on direct paste is now "
                        f"{'ON' if auto_crack_enabled else 'OFF'}.[/"
                        f"{'green' if auto_crack_enabled else 'yellow'}]"
                    )
                elif setting == "adaptive":
                    adaptive_enabled = value == "on"
                    status_message = f"adaptive {'on' if adaptive_enabled else 'off'}"
                    console.print(
                        f"Adaptive tool ordering is now {'ON' if adaptive_enabled else 'OFF'}."
                    )
                elif setting == "retry":
                    retry_enabled = value == "on"
                    status_message = f"retry {'on' if retry_enabled else 'off'}"
                    console.print(
                        f"Alternative branch retry is now {'ON' if retry_enabled else 'OFF'}."
                    )
                elif setting == "budget":
                    try:
                        parsed = float(value)
                        if parsed < 0:
                            raise ValueError
                    except ValueError:
                        console.print("[red]Budget must be a non-negative number.[/red]")
                    else:
                        budget_seconds = parsed if parsed > 0 else None
                        status_message = (
                            f"budget {budget_seconds:g}s" if budget_seconds else "budget unlimited"
                        )
                        console.print(
                            f"Crack budget set to {budget_seconds:g}s."
                            if budget_seconds
                            else "Crack budget set to unlimited."
                        )
                elif setting == "trials":
                    trial_disambiguation_enabled = value == "on"
                    status_message = (
                        f"trials {'on' if trial_disambiguation_enabled else 'off'}"
                    )
                    console.print(
                        "Trial disambiguation (cracking the top ambiguous "
                        f"candidates) is now "
                        f"{'ON' if trial_disambiguation_enabled else 'OFF'}."
                    )
                elif setting == "verify-cache":
                    verify_cache_enabled = value == "on"
                    status_message = (
                        f"verify-cache {'on' if verify_cache_enabled else 'off'}"
                    )
                    console.print(
                        "Cached-plaintext re-verification is now "
                        f"{'ON' if verify_cache_enabled else 'OFF'}."
                    )
                else:
                    console.print(
                        "[yellow]Use set auto-crack|adaptive|retry|trials|"
                        "verify-cache|budget <value>.[/yellow]"
                    )
                continue

            # Check if input line is a raw hash paste rather than a command
            norm, user = normalize_hash(line)
            is_hash_paste = (
                not line.startswith(" ")
                and " " not in line
                and (
                    len(norm) in (32, 40, 56, 64, 96, 128)
                    or norm.startswith("$")
                    or ":" in norm  # credential/archive format
                )
            )
            if is_hash_paste:
                # Direct Hash Paste Detected - Require confirmation unless auto_crack_enabled is set (SECTION 10.1)
                if not auto_crack_enabled:
                    confirm = session.prompt("Detected hash. Run crack? [y/N/identify-only/analyze]: ").strip().lower()
                    if confirm not in ("y", "yes"):
                        if confirm == "identify-only":
                            from hashvault.cli import app as cli_app
                            cli_app(["identify", line], standalone_mode=False)
                        elif confirm == "analyze":
                            from hashvault.cli import app as cli_app
                            cli_app(["analyze", line, "--live"], standalone_mode=False)
                        continue

                with get_db_session() as db_session:
                    # Apply the shell toggles to the live config so the
                    # pipeline sees them without a reload.
                    config.strategy.enable_trial_disambiguation = (
                        trial_disambiguation_enabled
                    )
                    config.strategy.verify_cache_entries = verify_cache_enabled
                    res = process_single_hash(
                        line,
                        db_session,
                        config,
                        auto_confirm=True,
                        retry_alternatives=retry_enabled,
                        adaptive_tool_selection=adaptive_enabled,
                        budget_seconds=budget_seconds,
                    )
                    render_crack_results([res])
                continue

            # Parse and delegate to typer CLI
            try:
                args = shlex.split(line)
                sanitized_args = sanitize_cmd_args(args)
                
                # Import cli app lazily to invoke subcommands
                from hashvault.cli import app
                app(args, standalone_mode=False)
            except Exception as e:
                console.print(f"[bold red]Command Error:[/bold red] {e}")

        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Exiting HashVault.[/yellow]")
            sys.exit(0)
