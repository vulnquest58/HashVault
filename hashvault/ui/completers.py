"""
Auto-completion providers for HashVault interactive shell using prompt_toolkit.
"""
from typing import Dict, Any
from prompt_toolkit.completion import Completer, NestedCompleter
from sqlalchemy.orm import Session

from hashvault.core.database import get_db_session
from hashvault.core.wordlist_manager import list_rules, list_wordlists
from hashvault.models.orm import Pattern


def build_interactive_completer(session: Session) -> NestedCompleter:
    """Build a nested auto-completer structure based on registered DB resources."""
    patterns = session.query(Pattern.name).all()
    pattern_names = {p[0]: None for p in patterns}

    wordlists = {w.name: None for w in list_wordlists(session)}
    rules = {r.name: None for r in list_rules(session)}

    completer_dict: Dict[str, Any] = {
        "identify": {
            "--live": None,
            "--extractors": None,
            "--json": None,
            "--file": None,
            "--hint": None,
            "--format": None,
            "--key": None,
            "--no-unwrap": None,
            "--max-layers": None,
            "--beam-width": None,
        },
        "analyze": {
            "--live": None,
            "--extractors": None,
            "--file": None,
            "--json": None,
            "--crack": None,
            "--wordlist": wordlists,
            "--hint": None,
            "--pattern": None,
            "--format": None,
            "--key": None,
            "--tool": {"hashcat": None, "john": None, "builtin": None, "auto": None},
            "--list-ops": None,
            "--category": None,
            "--verbose": None,
            "--max-layers": None,
            "--beam-width": None,
            "--recipe-out": None,
        },
        "crack": {
            "--tool": {"hashcat": None, "john": None, "builtin": None, "auto": None},
            "--wordlist": wordlists,
            "--rules": rules,
            "--file": None,
            "--auto": None,
            "--live": None,
            "--hint": None,
            "--pattern": None,
            "--format": None,
            "--key": None,
            "--no-unwrap": None,
            "--max-layers": None,
            "--beam-width": None,
            "--extractors": None,
            "--attack-mode": {"dictionary": None, "mask": None, "hybrid": None},
            "--mask": None,
            "--json": None,
            "--silent": None,
            "--no-retry": None,
            "--max-alternative-attempts": None,
            "--budget-seconds": None,
            "--no-adaptive": None,
            "--resolve-trials": None,
            "--trial-budget": None,
            "--recipe-out": None,
        },
        "parameters": {
            "--file": None,
            "--json": None,
        },
        "mutate": {
            "--term": None,
            "--context-json": None,
            "--history": None,
            "--enrich": None,
            "--llm": None,
            "--limit": None,
            "--language": {"auto": None, "arabic": None, "arabizi": None, "both": None, "off": None},
            "--year": None,
            "--no-years": None,
            "--wordlist-out": None,
            "--rules-out": None,
            "--json": None,
        },
        "replay": {
            "--input": None,
            "--key": None,
            "--json": None,
        },
        "benchmark-layers": {
            "--corpus": None,
            "--limit": None,
            "--crack": None,
            "--json": None,
            "--show": None,
        },
        "strategies": {
            "stats": {"--json": None},
            "reset": {"--yes": None},
        },
        "doctor": {
            "--json": None,
            "--probe": None,
        },
        "audit": {
            "--pattern": pattern_names or None,
            "--limit": None,
            "--json": None,
        },
        "insights": {
            "--days": None,
            "--json": None,
        },
        "convert": {
            "--analyze": None,
            "--crack": None,
            "--wordlist": wordlists,
            "--list-formats": None,
            "--gallery": None,
            "--filter": None,
            "--profile": None,
            "--hash-out": None,
            "--json": None,
        },
        "gallery": None,
        "selftest": {
            "--matrix": None,
            "--crack": None,
            "--archives": None,
            "--no-archives": None,
            "--report": None,
            "--json": None,
            "--live": None,
            "--max-layers": None,
            "--beam-width": None,
        },
        "check": None,
        "stats": None,
        "sessions": {
            "--status": {
                "running": None,
                "completed": None,
                "timeout": None,
                "failed": None,
            },
            "--json": None,
            "--purge": None,
            "--older-than-days": None,
            "--dry-run": None,
            "--yes": None,
        },
        "patterns-audit": {
            "--json": None,
            "--strict": None,
            "--include-known": None,
        },
        "calibrate": {
            "--json": None,
            "--out": None,
            "--min-samples": None,
            "--force-weights": None,
            "--limit": None,
        },
        "plan": {
            "--wordlist": None,
            "--rules": None,
            "--mask": None,
            "--keyspace": None,
            "--budget": None,
            "--rate": None,
            "--measure": None,
            "--json": None,
        },
        "evidence": {
            "--out": None,
            "--sign-key": None,
            "--generate-key": None,
            "--verify": None,
            "--public-key": None,
            "--limit": None,
            "--json": None,
        },
        "setup": None,
        "import-wordlist": None,
        "set": {
            "auto-crack": {"on": None, "off": None},
            "adaptive": {"on": None, "off": None},
            "retry": {"on": None, "off": None},
            "budget": None,
            "trials": {"on": None, "off": None},
            "verify-cache": {"on": None, "off": None},
        },
        "refresh": None,
        "exit": None,
        "quit": None,
        "help": None,
    }

    return NestedCompleter.from_nested_dict(completer_dict)


class RefreshableCompleter(Completer):
    """Wrapper class providing explicit refresh capabilities for the nested completer."""

    def __init__(self) -> None:
        self.completer: NestedCompleter | None = None
        self.refresh()

    def refresh(self) -> None:
        with get_db_session() as session:
            self.completer = build_interactive_completer(session)

    def get_completions(self, document, complete_event):  # type: ignore
        if self.completer:
            yield from self.completer.get_completions(document, complete_event)

    def __call__(self, document, complete_event):  # type: ignore
        if self.completer:
            yield from self.completer.get_completions(document, complete_event)
