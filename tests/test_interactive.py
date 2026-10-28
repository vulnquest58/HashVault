"""Tests for interactive shell configuration and prompt behavior."""

from hashvault.config import load_config
from hashvault.ui import interactive


def test_interactive_shell_configures_prompt_features(tmp_path, monkeypatch):
    captured = {}

    class FakePromptSession:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def prompt(self, *args, **kwargs):
            return "exit"

    class FakeCompleter:
        def refresh(self):
            pass

    monkeypatch.setattr(interactive, "PromptSession", FakePromptSession)
    monkeypatch.setattr(interactive, "RefreshableCompleter", FakeCompleter)
    monkeypatch.setattr(
        interactive, "get_secure_history_path", lambda: tmp_path / "history"
    )

    interactive.start_interactive_shell(load_config())

    assert captured["auto_suggest"] is not None
    assert captured["complete_while_typing"] is True
    assert captured["enable_history_search"] is True
    assert captured["search_ignore_case"] is True
    assert captured["key_bindings"] is not None
    toolbar = captured["bottom_toolbar"]()
    assert "auto-crack" in str(toolbar)
    assert "adaptive" in str(toolbar)
    assert "retry" in str(toolbar)
    assert "budget" in str(toolbar)
    assert "Ctrl+D exit" in str(toolbar)
