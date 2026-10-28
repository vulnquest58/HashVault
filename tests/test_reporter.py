"""Tests for analysis-aware cracking output."""

from io import StringIO

from rich.console import Console

import hashvault.core.reporter as reporter
from hashvault.core.orchestrator import ProcessResult


def test_render_crack_results_lists_analysis_hypotheses(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(
        reporter,
        "console",
        Console(file=output, force_terminal=False, width=140, highlight=False),
    )
    md5 = "5f4dcc3b5aa765d61d8327deb882cf99"
    result = ProcessResult(
        raw_input="payload",
        normalized_hash=md5,
        username=None,
        candidate=None,
        plaintext=None,
        cracked=False,
        cached=False,
        tool_used="none",
        analysis={
            "chain": "Base64 -> Hex",
            "layers_applied": 2,
            "terminal": True,
            "selected": md5,
            "branches": [
                {
                    "chain": "Base64 -> Hex",
                    "finalized_input": md5,
                    "layers_applied": 2,
                    "terminal": True,
                    "score": 0.91,
                    "selected": True,
                },
                {
                    "chain": "Base64",
                    "finalized_input": "not-a-hash",
                    "layers_applied": 1,
                    "terminal": False,
                    "score": 0.42,
                    "selected": False,
                },
            ],
        },
    )

    reporter.render_crack_results([result])

    rendered = output.getvalue()
    assert "Prepared input" in rendered
    assert "Analysis hypotheses" in rendered
    assert "Base64 -> Hex" in rendered
    assert "not-a-hash" in rendered
