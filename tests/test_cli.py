""" 
Unit tests for CLI commands and subcommands.
"""
import base64
import io
import json
import zipfile

from typer.testing import CliRunner
from hashvault.cli import app

runner = CliRunner()


def test_cli_setup():
    result = runner.invoke(app, ["setup"])
    assert result.exit_code == 0
    assert "Setup completed successfully" in result.stdout


def test_cli_identify():
    result = runner.invoke(app, ["identify", "5f4dcc3b5aa765d61d8327deb882cf99"])
    assert result.exit_code == 0
    assert "MD5" in result.stdout


def test_cli_identify_json():
    result = runner.invoke(app, ["identify", "5f4dcc3b5aa765d61d8327deb882cf99", "--json"])
    assert result.exit_code == 0
    assert '"resolved": false' in result.stdout or '"resolved":' in result.stdout
    assert '"candidates":' in result.stdout


def test_cli_identify_file_json_returns_array(tmp_path):
    path = tmp_path / "hashes.txt"
    path.write_text(
        "5f4dcc3b5aa765d61d8327deb882cf99\n"
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\n",
        encoding="utf-8",
    )
    result = runner.invoke(app, ["identify", str(path), "--file", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert len(data) == 2
    assert all(item["candidates"] for item in data)


def test_cli_identify_json_includes_analysis_for_wrapped_input():
    wrapped = base64.b64encode(
        b"5f4dcc3b5aa765d61d8327deb882cf99"
    ).decode()
    result = runner.invoke(app, ["identify", wrapped, "--json", "--live"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["analysis"]["chain"] == "Base64"
    assert data["analysis"]["selected"] == "5f4dcc3b5aa765d61d8327deb882cf99"


def test_cli_analyze_json():
    result = runner.invoke(
        app,
        ["analyze", "NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk=", "--json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["unwrap_chain"] == "Base64"
    assert data["finalized_input"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert len(data["branches"]) <= len(
        [branch for branch in data["branches"] if branch["terminal"]]
    ) + 4


def test_cli_analyze_reports_alternative_hypotheses():
    payload = json.dumps(
        {
            "first": "5f4dcc3b5aa765d61d8327deb882cf99",
            "second": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        }
    )
    result = runner.invoke(app, ["analyze", payload])
    assert result.exit_code == 0
    assert "Alternative hypotheses" in result.stdout


def test_cli_analyze_binary_archive_file(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("hash.txt", "5f4dcc3b5aa765d61d8327deb882cf99")
    path = tmp_path / "payload.zip"
    path.write_bytes(buffer.getvalue())

    result = runner.invoke(app, ["analyze", "--file", str(path), "--json"])

    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["finalized_input"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert "ArchiveExtract" in data["unwrap_chain"]


def test_cli_analyze_list_ops():
    result = runner.invoke(app, ["analyze", "--list-ops", "--category", "Keyed transforms"])
    assert result.exit_code == 0
    assert "AES-CBC" in result.stdout
    assert "RC4" in result.stdout


def test_cli_analyze_crack_forwards_context(monkeypatch):
    from hashvault.core.orchestrator import ProcessResult
    from hashvault.core.registry import SourceFormat

    captured = {}

    def fake_process_single_hash(**kwargs):
        captured.update(kwargs)
        return ProcessResult(
            raw_input=kwargs["raw_hash"],
            normalized_hash=kwargs["raw_hash"],
            username=None,
            candidate=None,
            plaintext=None,
            cracked=False,
            cached=False,
            tool_used="none",
            error_message="mock",
        )

    monkeypatch.setattr("hashvault.cli.process_single_hash", fake_process_single_hash)
    result = runner.invoke(
        app,
        [
            "analyze",
            "NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk=",
            "--crack",
            "--hint",
            "windows",
            "--format",
            "plain_list",
        ],
    )
    assert result.exit_code == 0
    assert captured["hint_category"] == "windows"
    assert captured["source_format"] == SourceFormat.PLAIN_LIST


def test_cli_selftest_json():
    result = runner.invoke(app, ["selftest", "--no-archives", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["summary"]["failed"] == 0
    assert data["summary"]["operations_missing"] == ["ArchiveExtract"]
    assert len(data["operations"]) == 54
    assert any(item["name"] == "Base64" and item["covered"] for item in data["operations"])


def test_cli_selftest_live():
    result = runner.invoke(app, ["selftest", "--no-archives", "--live"])
    assert result.exit_code == 0
    assert "Matrix:" in result.stdout
    assert "ArchiveExtract" in result.stdout


def test_cli_stats():
    result = runner.invoke(app, ["stats"])
    assert result.exit_code == 0
    assert "HashVault Statistics" in result.stdout


def test_cli_doctor_json():
    result = runner.invoke(app, ["doctor", "--json"])
    if result.exit_code != 0:
        runner.invoke(app, ["setup"])
        result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["ok"] is True
    assert data["summary"]["failures"] == 0
    assert any(check["name"] == "Patterns" for check in data["checks"])


def test_cli_audit_json():
    result = runner.invoke(
        app,
        ["audit", "--pattern", "__no_such_pattern__", "--json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["ok"] is True
    assert data["summary"]["total"] == 0


def test_cli_insights_json():
    result = runner.invoke(app, ["insights", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert "analyses" in data
    assert "cracking" in data
    assert "recommendations" in data


def test_refreshable_completer():
    from hashvault.ui.completers import RefreshableCompleter
    completer = RefreshableCompleter()
    assert completer.completer is not None


def test_cli_parameters_json():
    result = runner.invoke(
        app,
        [
            "parameters",
            "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS3vJ4u",
            "--json",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data[0]["format"] == "bcrypt"
    assert data[0]["parameters"]["cost"] == 12
    assert data[0]["is_slow"] is True


def test_cli_mutate_json():
    context = json.dumps(
        {"keywords": ["Acme"], "username": "alice", "dates": ["2024"]}
    )
    result = runner.invoke(
        app,
        [
            "mutate",
            "--context-json",
            context,
            "--limit",
            "24",
            "--json",
        ],
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["metadata"]["candidate_count"] > 0
    assert any("2024" in candidate for candidate in data["candidates"])


def test_cli_benchmark_layers():
    result = runner.invoke(app, ["benchmark-layers", "--limit", "1"])
    assert result.exit_code == 0
    assert "1/1 passed" in result.stdout


def test_cli_strategies_stats_json():
    result = runner.invoke(app, ["strategies", "stats", "--json"])
    assert result.exit_code == 0
    assert isinstance(json.loads(result.stdout), list)


def test_cli_replay_json(tmp_path):
    raw = base64.b64encode(b"hello").decode()
    recipe = {
        "version": 1,
        "raw_input": raw,
        "finalized_input": "hello",
        "chain": "Base64",
        "terminal": False,
        "kind": "text",
        "required_keys": [],
        "layers": [
            {
                "operation": "Base64",
                "category": "Encoding",
                "depth": 1,
                "input": raw,
                "output": "hello",
                "confidence": 1.0,
                "label": "",
                "metadata": {},
            }
        ],
    }
    path = tmp_path / "recipe.json"
    path.write_text(json.dumps(recipe), encoding="utf-8")
    result = runner.invoke(app, ["replay", str(path), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["verified"] is True
    assert data["finalized_input"] == "hello"



def test_cli_corpus_validate_json():
    result = runner.invoke(app, ["corpus", "validate", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["valid"] is True
    assert data["total_cases"] >= 680


def test_cli_campaign_potfile_and_checkpoint(tmp_path):
    corpus = tmp_path / "corpus.txt"
    corpus.write_text(
        "alice:5f4dcc3b5aa765d61d8327deb882cf99\n",
        encoding="utf-8",
    )
    potfile = tmp_path / "recovered.pot"
    potfile.write_text(
        "5f4dcc3b5aa765d61d8327deb882cf99:password\n",
        encoding="utf-8",
    )
    checkpoint = tmp_path / "campaign.json"
    result = runner.invoke(
        app,
        [
            "campaign",
            "run",
            str(corpus),
            "--potfile",
            str(potfile),
            "--checkpoint",
            str(checkpoint),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.stdout
    data = json.loads(result.stdout)
    assert data["recoveries"][0]["method"] == "known-plaintext"
    assert checkpoint.exists()

    resumed = runner.invoke(
        app,
        ["campaign", "run", str(corpus), "--resume", str(checkpoint), "--json"],
    )
    assert resumed.exit_code == 0, resumed.stdout
    resumed_data = json.loads(resumed.stdout)
    assert resumed_data["recoveries"][0]["method"] == "known-plaintext"


def test_cli_doctor_fix_reports_created_directories(tmp_path, monkeypatch):
    from hashvault.config import load_config

    config = load_config()
    sessions = tmp_path / "sessions"
    monkeypatch.setattr(config.paths, "sessions_dir", str(sessions))
    monkeypatch.setattr("hashvault.cli.load_config", lambda: config)
    result = runner.invoke(app, ["doctor", "--fix", "--json"])
    assert result.exit_code == 0, result.stdout
    data = json.loads(result.stdout)
    assert isinstance(data.get("fixes"), list)
    assert sessions.exists()

def test_cli_convert_paths_json():
    result = runner.invoke(app, ["convert", "--paths", "--json"])
    assert result.exit_code == 0, result.stdout
    data = json.loads(result.stdout)
    assert "converter_store" in data
    assert "conversions_dir" in data
    assert "checkpoints_dir" in data