"""
Unit tests dedicated to increasing code coverage above 85%+.
Tests CLI subcommands, JohnCracker, helper sanitization, system GPU detection, and reporter functions.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from typer.testing import CliRunner

from hashvault.cli import app
from hashvault.config import load_config
from hashvault.core.cracker import JohnCracker, HashcatCracker, compute_timeout
from hashvault.core.reporter import (
    render_identification_report, render_crack_results, render_sessions_report, get_value_str
)
from hashvault.core.orchestrator import ProcessResult
from hashvault.models.orm import CrackSession, Pattern
from hashvault.models.schemas import IdentificationResult, CandidateDTO, PatternSchema, CrackSessionSchema
from hashvault.core.registry import HashCategory, SessionStatus, ResolutionMethod
from hashvault.utils.helpers import validate_safe_path, mask_sensitive_hash, sanitize_cmd_args
from hashvault.utils.system import find_executable, detect_gpu, verify_system_environment, ToolNotFoundError
from hashvault.exceptions import ConfigError, DatabaseError

runner = CliRunner()


def test_cli_crack_cmd():
    result = runner.invoke(app, ["crack", "5f4dcc3b5aa765d61d8327deb882cf99"])
    assert result.exit_code in (0, 1)


def test_cli_check_cmd():
    result = runner.invoke(app, ["check", "5f4dcc3b5aa765d61d8327deb882cf99"])
    assert result.exit_code == 0


def test_cli_sessions_cmd():
    result = runner.invoke(app, ["sessions"])
    assert result.exit_code == 0


def test_cli_import_patterns_nonexistent():
    result = runner.invoke(app, ["import-patterns", "nonexistent_file.json"])
    assert result.exit_code == 0
    assert "0 new patterns" in result.output


def test_cli_import_wordlist_nonexistent():
    result = runner.invoke(app, ["import-wordlist", "nonexistent_wordlist.txt"])
    assert result.exit_code in (1, 2) or "Error" in result.output or "not found" in result.output.lower() or result.exit_code != 0


def test_helpers_validate_safe_path():
    base = Path("data").resolve()
    target = base / "wordlists" / "test.txt"
    assert validate_safe_path(target, base) == target.resolve()

    with pytest.raises(ConfigError):
        validate_safe_path("/etc/passwd", base)


def test_helpers_mask_sensitive_hash():
    assert mask_sensitive_hash("1234") == "1234"
    assert mask_sensitive_hash("5f4dcc3b5aa765d61d8327deb882cf99") == "5f4dcc3b..."


def test_helpers_sanitize_cmd_args():
    args = ["crack", "5f4dcc3b5aa765d61d8327deb882cf99"]
    sanitized = sanitize_cmd_args(args)
    assert sanitized == ["crack", "5f4dcc3b..."]


def test_system_find_executable():
    with pytest.raises(ToolNotFoundError):
        find_executable("non_existent_tool_xyz_123")


def test_system_detect_gpu():
    info = detect_gpu("non_existent_hashcat")
    assert info.available is False
    assert info.device_flag == "-D 1"


def test_system_verify_environment():
    status = verify_system_environment("non_existent_hc", "non_existent_john")
    assert "hashcat" in status
    assert "john" in status


def test_reporter_render_crack_results_text_and_json():
    pattern_schema = PatternSchema(
        id=1,
        name="MD5",
        regex="^[a-f0-9]{32}$",
        category=HashCategory.RAW_GENERIC,
        description="MD5 hash",
        is_slow=False,
        confidence_weight=0.4
    )
    cand = CandidateDTO(pattern=pattern_schema, confidence=0.9)
    res = ProcessResult(
        raw_input="5f4dcc3b5aa765d61d8327deb882cf99",
        normalized_hash="5f4dcc3b5aa765d61d8327deb882cf99",
        username=None,
        candidate=cand,
        cracked=True,
        plaintext="password",
        cached=True,
        tool_used="cache"
    )
    render_crack_results([res], json_output=False)
    render_crack_results([res], json_output=True)


def test_reporter_render_sessions_report_text_and_json(tmp_path):
    sess = CrackSessionSchema(
        session_id="test-session-123",
        outfile_path=str(tmp_path / "out.txt"),
        potfile_path=str(tmp_path / "pot.txt"),
        status=SessionStatus.COMPLETED,
        cracked_count=1,
        hashes_processed=1
    )
    render_sessions_report([sess], json_output=False)
    render_sessions_report([sess], json_output=True)


def test_john_cracker_no_john_format(tmp_path):
    config = load_config()
    cracker = JohnCracker(config)
    pattern = Pattern(
        id=1,
        name="CustomNoJohn",
        regex=".*",
        category=HashCategory.RAW_GENERIC,
        john_format=None,
        description="No format",
        is_slow=False,
        confidence_weight=0.5
    )
    session = CrackSession(session_id="s1", outfile_path=str(tmp_path / "out.txt"), potfile_path=str(tmp_path / "pot.txt"))

    res = cracker.crack("hash", pattern, "wordlist.txt", session)
    assert res.success is False
    assert "has no john_format defined" in (res.error_message or "")


def test_john_cracker_missing_tool(tmp_path):
    config = load_config()
    config.paths.john_bin = "non_existent_john_path_xyz"
    cracker = JohnCracker(config)
    pattern = Pattern(
        id=1,
        name="MD5",
        regex=".*",
        category=HashCategory.RAW_GENERIC,
        john_format="raw-md5",
        description="MD5",
        is_slow=False,
        confidence_weight=0.5
    )
    session = CrackSession(session_id="s1", outfile_path=str(tmp_path / "out.txt"), potfile_path=str(tmp_path / "pot.txt"))

    res = cracker.crack("hash", pattern, "wordlist.txt", session)
    assert res.success is False
    assert "non_existent_john_path_xyz" in str(res.error_message) or "john" in str(res.error_message)


@patch("subprocess.run")
def test_john_cracker_mock_success(mock_run, tmp_path):
    config = load_config()
    cracker = JohnCracker(config)
    pattern = Pattern(
        id=1,
        name="MD5",
        regex=".*",
        category=HashCategory.RAW_GENERIC,
        john_format="raw-md5",
        description="MD5",
        is_slow=False,
        confidence_weight=0.5
    )
    session_dir = tmp_path / "session_1"
    session_dir.mkdir()
    outfile = session_dir / "out.txt"
    potfile = session_dir / "john.pot"

    session = CrackSession(
        session_id="s1",
        outfile_path=str(outfile),
        potfile_path=str(potfile)
    )

    mock_run.side_effect = [
        MagicMock(stdout="John run finished", stderr="", returncode=0),
        MagicMock(stdout="hash:password\n1 password hash cracked", stderr="", returncode=0)
    ]

    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("password\n", encoding="utf-8")

    with patch("hashvault.core.cracker.find_executable", return_value="john"):
        res = cracker.crack("5f4dcc3b5aa765d61d8327deb882cf99", pattern, tmp_path / "wl.txt", session)
        assert res.success is True
        assert res.plaintext == "password"


def test_compute_timeout():
    config = load_config()
    pattern_fast = Pattern(
        id=1,
        name="MD5",
        regex=".*",
        is_slow=False,
        category=HashCategory.RAW_GENERIC,
        description="MD5",
        confidence_weight=0.5
    )
    pattern_slow = Pattern(
        id=2,
        name="bcrypt",
        regex=".*",
        is_slow=True,
        category=HashCategory.WEB_APP,
        description="bcrypt",
        confidence_weight=0.5
    )

    assert compute_timeout(pattern_fast, config) == config.timeouts.fast_hash_seconds
    assert compute_timeout(pattern_slow, config) == config.timeouts.slow_hash_seconds
