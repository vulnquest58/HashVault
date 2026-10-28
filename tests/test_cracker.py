"""
Unit tests for cracker execution engine using mocked subprocess calls.
"""
import subprocess
from pathlib import Path

from hashvault.config import load_config
from hashvault.core.cracker import HashcatCracker, JohnCracker, create_crack_session
from hashvault.core.registry import HashCategory
from hashvault.models.schemas import PatternSchema


def test_hashcat_cracker_success(mocker, tmp_path):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")

    # Mock find_executable and detect_gpu
    mocker.patch("hashvault.core.cracker.find_executable", return_value="hashcat")
    mocker.patch("hashvault.core.cracker.detect_gpu", return_value=mocker.MagicMock(device_flag="-D 1"))

    session = create_crack_session(config.paths.sessions_dir)
    outfile = Path(session.outfile_path)
    outfile.write_text("password123\n", encoding="utf-8")

    mock_run = mocker.patch("subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(
        args=["hashcat"], returncode=0, stdout="Cracked", stderr=""
    )

    pattern = PatternSchema(
        name="MD5",
        regex="^[a-fA-F0-9]{32}$",
        hashcat_mode=0,
        category=HashCategory.RAW_GENERIC,
        is_slow=False,
    )

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password123\n", encoding="utf-8")

    cracker = HashcatCracker(config)
    result = cracker.crack("5f4dcc3b5aa765d61d8327deb882cf99", pattern, wordlist, session)

    assert result.success is True
    assert result.plaintext == "password123"
    assert session.status == "completed"
    assert mock_run.call_count == 1
    # Verify shell=False was explicitly enforced
    _, kwargs = mock_run.call_args
    assert kwargs.get("shell") is False


def test_hashcat_does_not_strip_embedded_username_fields(mocker, tmp_path):
    """NetNTLM/PostgreSQL inputs use ':' as part of the hash, not user:hash."""
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")

    mocker.patch("hashvault.core.cracker.find_executable", return_value="hashcat")
    mocker.patch("hashvault.core.cracker.detect_gpu", return_value=mocker.MagicMock(device_flag="-D 1"))
    mock_run = mocker.patch("subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(
        args=["hashcat"], returncode=0, stdout="", stderr=""
    )

    pattern = PatternSchema(
        name="NetNTLMv2",
        regex="^[^:]+::[^:]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+$",
        hashcat_mode=5600,
        category=HashCategory.NETWORK_AUTH,
        is_slow=False,
    )
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    session = create_crack_session(config.paths.sessions_dir)

    HashcatCracker(config).crack(
        "admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030",
        pattern,
        wordlist,
        session,
    )

    cmd = mock_run.call_args.args[0]
    assert "--username" not in cmd

    mock_run.reset_mock()
    HashcatCracker(config).crack(
        "admin:5f4dcc3b5aa765d61d8327deb882cf99",
        pattern,
        wordlist,
        create_crack_session(config.paths.sessions_dir),
        use_username=True,
    )
    assert "--username" in mock_run.call_args.args[0]


def test_hashcat_error_output_is_not_treated_as_plaintext(mocker, tmp_path):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")

    mocker.patch("hashvault.core.cracker.find_executable", return_value="hashcat")
    mocker.patch("hashvault.core.cracker.detect_gpu", return_value=mocker.MagicMock(device_flag="-D 1"))

    session = create_crack_session(config.paths.sessions_dir)
    mock_run = mocker.patch("subprocess.run")
    mock_run.return_value = subprocess.CompletedProcess(
        args=["hashcat"], returncode=1, stdout="Separator unmatched", stderr=""
    )

    pattern = PatternSchema(
        name="NetNTLMv2",
        regex="^[^:]+::[^:]+:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+$",
        hashcat_mode=5600,
        category=HashCategory.NETWORK_AUTH,
        is_slow=False,
    )
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")

    result = HashcatCracker(config).crack(
        "admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:"
        "5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e00000000"
        "52920b85f78d013c31cdb3b92f5d765c783030",
        pattern,
        wordlist,
        session,
    )

    assert result.success is False
    assert result.plaintext is None
    assert result.engine_error is True
    assert result.error_message == "Separator unmatched"


def test_hashcat_cracker_timeout(mocker, tmp_path):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")

    mocker.patch("hashvault.core.cracker.find_executable", return_value="hashcat")
    mocker.patch("hashvault.core.cracker.detect_gpu", return_value=mocker.MagicMock(device_flag="-D 1"))

    session = create_crack_session(config.paths.sessions_dir)

    mock_run = mocker.patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="hashcat", timeout=300))

    pattern = PatternSchema(
        name="MD5",
        regex="^[a-fA-F0-9]{32}$",
        hashcat_mode=0,
        category=HashCategory.RAW_GENERIC,
        is_slow=False,
    )

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password123\n", encoding="utf-8")

    cracker = HashcatCracker(config)
    result = cracker.crack("5f4dcc3b5aa765d61d8327deb882cf99", pattern, wordlist, session)

    assert result.success is False
    assert session.status == "timeout"
    assert "timed out" in result.error_message
