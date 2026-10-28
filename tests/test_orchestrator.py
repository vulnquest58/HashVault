"""
Unit tests for CLI commands and orchestrator.
"""
from pathlib import Path
from hashvault.analysis.analyzer import AnalysisHandoff
from hashvault.analysis.recipe import AnalysisTrace, Layer
from hashvault.analysis.search import DiscoveryResult, SearchConfig
from hashvault.analysis.validators import profile_input
from hashvault.config import load_config
from hashvault.core.cracker import CrackResult
from hashvault.core.database import init_db, reset_db_engine, seed_patterns
from hashvault.core.orchestrator import process_single_hash
from hashvault.core.registry import CrackTool, SourceFormat


def _seed_md5_engine(tmp_path):
    """Create an isolated DB seeded with a single MD5 pattern."""
    reset_db_engine()
    db_file = tmp_path / "orch.db"
    seed_file = tmp_path / "patterns.json"
    seed_file.write_text("""[
        {
            "name": "MD5",
            "regex": "^[a-fA-F0-9]{32}$",
            "hashcat_mode": 0,
            "category": "raw_generic",
            "confidence_weight": 0.5,
            "min_length": 32,
            "max_length": 32
        }
    ]""")
    engine = init_db(db_file, seed_patterns_path=seed_file)
    from sqlalchemy.orm import Session
    return Session(engine)


def _offline_config(tmp_path):
    """Return an isolated config for the cache tests."""
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")
    return config


class _StubCracker:
    """Engine stand-in that never spawns a subprocess."""

    def __init__(self, config) -> None:
        self.config = config

    def crack(self, hash_value, pattern, wordlist_path, session, rule_path=None, **kwargs):
        return CrackResult(
            success=False,
            session_id=session.session_id,
            error_message="stub engine: not cracked",
        )


def _go_offline(monkeypatch):
    """Make routing succeed without any external binary being executed."""
    monkeypatch.setattr(
        "hashvault.core.orchestrator._engine_available", lambda tool, config: True
    )
    monkeypatch.setattr(
        "hashvault.core.orchestrator._make_cracker",
        lambda tool, config: _StubCracker(config),
    )


def test_process_single_hash_cache_miss(tmp_path, monkeypatch):
    """An empty cache must not report a hit."""
    _go_offline(monkeypatch)
    session = _seed_md5_engine(tmp_path)
    try:
        res = process_single_hash(
            "5f4dcc3b5aa765d61d8327deb882cf99",
            session,
            _offline_config(tmp_path),
            tool=CrackTool.HASHCAT,
        )
        assert res.cached is False
        assert res.cracked is False
    finally:
        session.close()
        reset_db_engine()


def test_process_single_hash_cache_hit(tmp_path, monkeypatch):
    """A stored plaintext must be returned without re-running an engine."""
    _go_offline(monkeypatch)
    session = _seed_md5_engine(tmp_path)
    try:
        from hashvault.models.orm import CrackedHash, Pattern

        pattern = session.query(Pattern).filter_by(name="MD5").one()
        session.add(
            CrackedHash(
                hash_value="5f4dcc3b5aa765d61d8327deb882cf99",
                normalized_hash="5f4dcc3b5aa765d61d8327deb882cf99",
                pattern_id=pattern.id,
                plaintext="password",
                tool_used="builtin",
                source="test",
                raw_input="5f4dcc3b5aa765d61d8327deb882cf99",
            )
        )
        session.commit()

        config = _offline_config(tmp_path)
        res = process_single_hash(
            "5f4dcc3b5aa765d61d8327deb882cf99",
            session,
            config,
            tool=CrackTool.HASHCAT,
        )

        assert res.cached is True
        assert res.cracked is True
        assert res.plaintext == "password"
    finally:
        session.close()
        reset_db_engine()


def test_cache_entry_is_reverified_when_enabled(tmp_path, monkeypatch):
    """A corrupted cached plaintext must not be served when verification is on."""
    _go_offline(monkeypatch)
    session = _seed_md5_engine(tmp_path)
    try:
        from hashvault.models.orm import CrackedHash, Pattern

        pattern = session.query(Pattern).filter_by(name="MD5").one()
        session.add(
            CrackedHash(
                hash_value="5f4dcc3b5aa765d61d8327deb882cf99",
                normalized_hash="5f4dcc3b5aa765d61d8327deb882cf99",
                pattern_id=pattern.id,
                plaintext="definitely-not-the-password",
                tool_used="builtin",
                source="test",
                raw_input="5f4dcc3b5aa765d61d8327deb882cf99",
            )
        )
        session.commit()

        config = _offline_config(tmp_path)
        config.strategy.verify_cache_entries = True
        res = process_single_hash(
            "5f4dcc3b5aa765d61d8327deb882cf99",
            session,
            config,
            tool=CrackTool.HASHCAT,
        )

        # The bogus entry is rejected, so the result cannot be a cache hit.
        assert res.cached is False
        assert res.cracked is False
    finally:
        session.close()
        reset_db_engine()


def test_explicit_builtin_unsupported_pattern_reports_error(test_db_session):
    config = load_config()
    res = process_single_hash(
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
        test_db_session,
        config,
        tool=CrackTool.BUILTIN,
        forced_pattern="argon2id",
        auto_confirm=True,
    )
    assert res.cracked is False
    assert res.tool_used == "none"
    assert "no built-in verifier" in (res.error_message or "").lower()


def test_process_single_hash_accepts_tool_string(test_db_session):
    config = load_config()
    res = process_single_hash(
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
        test_db_session,
        config,
        tool="builtin",
        forced_pattern="argon2id",
        auto_confirm=True,
    )
    assert res.cracked is False
    assert res.tool_used == "none"
    assert "no built-in verifier" in (res.error_message or "").lower()


def test_auto_does_not_replay_exhausted_search(test_db_session, tmp_path, mocker):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")
    mocker.patch("hashvault.core.orchestrator._engine_available", return_value=True)

    calls = []

    class FakeCracker:
        def crack(self, **kwargs):
            return CrackResult(
                success=False,
                session_id=kwargs["session"].session_id,
                error_message="Hash not cracked by dictionary/rules/mask.",
                engine_error=False,
            )

    def make_cracker(tool, cfg):
        calls.append(tool)
        return FakeCracker()

    mocker.patch("hashvault.core.orchestrator._make_cracker", side_effect=make_cracker)

    process_single_hash(
        "5f4dcc3b5aa765d61d8327deb882cf99",
        test_db_session,
        config,
        tool=CrackTool.AUTO,
        forced_pattern="MD5",
        auto_confirm=True,
        use_cache=False,
    )

    assert calls == [CrackTool.HASHCAT]


def test_auto_falls_back_on_engine_error(test_db_session, tmp_path, mocker):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")
    mocker.patch("hashvault.core.orchestrator._engine_available", return_value=True)

    calls = []

    class FakeCracker:
        def crack(self, **kwargs):
            return CrackResult(
                success=False,
                session_id=kwargs["session"].session_id,
                error_message="Token length exception",
                engine_error=True,
            )

    def make_cracker(tool, cfg):
        calls.append(tool)
        return FakeCracker()

    mocker.patch("hashvault.core.orchestrator._make_cracker", side_effect=make_cracker)

    process_single_hash(
        "5f4dcc3b5aa765d61d8327deb882cf99",
        test_db_session,
        config,
        tool=CrackTool.AUTO,
        forced_pattern="MD5",
        auto_confirm=True,
        use_cache=False,
    )

    assert calls[0] == CrackTool.HASHCAT
    assert CrackTool.BUILTIN in calls

def test_analysis_alternative_recovers_unidentified_primary(test_db_session, monkeypatch):
    config = load_config()
    md5 = "5f4dcc3b5aa765d61d8327deb882cf99"
    raw = "NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk="
    bad_trace = AnalysisTrace(
        raw_input=raw,
        finalized_input="not-a-real-hash",
        layers=[
            Layer(
                operation="Base64",
                input_text=raw,
                output_text="not-a-real-hash",
                confidence=0.7,
                depth=1,
                category="Data format",
            )
        ],
        terminal=True,
    )
    good_trace = AnalysisTrace(
        raw_input=raw,
        finalized_input=md5,
        layers=[
            Layer(
                operation="Base64",
                input_text=raw,
                output_text=md5,
                confidence=0.9,
                depth=1,
                category="Data format",
            )
        ],
        terminal=True,
    )
    discovery = DiscoveryResult(
        raw_input=raw,
        profile=profile_input(raw),
        traces=[bad_trace, good_trace],
        best=bad_trace,
        nodes_expanded=2,
        elapsed_seconds=0.01,
        truncated=False,
        config=SearchConfig(),
        warnings=[],
    )
    handoff = AnalysisHandoff(
        raw_input=raw,
        trace=bad_trace,
        discovery=discovery,
        primary=bad_trace.finalized_input,
        reason="terminal-hash",
        alternatives=[good_trace],
    )
    monkeypatch.setattr("hashvault.core.orchestrator.prepare_input", lambda *a, **k: handoff)

    result = process_single_hash(
        raw,
        test_db_session,
        config,
        identify_only=True,
        use_cache=False,
    )

    assert result.normalized_hash == md5
    assert result.candidate is not None
    assert result.analysis["analysis_fallback"] == "analysis-alternative"
    assert any(
        branch["selected"] and branch["finalized_input"] == md5
        for branch in result.analysis["branches"]
    )


def test_resolved_analysis_alternative_beats_ambiguous_primary(test_db_session, monkeypatch):
    config = load_config()
    md5 = "5f4dcc3b5aa765d61d8327deb882cf99"
    kerberos = "$krb5tgs$23$user@domain:hashdata"
    primary = AnalysisTrace(raw_input=md5, finalized_input=md5, layers=[], terminal=True)
    alternative = AnalysisTrace(
        raw_input=md5,
        finalized_input=kerberos,
        layers=[
            Layer(
                operation="ExtractEmbeddedHash",
                input_text=md5,
                output_text=kerberos,
                confidence=0.8,
                depth=1,
                category="Forensics",
            )
        ],
        terminal=True,
    )
    discovery = DiscoveryResult(
        raw_input=md5,
        profile=profile_input(md5),
        traces=[primary, alternative],
        best=primary,
        nodes_expanded=2,
        elapsed_seconds=0.01,
        truncated=False,
        config=SearchConfig(),
        warnings=[],
    )
    handoff = AnalysisHandoff(
        raw_input=md5,
        trace=primary,
        discovery=discovery,
        primary=md5,
        reason="terminal-hash",
        alternatives=[alternative],
    )
    monkeypatch.setattr("hashvault.core.orchestrator.prepare_input", lambda *a, **k: handoff)

    result = process_single_hash(
        md5,
        test_db_session,
        config,
        identify_only=True,
        use_cache=False,
    )

    assert result.normalized_hash == kerberos
    assert result.candidate is not None
    assert result.candidate.pattern.name.startswith("Kerberos 5 TGS")


def test_analysis_bad_terminal_falls_back_to_original(test_db_session, monkeypatch):
    config = load_config()
    raw = "5f4dcc3b5aa765d61d8327deb882cf99"
    bogus = "not-a-real-hash"
    trace = AnalysisTrace(
        raw_input=raw,
        finalized_input=bogus,
        layers=[
            Layer(
                operation="Base64",
                input_text=raw,
                output_text=bogus,
                confidence=0.7,
                depth=1,
                category="Data format",
            )
        ],
        terminal=True,
    )
    discovery = DiscoveryResult(
        raw_input=raw,
        profile=profile_input(raw),
        traces=[trace],
        best=trace,
        nodes_expanded=1,
        elapsed_seconds=0.01,
        truncated=False,
        config=SearchConfig(),
        warnings=[],
    )
    handoff = AnalysisHandoff(
        raw_input=raw,
        trace=trace,
        discovery=discovery,
        primary=bogus,
        reason="terminal-hash",
    )
    monkeypatch.setattr("hashvault.core.orchestrator.prepare_input", lambda *a, **k: handoff)

    result = process_single_hash(
        raw,
        test_db_session,
        config,
        identify_only=True,
        use_cache=False,
    )

    assert result.candidate is not None
    assert result.normalized_hash == raw
    assert result.analysis["analysis_fallback"] == "original-input"
