"""Tests for layered recipes, context mutation, parameters, and retries."""

from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import pytest

from hashvault.analysis.analyzer import AnalysisHandoff
from hashvault.analysis.recipe import AnalysisTrace, Layer
from hashvault.analysis.replay import recipe_to_dict, replay_recipe
from hashvault.analysis.search import DiscoveryResult, SearchConfig
from hashvault.analysis.validators import profile_input
from hashvault.config import load_config
from hashvault.core.ambiguity import ambiguity_payload
from hashvault.core.cracker import CrackResult
from hashvault.core.parameters import analyze_parameters
from hashvault.core.registry import CrackTool
from hashvault.core.strategies import (
    list_strategy_stats,
    rank_tools,
    record_strategy_outcome,
)
from hashvault.layers import benchmark_layers, load_layer_vectors
from hashvault.models.orm import CrackAttempt
from hashvault.mutation.context import ContextProfile
from hashvault.mutation.llm import LLMError, LLMSettings, OllamaSeeder
from hashvault.mutation.service import build_mutation

MD5 = "5f4dcc3b5aa765d61d8327deb882cf99"
SHA256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
BCRYPT = "$2b$04$KKimJWG4bZewL437dNFCoOekyDTTKBjxS.0apAza9s/VtgPjgxbV6"


def test_layer_corpus_roundtrip_with_crack(test_db_session, tmp_path):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")
    vectors = load_layer_vectors()
    assert len(vectors) >= 18
    vector = next(item for item in vectors if item.id == "layer-b64-md5")

    report = benchmark_layers([vector], test_db_session, config, crack=True)

    assert report.summary()["passed"] == 1
    assert report.summary()["cracked"] == 1
    assert report.outcomes[0].chain == ["Base64"]
    assert report.outcomes[0].cracked is True


def test_parameter_analysis_detects_cost_and_iterations():
    bcrypt = analyze_parameters(BCRYPT)
    assert bcrypt.format == "bcrypt"
    assert bcrypt.parameters["cost"] == 4
    assert bcrypt.cost_class == "low"
    assert bcrypt.is_slow is False

    pbkdf2 = analyze_parameters("pbkdf2_sha256$600000$saltvalue$deadbeef")
    assert pbkdf2.format == "django-pbkdf2-sha256"
    assert pbkdf2.parameters["iterations"] == 600000
    assert pbkdf2.cost_class == "moderate"
    assert pbkdf2.is_slow is True

    argon2 = analyze_parameters(
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"
    )
    assert argon2.format == "argon2id"
    assert argon2.parameters["memory_kib"] == 65536
    assert argon2.is_slow is True

    scrypt = analyze_parameters("$scrypt$ln=16,r=8,p=1$c2FsdA$aGFzaA")
    assert scrypt.format == "scrypt"
    assert scrypt.parameters["n"] == 65536
    assert scrypt.is_slow is True


def test_ambiguity_report_flags_close_candidates():
    identification = SimpleNamespace(
        resolved=True,
        method="regex",
        candidates=[
            SimpleNamespace(pattern=SimpleNamespace(name="MD5"), confidence=0.72),
            SimpleNamespace(pattern=SimpleNamespace(name="NTLM"), confidence=0.66),
        ],
    )
    report = ambiguity_payload(identification)
    assert report["requires_confirmation"] is True
    assert report["margin"] == 0.06
    assert report["second_name"] == "NTLM"


def test_mutation_uses_context_and_language_variants():
    profile = ContextProfile.from_mapping(
        {
            "username": "ahmed",
            "organization": "Acme",
            "dates": ["2024"],
            "keywords": ["محمد"],
        }
    )
    result = build_mutation(profile, limit=60, language="both")

    assert result.metadata["seed_count"] >= 4
    assert len(result.candidates) <= 60
    assert any(candidate.startswith("ahmed") for candidate in result.candidates)
    assert any(candidate.lower().startswith("mohamed") for candidate in result.candidates)
    assert "2024" in result.context["dates"]


def test_mutation_uses_authorized_local_enrichment(tmp_path):
    wordlist = tmp_path / "local-names.txt"
    wordlist.write_text("acme2025\nacme-admin\n", encoding="utf-8")
    profile = ContextProfile.from_mapping({"organization": "Acme"})

    result = build_mutation(profile, enrich_paths=[wordlist], limit=80)

    assert str(wordlist) in result.metadata["enrichment_sources"]
    assert any(candidate.startswith("acme2025") for candidate in result.candidates)


def test_llm_seeder_is_disabled_by_default_and_schema_validated(monkeypatch):
    with pytest.raises(LLMError):
        OllamaSeeder(LLMSettings(enabled=False)).suggest(ContextProfile(), [])

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps(
                {"response": json.dumps({"candidates": ["acme2026!", "acme2026"]})}
            ).encode("utf-8")

    monkeypatch.setattr(
        "hashvault.mutation.llm.urllib.request.urlopen",
        lambda *args, **kwargs: FakeResponse(),
    )
    seeder = OllamaSeeder(LLMSettings(enabled=True, max_candidates=5))
    suggestions = seeder.suggest(ContextProfile(organization="Acme"), [])
    assert suggestions == ["acme2026!", "acme2026"]


def test_recipe_serialization_and_replay():
    raw = base64.b64encode(MD5.encode()).decode()
    trace = AnalysisTrace(
        raw_input=raw,
        finalized_input=MD5,
        layers=[
            Layer(
                operation="Base64",
                input_text=raw,
                output_text=MD5,
                confidence=0.7,
                depth=1,
                category="Data format",
            )
        ],
        terminal=True,
    )
    recipe = recipe_to_dict(trace)
    assert recipe["required_keys"] == []
    assert recipe["chain"] == "Base64"

    replayed = replay_recipe(recipe["raw_input"], recipe)
    assert replayed.finalized_input == MD5
    assert replayed.describe() == "Base64"


def test_strategy_feedback_is_aggregated(test_db_session):
    record_strategy_outcome(
        test_db_session,
        pattern_name="MD5",
        tool=CrackTool.BUILTIN,
        attack_mode="dictionary",
        success=True,
        elapsed_seconds=0.25,
    )
    record_strategy_outcome(
        test_db_session,
        pattern_name="MD5",
        tool=CrackTool.BUILTIN,
        attack_mode="dictionary",
        success=False,
        elapsed_seconds=0.5,
    )
    for _ in range(2):
        record_strategy_outcome(
            test_db_session,
            pattern_name="MD5",
            tool=CrackTool.HASHCAT,
            attack_mode="dictionary",
            success=False,
            elapsed_seconds=0.1,
        )
    test_db_session.commit()

    rows = list_strategy_stats(test_db_session)
    row = next(
        item
        for item in rows
        if item.pattern_name == "MD5" and item.tool == "builtin"
    )
    assert row.attempts == 2
    assert row.successes == 1
    assert row.success_rate == 0.5
    assert row.average_seconds == 0.375
    ranked = rank_tools(
        test_db_session,
        pattern_name="MD5",
        tools=[CrackTool.HASHCAT, CrackTool.BUILTIN],
        attack_mode="dictionary",
    )
    assert ranked[0] == CrackTool.BUILTIN


def test_retry_alternative_branch_succeeds(
    test_db_session, tmp_path, monkeypatch
):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")
    raw = "$audit-input$"
    primary = AnalysisTrace(
        raw_input=raw,
        finalized_input=BCRYPT,
        layers=[
            Layer(
                operation="ExtractEmbeddedHash",
                input_text=raw,
                output_text=BCRYPT,
                confidence=0.7,
                depth=1,
                category="Forensics",
            )
        ],
        terminal=True,
    )
    alternative = AnalysisTrace(
        raw_input=raw,
        finalized_input=SHA256,
        layers=[
            Layer(
                operation="Base64",
                input_text=raw,
                output_text=SHA256,
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
        traces=[primary, alternative],
        best=primary,
        nodes_expanded=2,
        elapsed_seconds=0.01,
        truncated=False,
        config=SearchConfig(),
        warnings=[],
    )
    handoff = AnalysisHandoff(
        raw_input=raw,
        trace=primary,
        discovery=discovery,
        primary=primary.finalized_input,
        reason="terminal-hash",
        alternatives=[alternative],
    )
    monkeypatch.setattr(
        "hashvault.core.orchestrator.prepare_input", lambda *a, **k: handoff
    )
    monkeypatch.setattr(
        "hashvault.core.orchestrator._engine_available", lambda *a, **k: True
    )
    seen: list[str] = []

    class FakeCracker:
        def crack(self, **kwargs):
            hash_value = kwargs["hash_value"]
            seen.append(hash_value)
            if SHA256 in hash_value:
                return CrackResult(
                    success=True,
                    session_id=kwargs["session"].session_id,
                    plaintext="password",
                )
            return CrackResult(
                success=False,
                session_id=kwargs["session"].session_id,
                error_message="exhausted",
                engine_error=False,
            )

    monkeypatch.setattr(
        "hashvault.core.orchestrator._make_cracker",
        lambda *a, **k: FakeCracker(),
    )

    from hashvault.core.orchestrator import process_single_hash

    result = process_single_hash(
        raw,
        test_db_session,
        config,
        tool=CrackTool.AUTO,
        auto_confirm=True,
        use_cache=False,
        budget_seconds=30,
    )

    assert result.cracked is True
    assert result.normalized_hash == SHA256
    assert result.budget_seconds == 30
    assert result.attempts is not None
    assert any(
        attempt["success"] and attempt["chain"] == "Base64"
        for attempt in result.attempts
    )
    assert len(seen) >= 2
    assert result.recipe is not None
    assert result.recipe["finalized_input"] == SHA256
    assert test_db_session.query(CrackAttempt).count() >= 2
