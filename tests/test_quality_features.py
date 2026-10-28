"""Tests for the quality features: audit, calibration, trials, plan, evidence.

Each feature is exercised on synthetic input so the tests stay fast and do not
depend on hashcat, John or a seeded corpus; the integration cases use the real
catalogue through a temporary database.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest
from sqlalchemy.orm import Session

from hashvault.core.calibration import calibrate, suggested_weights
from hashvault.core.database import init_db, reset_db_engine
from hashvault.core.disambiguation import trial_disambiguate
from hashvault.core.evidence import (
    EvidenceError,
    build_evidence_report,
    generate_keypair,
    sign_report,
    verify_report,
)
from hashvault.core.pattern_audit import audit_patterns
from hashvault.core.planner import (
    MEASURED,
    REFERENCE,
    UNKNOWN,
    count_wordlist,
    format_duration,
    mask_keyspace,
    plan_crack,
)
from hashvault.core.registry import HashCategory
from hashvault.models.orm import CrackedHash, Pattern


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class StubPattern:
    name: str
    regex: str
    hashcat_mode: Optional[int] = None
    confidence_weight: Optional[float] = 0.5
    min_length: Optional[int] = None
    id: int = 0


@dataclass
class StubOutcome:
    status: str
    confidence: Optional[float]
    top_name: Optional[str] = None
    top_weight: Optional[float] = None


@dataclass
class StubCandidate:
    pattern: StubPattern


# ---------------------------------------------------------------------------
# Pattern audit
# ---------------------------------------------------------------------------


def test_audit_flags_invalid_regex():
    report = audit_patterns([StubPattern("broken", "^[unclosed")])
    codes = [issue.code for issue in report.issues]
    assert "invalid_regex" in codes
    assert report.ok is False


def test_audit_flags_too_loose_regex():
    # Matches a string of "!" characters, which cannot be a hash.
    report = audit_patterns(
        [StubPattern("loose", r"^.+$", min_length=32)]
    )
    codes = [issue.code for issue in report.issues]
    assert "too_loose" in codes


def test_audit_flags_ambiguous_tie():
    patterns = [
        StubPattern("a", r"^[0-9a-f]{32}$", 1, 0.24, 32),
        StubPattern("b", r"^[0-9a-f]{32}$", 2, 0.24, 32),
    ]
    report = audit_patterns(patterns)
    ties = [issue for issue in report.issues if issue.code == "ambiguous_tie"]
    assert len(ties) == 1
    assert ties[0].severity == "warning"
    assert "a" in ties[0].detail and "b" in ties[0].detail


def test_audit_treats_different_weights_as_info():
    patterns = [
        StubPattern("a", r"^[0-9a-f]{32}$", 1, 0.9, 32),
        StubPattern("b", r"^[0-9a-f]{32}$", 2, 0.2, 32),
    ]
    report = audit_patterns(patterns)
    codes = [issue.code for issue in report.issues]
    assert "ambiguous_tie" not in codes
    assert "duplicate_regex" in codes


def test_audit_detects_mode_example_mismatch(tmp_path):
    patterns_file = tmp_path / "patterns.json"
    patterns_file.write_text("[]", encoding="utf-8")
    (tmp_path / "patterns.meta.json").write_text(
        json.dumps(
            {
                "16500": {
                    "Name": "JWT (JSON Web Token)",
                    "Example.Hash": "eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig",
                    "Example.Hash.Format": "plain",
                }
            }
        ),
        encoding="utf-8",
    )

    # The pattern claims the mode but rejects its example.
    report = audit_patterns(
        [StubPattern("JWT (JSON Web Token)", r"^\$never\$matches$", 16500, 0.9)],
        patterns_file=patterns_file,
    )
    codes = [issue.code for issue in report.issues]
    assert "self_mismatch" in codes
    assert report.ok is False


def test_audit_accepts_when_a_sibling_pattern_matches_the_example(tmp_path):
    patterns_file = tmp_path / "patterns.json"
    patterns_file.write_text("[]", encoding="utf-8")
    (tmp_path / "patterns.meta.json").write_text(
        json.dumps(
            {
                "12": {
                    "Name": "PostgreSQL",
                    "Example.Hash": "93a8cf6a7d43e3b5bcd2dc6abb3e02c6:2703215",
                    "Example.Hash.Format": "plain",
                }
            }
        ),
        encoding="utf-8",
    )

    patterns = [
        # Stored form: does not match the crackable example.
        StubPattern("PostgreSQL MD5", r"^md5\$?[0-9a-f]{32}$", 12, 0.6),
        # Crackable form: does.
        StubPattern("PostgreSQL", r"^[0-9a-f]{32}:[^\s:]+$", 12, 0.3),
    ]
    report = audit_patterns(patterns, patterns_file=patterns_file)
    codes = [issue.code for issue in report.issues]
    assert "self_mismatch" not in codes


def test_audit_allowlist_suppresses_documented_issues(tmp_path):
    patterns_file = tmp_path / "patterns.json"
    patterns_file.write_text("[]", encoding="utf-8")
    (tmp_path / "patterns.meta.json").write_text(
        json.dumps(
            {
                "300": {
                    "Name": "MySQL 4.1+",
                    "Example.Hash": "fcf7c1b8749cf99d88e5f34271d636178fb5d130",
                    "Example.Hash.Format": "plain",
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "audit_allowlist.json").write_text(
        json.dumps({"known_issues": [{"mode": 300, "code": "self_mismatch"}]}),
        encoding="utf-8",
    )

    patterns = [StubPattern("MySQL 4.1+", r"^\*[A-Fa-f0-9]{40}$", 300, 0.95)]
    suppressed = audit_patterns(patterns, patterns_file=patterns_file)
    assert suppressed.ok is True
    assert suppressed.suppressed == 1

    strict = audit_patterns(
        patterns, patterns_file=patterns_file, allow_known=False
    )
    assert strict.ok is False


def test_real_catalogue_has_no_unaudited_errors():
    """The shipped catalogue must not contain a *new* error-level defect."""
    from hashvault.core.database import get_db_session

    reset_db_engine()
    root = Path(__file__).resolve().parent.parent
    patterns_file = root / "data" / "patterns" / "patterns.json"
    init_db(
        ":memory:",
        seed_patterns_path=patterns_file,
    )
    try:
        with get_db_session() as session:
            patterns = session.query(Pattern).all()
        report = audit_patterns(patterns, patterns_file=patterns_file)
        assert report.ok, [
            f"{issue.code} {issue.pattern_name}: {issue.detail}"
            for issue in report.issues
            if issue.severity == "error"
        ]
    finally:
        reset_db_engine()


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------


def test_brier_score_of_perfect_predictions_is_zero():
    outcomes = [
        StubOutcome("exact", 1.0, "a"),
        StubOutcome("exact", 1.0, "a"),
    ]
    report = calibrate(outcomes)
    assert report.brier_score == pytest.approx(0.0)
    assert report.accuracy == 1.0


def test_brier_score_of_coin_flip_is_quarter():
    report = calibrate([StubOutcome("exact", 0.5, "a")])
    assert report.brier_score == pytest.approx(0.25)


def test_ece_is_zero_when_stated_matches_observed():
    # 10 predictions at 0.3 confidence, 3 of which are correct.
    outcomes = [StubOutcome("exact", 0.3, "a")] * 3 + [
        StubOutcome("mismatch", 0.3, "b")
    ] * 7
    report = calibrate(outcomes)
    assert report.expected_calibration_error == pytest.approx(0.0, abs=1e-9)


def test_ece_is_large_when_wildly_overconfident():
    outcomes = [StubOutcome("mismatch", 0.95, "a")] * 10
    report = calibrate(outcomes)
    assert report.expected_calibration_error > 0.9
    assert report.overconfident is True


def test_isotonic_mapping_is_monotonic():
    outcomes = [
        StubOutcome("mismatch", 0.2, "a"),
        StubOutcome("exact", 0.4, "b"),
        StubOutcome("mismatch", 0.6, "c"),
        StubOutcome("exact", 0.9, "d"),
    ]
    report = calibrate(outcomes)
    ys = [value for _, value in report.isotonic]
    assert ys == sorted(ys), f"isotonic mapping decreased: {ys}"


def test_suggested_weights_skip_rarely_seen_patterns():
    outcomes = [StubOutcome("exact", 0.9, "common")] * 10 + [
        StubOutcome("mismatch", 0.9, "rare")
    ]
    report = calibrate(outcomes)
    weights = suggested_weights(report, min_samples=5)
    assert "common" in weights
    assert "rare" not in weights

    forced = suggested_weights(report, min_samples=5, force=True)
    assert "rare" in forced


def test_suggested_weight_reflects_observed_accuracy():
    outcomes = [StubOutcome("exact", 0.9, "good")] * 9 + [
        StubOutcome("mismatch", 0.9, "good")
    ]
    weights = suggested_weights(calibrate(outcomes), min_samples=5)
    assert 0.8 < weights["good"] <= 1.0


def test_calibration_ignores_skipped_entries():
    outcomes = [
        StubOutcome("skipped", 0.9, "a"),
        StubOutcome("exact", 0.9, "a"),
    ]
    report = calibrate(outcomes)
    assert report.entries == 1


# ---------------------------------------------------------------------------
# Trial disambiguation
# ---------------------------------------------------------------------------


def _candidates(*names):
    return [
        StubCandidate(StubPattern(name, "^x$", index + 1))
        for index, name in enumerate(names)
    ]


def test_trial_resolves_on_first_success():
    seen = []

    def attempt(candidate, remaining):
        seen.append(candidate.pattern.name)
        return candidate.pattern.name == "md5-salted"

    result = trial_disambiguate(
        _candidates("a", "md5-salted", "c"), attempt, max_trials=3
    )

    assert result.resolved is True
    assert result.chosen.pattern.name == "md5-salted"
    assert seen == ["a", "md5-salted"]
    assert [trial.success for trial in result.trials] == [False, True]


def test_trial_stops_at_max_trials():
    calls = []

    def attempt(candidate, remaining):
        calls.append(candidate.pattern.name)
        return False

    result = trial_disambiguate(
        _candidates("a", "b", "c", "d"), attempt, max_trials=2
    )

    assert result.resolved is False
    assert calls == ["a", "b"]
    assert len(result.trials) == 2


def test_trial_respects_the_budget():
    def attempt(candidate, remaining):
        return False

    result = trial_disambiguate(
        _candidates("a", "b", "c"),
        attempt,
        max_trials=3,
        budget_seconds=0.0,
    )

    assert result.resolved is False
    assert result.budget_exhausted is True
    assert result.trials == []


def test_trial_survives_an_engine_exception():
    def attempt(candidate, remaining):
        if candidate.pattern.name == "boom":
            raise RuntimeError("engine crashed")
        return candidate.pattern.name == "good"

    result = trial_disambiguate(
        _candidates("boom", "good"), attempt, max_trials=2
    )

    assert result.resolved is True
    assert result.chosen.pattern.name == "good"
    assert result.trials[0].error is not None
    assert "engine crashed" in result.trials[0].error


def test_trial_passes_remaining_budget_to_the_attempt():
    observed = []

    def attempt(candidate, remaining):
        observed.append(remaining)
        return False

    trial_disambiguate(
        _candidates("a"), attempt, max_trials=1, budget_seconds=30
    )
    assert observed[0] is not None and 0 < observed[0] <= 30


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------


def test_mask_keyspace_counts_classes():
    assert mask_keyspace("?d?d?d?d") == 10 ** 4
    assert mask_keyspace("?l?l") == 26 ** 2
    assert mask_keyspace("?a?b") == 95 * 256
    # Literal characters contribute a factor of one.
    assert mask_keyspace("abc?d") == 10


def test_format_duration_scales():
    assert format_duration(None) == "unknown"
    assert format_duration(0.5).endswith("ms")
    assert format_duration(45).endswith("s")
    assert format_duration(600).endswith("min")
    assert format_duration(7200).endswith("h")
    assert "days" in format_duration(86400 * 3)
    assert "years" in format_duration(86400 * 400)


def test_plan_marks_a_job_infeasible_over_budget():
    plan = plan_crack(
        "5f4dcc3b5aa765d61d8327deb882cf99",
        wordlist_entries=10_000_000,
        rule_count=100,
        measured_rate=1_000_000,
        budget_seconds=60,
    )
    assert plan.keyspace == 1_000_000_000
    assert plan.eta_seconds == pytest.approx(1000.0)
    assert plan.feasible is False
    assert any("longer" in item for item in plan.recommendations)


def test_plan_marks_a_small_job_feasible():
    plan = plan_crack(
        "5f4dcc3b5aa765d61d8327deb882cf99",
        wordlist_entries=1000,
        measured_rate=1_000_000,
        budget_seconds=60,
    )
    assert plan.feasible is True


def test_plan_uses_reference_rates_and_says_so():
    plan = plan_crack("$2b$12$" + "a" * 53, wordlist_entries=1000)
    assert plan.rate_source == REFERENCE
    assert plan.candidates_per_second > 0
    assert plan.eta_seconds is not None


def test_plan_reports_unknown_rate_for_obscure_formats():
    plan = plan_crack("totally-unknown-format", wordlist_entries=1000)
    assert plan.rate_source == UNKNOWN
    assert plan.eta_seconds is None
    assert any("benchmark" in warning for warning in plan.warnings)


def test_plan_prefers_a_measured_rate():
    plan = plan_crack(
        "5f4dcc3b5aa765d61d8327deb882cf99",
        wordlist_entries=1000,
        measured_rate=500,
    )
    assert plan.rate_source == MEASURED
    assert plan.eta_seconds == pytest.approx(2.0)


def test_plan_mask_takes_precedence_over_wordlist():
    plan = plan_crack(
        "5f4dcc3b5aa765d61d8327deb882cf99",
        wordlist_entries=1000,
        mask="?d?d",
        measured_rate=10,
    )
    assert plan.keyspace == 100
    assert plan.warnings


def test_count_wordlist_counts_lines(tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("a\nb\nc\n", encoding="utf-8")
    assert count_wordlist(path) == 3
    assert count_wordlist(tmp_path / "missing.txt") == 0


# ---------------------------------------------------------------------------
# Evidence report
# ---------------------------------------------------------------------------


@pytest.fixture
def cracked_session(tmp_path):
    reset_db_engine()
    engine = init_db(
        tmp_path / "evidence.db",
        seed_patterns_path="data/patterns/patterns.json",
    )
    session = Session(engine)
    pattern = session.query(Pattern).filter_by(name="MD5").first()
    if pattern is None:  # pragma: no cover - seeded catalogue always has MD5
        pattern = Pattern(
            name="MD5", regex=r"^[a-fA-F0-9]{32}$", category=HashCategory.RAW_GENERIC
        )
        session.add(pattern)
        session.commit()
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
    yield session
    session.close()
    reset_db_engine()


def test_evidence_report_never_contains_plaintext(cracked_session):
    report = build_evidence_report(cracked_session)
    serialised = json.dumps(report.payload())
    assert "password" not in serialised
    assert len(report.records) == 1
    # Only a digest of the hash is emitted.
    assert len(report.records[0].hash_digest) == 64


def test_evidence_report_fingerprints_are_stable(cracked_session):
    first = build_evidence_report(cracked_session)
    second = build_evidence_report(cracked_session)
    assert first.database_fingerprint == second.database_fingerprint
    assert first.database_fingerprint != ""


def test_signed_report_verifies(cracked_session):
    private_pem, public_pem = generate_keypair()
    document = sign_report(build_evidence_report(cracked_session), private_pem)

    ok, reasons = verify_report(document, public_pem)
    assert ok is True, reasons


def test_tampering_is_detected(cracked_session):
    private_pem, public_pem = generate_keypair()
    document = sign_report(build_evidence_report(cracked_session), private_pem)

    document["records"][0]["pattern"] = "Something Else"
    ok, reasons = verify_report(document, public_pem)

    assert ok is False
    assert any("modified" in reason for reason in reasons)


def test_verification_without_a_public_key_still_checks_the_payload(
    cracked_session,
):
    private_pem, _ = generate_keypair()
    document = sign_report(build_evidence_report(cracked_session), private_pem)

    ok, _ = verify_report(document)
    assert ok is True

    document["summary"]["total"] = 99
    ok, reasons = verify_report(document)
    assert ok is False
    assert any("digest mismatch" in reason for reason in reasons)


def test_wrong_public_key_is_rejected(cracked_session):
    private_pem, _ = generate_keypair()
    _, other_public = generate_keypair()
    document = sign_report(build_evidence_report(cracked_session), private_pem)

    ok, reasons = verify_report(document, other_public)
    assert ok is False
    assert any("signature" in reason for reason in reasons)


def test_unsigned_document_is_rejected():
    ok, reasons = verify_report({"schema_version": 1})
    assert ok is False
    assert any("not signed" in reason for reason in reasons)


def test_signing_rejects_an_invalid_key():
    # Garbage key material must raise rather than silently produce a signature.
    with pytest.raises(EvidenceError):
        sign_report(None, b"not a pem key")  # type: ignore[arg-type]
