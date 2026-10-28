"""Regression tests for the curated HashVault corpus."""

import hashlib
import json
from pathlib import Path

import pytest

from hashvault.config import load_config
from hashvault.core.identifier import get_identifier
from hashvault.core.database import get_session_factory, seed_corpus, seed_patterns
from hashvault.corpus import (
    evaluate_cracking,
    evaluate_identification,
    load_corpus_file,
    load_corpus_from_db,
    load_default_corpora,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HASHCAT_CORPUS = PROJECT_ROOT / "data" / "corpus" / "hashcat_examples.json"
XDF_CORPUS = PROJECT_ROOT / "data" / "corpus" / "0xdf_cases.json"
CRYPTO_CORPUS = PROJECT_ROOT / "data" / "corpus" / "crypto_vectors.json"
PATTERNS_META = PROJECT_ROOT / "data" / "patterns" / "patterns.meta.json"


def _load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_hashcat_corpus_manifest():
    document = _load_json(HASHCAT_CORPUS)
    entries = load_corpus_file(HASHCAT_CORPUS)

    assert document["counts"] == {
        "total": 473,
        "with_plaintext": 472,
        "usable_for_identification": 311,
        "usable_for_cracking": 311,
        "binary_only": 40,
        "truncated": 161,
        "no_example": 1,
    }
    assert len(entries) == 473
    assert sum(entry.usable_for_identification for entry in entries) == 311
    assert sum(entry.usable_for_cracking for entry in entries) == 311
    assert document["source_sha256"] == hashlib.sha256(
        PATTERNS_META.read_bytes()
    ).hexdigest()


def test_xdf_corpus_manifest():
    document = _load_json(XDF_CORPUS)
    entries = load_corpus_file(XDF_CORPUS)

    assert document["counts"] == {
        "total": 20,
        "with_plaintext": 18,
        "identification_only": 2,
    }
    assert len(entries) == 20
    assert sum(bool(entry.expected_plaintext) for entry in entries) == 18
    assert len({entry.id for entry in entries}) == 20


def test_crypto_corpus_manifest():
    document = _load_json(CRYPTO_CORPUS)
    entries = load_corpus_file(CRYPTO_CORPUS)

    assert document["counts"] == {
        "total": 158,
        "with_plaintext": 158,
        "usable_for_identification": 158,
        "usable_for_cracking": 158,
        "verified": 158,
        "modes": 32,
        "upstreams": 6,
    }
    assert len(entries) == 158
    assert len({entry.id for entry in entries}) == 158
    assert len({entry.mode for entry in entries}) == 32
    assert len({entry.upstream_repo for entry in entries}) == 6
    assert all(entry.verified and entry.verification for entry in entries)
    assert all(entry.expected_plaintext for entry in entries)


def test_crypto_corpus_identification_baseline(test_db_session):
    identifier = get_identifier(test_db_session)
    report = evaluate_identification(load_corpus_file(CRYPTO_CORPUS), identifier)
    summary = report.summary()

    assert summary["total_entries"] == 158
    assert summary["evaluated"] == 158
    # 148 with the hand-assigned weights; calibration transforms confidence,
    # not ranking, so this count must not move at all.
    assert summary["exact"] >= 148
    assert summary["identified_any"] == 158
    assert summary["mismatch"] == 0
    assert summary["no_candidates"] == 0
    assert summary["errors"] == 0


def test_corpus_db_seed_round_trip(test_db_session):
    original = load_default_corpora()
    assert seed_corpus(get_session_factory()) == len(original)
    assert seed_corpus(get_session_factory()) == 0

    test_db_session.expire_all()
    loaded = load_corpus_from_db(test_db_session)
    assert len(loaded) == len(original)
    assert {entry.id: entry for entry in loaded} == {
        entry.id: entry for entry in original
    }

    crypto = load_corpus_from_db(test_db_session, ("crypto",))
    assert len(crypto) == 158
    assert {entry.source for entry in crypto} == {"crypto"}


def test_corpus_identification_baseline(test_db_session):
    identifier = get_identifier(test_db_session)
    config = load_config()
    report = evaluate_identification(
        load_default_corpora(), identifier, config=config
    )
    summary = report.summary()

    # 651 bundled entries + 3 from the local CTF/lab tree + 8 from public
    # CTF writeups collected on the web.
    assert summary["total_entries"] == 662
    assert summary["evaluated"] == 500
    assert summary["skipped"] == 162
    assert summary["errors"] == 0
    assert summary["no_candidates"] == 0
    assert summary["mismatch"] <= 23

    # The shipped calibration curve transforms the *reported* confidence, not
    # the ranking.  Measured on this corpus:
    #   raw weights       : exact 337, resolved 328, precision 86.3%, ECE 0.221
    #   + calibration     : exact 337, resolved 302, precision 93.4%, ECE 0.190
    # Top-1 accuracy is unchanged -- that is the invariant this test protects.
    assert summary["exact"] >= 337
    assert summary["identified_any"] >= 478

    resolved_outcomes = [
        outcome
        for outcome in report.outcomes
        if outcome.resolved and outcome.status != "skipped"
    ]
    assert resolved_outcomes, "nothing resolved; the baseline is meaningless"
    precision = (
        sum(1 for o in resolved_outcomes if o.status == "exact")
        / len(resolved_outcomes)
    )
    assert precision >= 0.92, (
        f"resolved-answer precision regressed to {precision:.1%}; "
        "re-run `hashvault calibrate` and revisit auto_select_confidence_threshold"
    )

    by_source = {
        source: [outcome for outcome in report.outcomes if outcome.source == source]
        for source in (
            "hashcat",
            "0xdf",
            "crypto",
            "local-ctf-writeups",
            "ctf-public-writeups",
        )
    }
    assert sum(outcome.status == "exact" for outcome in by_source["0xdf"]) == 20
    assert sum(outcome.status == "exact" for outcome in by_source["hashcat"]) >= 159
    assert sum(outcome.status == "exact" for outcome in by_source["crypto"]) >= 148
    assert all(
        outcome.status in {"exact", "candidate_only"}
        for outcome in by_source["crypto"]
    )
    # The three locally recovered artefacts must all identify to their mode.
    assert len(by_source["local-ctf-writeups"]) == 3
    assert all(
        outcome.status == "exact"
        for outcome in by_source["local-ctf-writeups"]
    )
    # Public CTF corpus: the two bare 32-hex digests are inherently ambiguous
    # (MD5 vs MD4 vs NTLM), so they are allowed to rank a sibling mode first
    # but must stay within the candidate set.
    public = by_source["ctf-public-writeups"]
    assert len(public) == 8
    assert all(
        outcome.status in {"exact", "candidate_only"} for outcome in public
    )
    assert sum(outcome.status == "exact" for outcome in public) >= 6
    for outcome in public:
        reachable = set(outcome.candidate_modes or [])
        reachable.add(outcome.top_mode)
        assert outcome.expected_mode in reachable, (
            f"{outcome.id}: declared mode {outcome.expected_mode} not among "
            f"{sorted(m for m in reachable if m is not None)}"
        )


def test_calibration_artefact_actually_moves_the_needle(test_db_session):
    """The shipped calibration curve must improve stated confidence.

    Guards the feedback loop: if nobody regenerates ``calibration.json`` after
    a catalogue change, expected calibration error drifts back up and this
    fails instead of silently decaying.

    Equally important: the curve must not touch the ranking.  Rewriting
    ``confidence_weight`` instead was tried and reverted -- it demoted NTLM to
    0.25 while MD5, never measured because it never wins, kept 0.40 and
    leapfrogged it on every 32-hex digest.
    """
    from hashvault.core.calibration import calibrate, load_calibration

    patterns_dir = Path(__file__).resolve().parent.parent / "data" / "patterns"
    curve = load_calibration(patterns_dir)
    if not curve:
        pytest.skip("no calibration.json shipped")

    config = load_config()
    report = evaluate_identification(
        load_default_corpora(), get_identifier(test_db_session), config=config
    )
    cal = calibrate(report.outcomes)

    # Hand-assigned weights measure ~0.22 without the curve.
    assert cal.expected_calibration_error <= 0.20, (
        f"ECE drifted to {cal.expected_calibration_error:.3f}; "
        "regenerate with `hashvault calibrate --out "
        "data/patterns/calibration.json`"
    )


def test_calibration_curve_cannot_reorder_candidates(test_db_session):
    """A monotone map must preserve the candidate order exactly."""
    from hashvault.core.calibration import CalibrationMap
    from hashvault.core.identifier import Identifier

    config = {
        "auto_select_confidence_threshold": 0.75,
        "auto_select_margin": 0.2,
    }
    plain = get_identifier(test_db_session)

    # A deliberately extreme but monotone curve.
    steep = Identifier(plain.patterns, calibration=CalibrationMap([(0.0, 0.0), (1.0, 1.0)]))
    flat = Identifier(plain.patterns, calibration=CalibrationMap([]))

    for vector in (
        "5f4dcc3b5aa765d61d8327deb882cf99",
        "32693b11e6aa90eb43d32c72a07ceea6",
        "b4b9b02e6f09a9bd760f388b67351e2b",
    ):
        a = flat.identify(vector, config=config)
        b = steep.identify(vector, config=config)
        assert [c.pattern.name for c in a.candidates] == [
            c.pattern.name for c in b.candidates
        ], f"calibration reordered candidates for {vector}"


def test_calibration_map_is_monotone():
    from hashvault.core.calibration import CalibrationMap

    curve = CalibrationMap([(0.2, 0.1), (0.5, 0.4), (0.9, 0.95)])
    samples = [i / 100 for i in range(101)]
    applied = [curve.apply(value) for value in samples]
    assert applied == sorted(applied), "calibration map is not monotone"


def test_calibration_map_clamps_outside_its_range():
    from hashvault.core.calibration import CalibrationMap

    curve = CalibrationMap([(0.3, 0.2), (0.7, 0.9)])
    assert curve.apply(0.0) == 0.2
    assert curve.apply(1.0) == 0.9
    assert 0.2 <= curve.apply(0.5) <= 0.9


def test_empty_calibration_map_is_a_no_op():
    from hashvault.core.calibration import CalibrationMap

    curve = CalibrationMap([])
    assert not curve
    assert curve.apply(0.42) == 0.42


def test_xdf_corpus_cracking_baseline():
    pytest.importorskip("passlib")
    pytest.importorskip("bcrypt")
    report = evaluate_cracking(load_corpus_file(XDF_CORPUS), load_config())
    summary = report.summary()

    assert summary["attempted"] == 17
    assert summary["cracked"] == 17
    assert summary["failed"] == 0
    assert summary["plaintext_mismatch"] == 0
    assert summary["errors"] == 0
    assert summary["skipped"] == 3


def test_hashcat_corpus_cracking_baseline():
    pytest.importorskip("passlib")
    pytest.importorskip("bcrypt")
    report = evaluate_cracking(load_corpus_file(HASHCAT_CORPUS), load_config())
    summary = report.summary()

    assert summary["attempted"] >= 31
    assert summary["cracked"] == summary["attempted"]
    assert summary["failed"] == 0
    assert summary["plaintext_mismatch"] == 0
    assert summary["errors"] == 0

def test_crypto_corpus_cracking_baseline():
    pytest.importorskip("passlib")
    pytest.importorskip("bcrypt")
    report = evaluate_cracking(load_corpus_file(CRYPTO_CORPUS), load_config())
    summary = report.summary()

    assert summary["attempted"] == 158
    assert summary["cracked"] == 158
    assert summary["failed"] == 0
    assert summary["plaintext_mismatch"] == 0
    assert summary["errors"] == 0
    assert summary["skipped"] == 0

def test_seed_patterns_prunes_legacy_aliases_without_cross_mode_loss(test_db_session):
    from hashvault.models.orm import Pattern

    canonical = test_db_session.query(Pattern).filter_by(name="phpass").one()
    legacy = Pattern(
        name="WordPress MD5 (PHPass)",
        regex=canonical.regex,
        hashcat_mode=400,
        category=canonical.category,
    )
    test_db_session.add(legacy)
    test_db_session.commit()

    seed_patterns(
        get_session_factory(),
        PROJECT_ROOT / "data" / "patterns" / "patterns.json",
    )
    test_db_session.expire_all()

    assert test_db_session.query(Pattern).filter_by(name="WordPress MD5 (PHPass)").first() is None
    assert test_db_session.query(Pattern).filter_by(name="phpass").count() == 1
    assert test_db_session.query(Pattern).filter_by(hashcat_mode=27000).count() == 1
