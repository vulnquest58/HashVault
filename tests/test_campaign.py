"""Tests for proof-carrying corpus recovery campaigns."""

from __future__ import annotations

import hashlib
import json

from hashvault.campaign import (
    CampaignEngine,
    Target,
    build_certificate,
    generate_certificate_keypair,
    iter_corpus_file,
    load_checkpoint,
    parse_corpus_text,
    parse_potfile_text,
    potfile_mapping,
    sign_certificate,
    verify_certificate,
)
from hashvault.core.registry import HashCategory
from hashvault.models.schemas import PatternSchema


def _md5(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _pattern(name: str = "MD5", mode: int = 0, *, slow: bool = False) -> PatternSchema:
    return PatternSchema(
        name=name,
        regex="^[a-fA-F0-9]{32}$",
        hashcat_mode=mode,
        category=HashCategory.RAW_GENERIC,
        is_slow=slow,
    )


def _target(
    target_id: str,
    value: str,
    patterns: list[PatternSchema],
    username: str | None = None,
) -> Target:
    return Target(
        target_id=target_id,
        raw_hash=value,
        normalized_hash=value,
        username=username,
        patterns=patterns,
    )


def test_parse_pwdump_and_shadow_records():
    pwdump = (
        "alice:1000:aad3b435b51404eeaad3b435b51404ee:"
        "8846f7eaee8fb117ad06bdd830b7586c:::"
    )
    pwdump_without_lm = "carol:1001::8846f7eaee8fb117ad06bdd830b7586c:::"
    shadow = "bob:$6$salt$hash:19000:0:99999:7:::"
    records = parse_corpus_text(f"{pwdump}\n{pwdump_without_lm}\n{shadow}\n# ignored\n")
    assert len(records) == 3
    assert records[0].username == "alice"
    assert records[0].hash_value == "8846f7eaee8fb117ad06bdd830b7586c"
    assert records[0].metadata["format"] == "pwdump"
    assert records[1].username == "carol"
    assert records[1].hash_value == "8846f7eaee8fb117ad06bdd830b7586c"
    assert records[2].username == "bob"
    assert records[2].hash_value == "$6$salt$hash"
    assert records[2].metadata["format"] == "shadow"


def test_engine_propagates_exact_reuse():
    targets = [
        _target("t0001", _md5("password"), [_pattern()], "alice"),
        _target("t0002", _md5("password"), [_pattern()], "bob"),
    ]
    report = CampaignEngine(
        targets,
        known_plaintexts={"t0001": "password"},
    ).run()
    assert all(target.resolved for target in report.targets)
    assert targets[0].method == "known-plaintext"
    assert targets[1].method == "exact-reuse"
    assert {recovery.method for recovery in report.recoveries} == {
        "known-plaintext",
        "exact-reuse",
    }


def test_engine_applies_context_mutations():
    targets = [
        _target("t0001", _md5("password"), [_pattern()], "alice"),
        _target("t0002", _md5("Password2026!"), [_pattern()], "bob"),
    ]
    CampaignEngine(
        targets,
        known_plaintexts={"t0001": "password"},
        max_candidates=10_000,
    ).run()
    assert targets[1].resolved
    assert targets[1].plaintext == "Password2026!"
    assert targets[1].method == "context-mutation"


def test_engine_cracks_from_wordlist(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("wrong\nhunter2\n", encoding="utf-8")
    targets = [_target("t0001", _md5("hunter2"), [_pattern()])]
    report = CampaignEngine(targets, wordlist=wordlist).run()
    assert targets[0].resolved
    assert targets[0].plaintext == "hunter2"
    assert targets[0].method == "wordlist"
    assert report.candidates_generated == 2


def test_engine_skips_slow_targets_during_mutations():
    targets = [
        _target("t0001", _md5("password"), [_pattern()], "alice"),
        _target(
            "t0002",
            _md5("Password2026!"),
            [_pattern(slow=True)],
            "bob",
        ),
    ]
    report = CampaignEngine(
        targets,
        known_plaintexts={"t0001": "password"},
        max_candidates=10_000,
    ).run()
    assert targets[0].resolved
    assert not targets[1].resolved
    assert any("slow targets" in note for note in report.notes)


def test_engine_reports_unsupported_targets():
    pattern = PatternSchema(
        name="Unknown Mode",
        regex="^[a-fA-F0-9]{32}$",
        hashcat_mode=999_999,
        category=HashCategory.RAW_GENERIC,
        is_slow=False,
    )
    report = CampaignEngine([_target("t0001", _md5("password"), [pattern])]).run()
    assert not report.targets[0].resolved
    assert any("external backend" in note for note in report.notes)
    assert report.summary()["unresolved"] == 1


def test_plan_orders_reuse_before_mutation_and_wordlist(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password\n", encoding="utf-8")
    targets = [
        _target("t0001", _md5("password"), [_pattern()], "alice"),
        _target("t0002", _md5("Password2026!"), [_pattern()], "bob"),
    ]
    engine = CampaignEngine(
        targets,
        known_plaintexts={"t0001": "password"},
        wordlist=wordlist,
    )
    plan = engine.plan()
    assert [stage.name for stage in plan.stages] == [
        "exact-reuse",
        "context-mutations",
        "wordlist",
    ]
    assert plan.supported_targets == 2
    assert plan.total_targets == 2


def test_certificate_signs_verifies_and_omits_plaintext(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("hunter2\n", encoding="utf-8")
    report = CampaignEngine(
        [_target("t0001", _md5("hunter2"), [_pattern()], "alice")],
        wordlist=wordlist,
    ).run()
    private_pem, public_pem = generate_certificate_keypair()
    document = sign_certificate(build_certificate(report), private_pem)
    assert "hunter2" not in json.dumps(document)
    ok, reasons = verify_certificate(document, public_pem)
    assert ok, reasons
    document["payload"]["targets"][0]["status"] = "tampered"
    ok, reasons = verify_certificate(document, public_pem)
    assert not ok
    assert any("digest mismatch" in reason for reason in reasons)

def test_checkpoint_resumes_verified_recoveries(tmp_path):
    checkpoint = tmp_path / "campaign.json"
    targets = [_target("t0001", _md5("password"), [_pattern()])]
    first = CampaignEngine(
        targets, known_plaintexts={"t0001": "password"}
    ).run(checkpoint_path=checkpoint)
    assert first.targets[0].resolved
    snapshot = load_checkpoint(checkpoint)
    assert "exact-reuse" in snapshot["completed_stages"]

    resumed_targets = [_target("t0001", _md5("password"), [_pattern()])]
    report = CampaignEngine(resumed_targets).run(resume_path=checkpoint)
    assert resumed_targets[0].resolved
    assert resumed_targets[0].method == "known-plaintext"
    assert any("restored 1 verified" in note for note in report.notes)


def test_checkpoint_rejects_plaintext_that_no_longer_verifies(tmp_path):
    checkpoint = tmp_path / "campaign.json"
    targets = [_target("t0001", _md5("password"), [_pattern()])]
    CampaignEngine(targets, known_plaintexts={"t0001": "password"}).run(
        checkpoint_path=checkpoint
    )
    document = load_checkpoint(checkpoint)
    document["targets"][0]["plaintext"] = "wrong"
    checkpoint.write_text(json.dumps(document), encoding="utf-8")
    resumed = [_target("t0001", _md5("password"), [_pattern()])]
    report = CampaignEngine(resumed).run(resume_path=checkpoint)
    assert not resumed[0].resolved
    assert any("rejected 1 checkpoint" in note for note in report.notes)


def test_potfile_parser_decodes_hex_and_last_value_wins():
    entries = parse_potfile_text(
        "abc:plain\n# comment\n$HEX[70617373]:$HEX[70617373]\nabc:last\n"
    )
    assert len(entries) == 3
    assert entries[1].plaintext == "pass"
    assert potfile_mapping(entries) == {"abc": "last", "$HEX[70617373]": "pass"}


def test_iter_corpus_file_streams_records(tmp_path):
    corpus = tmp_path / "corpus.txt"
    corpus.write_text(
        "alice:" + _md5("password") + "\n# comment\n"
        "bob:" + _md5("hunter2") + "\n",
        encoding="utf-8",
    )
    records = list(iter_corpus_file(corpus))
    assert [record.username for record in records] == ["alice", "bob"]
