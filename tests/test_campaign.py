"""Tests for proof-carrying corpus recovery campaigns."""

from __future__ import annotations

import base64
import hashlib
import json

from hashvault.campaign import (
    CampaignEngine,
    Target,
    build_certificate,
    generate_certificate_keypair,
    parse_corpus_text,
    sign_certificate,
    verify_certificate,
)
from hashvault.core.builtin import _nt_hash, verify_plaintext
from hashvault.core.registry import HashCategory
from hashvault.models.schemas import PatternSchema


def _md5(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _ntlm(value: str) -> str:
    return _nt_hash(value).hex()


def _ab64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").replace("+", ".").rstrip("=")


def _pbkdf2_sha256_shadow(value: str, salt: bytes = b"fixturesalt", rounds: int = 1) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), salt, rounds, 32)
    return f"$pbkdf2-sha256${rounds}${_ab64encode(salt)}${_ab64encode(digest)}"


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


def test_mixed_shadow_and_pwdump_campaign_regression():
    alice_ntlm = _ntlm("summer")
    bob_shadow = _pbkdf2_sha256_shadow("summer")
    carol_ntlm = _ntlm("Summer2026!")
    dave_slow_shadow = "$6$fixturesalt$placeholderhashvalueforregressiontest0123456789"

    corpus = "\n".join(
        [
            "# Synthetic mixed pwdump + shadow regression fixture",
            f"alice:1000:aad3b435b51404eeaad3b435b51404ee:{alice_ntlm}:::",
            f"bob:{bob_shadow}:19000:0:99999:7:::",
            f"carol:1001:aad3b435b51404eeaad3b435b51404ee:{carol_ntlm}:::",
            f"dave:{dave_slow_shadow}:19000:0:99999:7:::",
        ]
    )

    records = parse_corpus_text(corpus, source="mixed_fixture.txt")
    assert len(records) == 4
    assert [record.metadata.get("format") for record in records] == [
        "pwdump",
        "shadow",
        "pwdump",
        "shadow",
    ]

    ntlm_pattern = PatternSchema(
        name="NTLM",
        regex="^[a-fA-F0-9]{32}$",
        hashcat_mode=1000,
        category=HashCategory.WINDOWS,
        is_slow=False,
    )
    pbkdf2_shadow_pattern = PatternSchema(
        name="PBKDF2-SHA256",
        regex=r"^\$pbkdf2-sha256\$\d+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+$",
        hashcat_mode=10900,
        category=HashCategory.LINUX_UNIX,
        is_slow=False,
    )
    slow_shadow_pattern = PatternSchema(
        name="sha512crypt",
        regex=r"^\$6\$[^$]+\$.+$",
        hashcat_mode=1800,
        category=HashCategory.LINUX_UNIX,
        is_slow=True,
    )

    patterns_by_user = {
        "alice": [ntlm_pattern],
        "bob": [pbkdf2_shadow_pattern],
        "carol": [ntlm_pattern],
        "dave": [slow_shadow_pattern],
    }
    targets = [
        _target(
            f"t{index:04d}",
            record.hash_value,
            patterns_by_user[record.username or ""],
            record.username,
        )
        for index, record in enumerate(records, start=1)
    ]

    report = CampaignEngine(
        targets,
        known_plaintexts={"t0001": "summer"},
        max_candidates=10_000,
    ).run()

    by_user = {target.username: target for target in report.targets}
    assert by_user["alice"].resolved
    assert by_user["alice"].plaintext == "summer"
    assert by_user["alice"].method == "known-plaintext"

    assert by_user["bob"].resolved
    assert by_user["bob"].plaintext == "summer"
    assert by_user["bob"].method == "exact-reuse"

    assert by_user["carol"].resolved
    assert by_user["carol"].plaintext == "Summer2026!"
    assert by_user["carol"].method == "context-mutation"

    assert not by_user["dave"].resolved
    assert any("slow targets" in note for note in report.notes)

    for username in ("alice", "bob", "carol"):
        target = by_user[username]
        assert target.plaintext is not None
        assert (
            verify_plaintext(
                target.normalized_hash,
                target.patterns[0],
                target.plaintext,
            )
            is True
        )
