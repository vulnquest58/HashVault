"""Tests for the pure-Python built-in cracking engine."""
import hashlib
from pathlib import Path

import pytest

from hashvault.config import load_config
from hashvault.core.builtin import (
    BuiltinCracker,
    _drupal_hash,
    _md4,
    _nt_hash,
    builtin_supports,
)
from hashvault.core.cracker import create_crack_session
from hashvault.core.registry import HashCategory
from hashvault.models.schemas import PatternSchema


def _pattern(name="MD5", mode=0, **kwargs):
    return PatternSchema(
        name=name,
        regex=kwargs.pop("regex", "^[a-fA-F0-9]{32}$"),
        hashcat_mode=mode,
        category=HashCategory.RAW_GENERIC,
        is_slow=False,
        **kwargs,
    )


def test_md4_vectors():
    assert _md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert _md4(b"a").hex() == "bde52cb31de33e46245e05fbdbd6fb24"
    assert _md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    assert _nt_hash("password").hex() == "8846f7eaee8fb117ad06bdd830b7586c"


def test_drupal7_known_vector():
    target = "$S$C33783772bRXEx1aCsvY.dqgaaSu76XmVlKrW9Qu8IQlvxHlmzLf"
    assert _drupal_hash("hashcat", target) == target
    assert _drupal_hash("wrong", target) != target


def test_netntlmv1_ess_known_vector():
    pattern = _pattern("NetNTLMv1", 5500)
    target = (
        "u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:"
        "9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c"
    )
    from hashvault.core.builtin import _make_verifier

    verifier = _make_verifier(target, pattern)
    assert verifier.fn("hashcat") is True
    assert verifier.fn("wrong") is False


def test_postgresql_md5():
    from hashvault.core.builtin import _make_verifier

    pattern = _pattern("PostgreSQL MD5", 12, regex="^md5[0-9a-f]{32}$")
    verifier = _make_verifier("32e12f215ba27cb750c9e093ce4b5127:postgres", pattern)
    assert verifier.fn("password") is True
    assert verifier.fn("wrong") is False
    assert hashlib.md5(b"passwordpostgres").hexdigest() == "32e12f215ba27cb750c9e093ce4b5127"


def test_mscache_verifier_uses_rid():
    pytest.importorskip("passlib")
    from hashvault.core.builtin import _make_verifier

    pattern = _pattern(
        "MSCache",
        1100,
        regex=r"^[0-9a-f]{32}:[0-9]+$",
    )
    verifier = _make_verifier(
        "4dd8965d1d476fa0d026722989a6b772:3060147285011", pattern
    )
    assert verifier.fn("hashcat") is True
    assert verifier.fn("wrong") is False


def test_dcc2_verifier_parses_hashcat_format():
    pytest.importorskip("passlib")
    from passlib.hash import msdcc2
    from hashvault.core.builtin import _make_verifier

    checksum = msdcc2.hash("hashcat", user="administrator")
    target = f"$DCC2$10240#administrator#{checksum}"
    pattern = _pattern("DCC2", 2100, regex=r"^\$DCC2\$")
    verifier = _make_verifier(target, pattern)

    assert verifier.fn("hashcat") is True
    assert verifier.fn("wrong") is False


def test_wpa_pmkid_known_vector():
    import hashlib
    import hmac
    from hashvault.core.builtin import _make_verifier

    ssid = b"hashcat"
    ap = bytes.fromhex("001122334455")
    sta = bytes.fromhex("66778899aabb")
    pmk = hashlib.pbkdf2_hmac("sha1", b"hashcat", ssid, 4096, 32)
    pmkid = hmac.new(pmk, b"PMK Name" + ap + sta, hashlib.sha1).digest()[:16]
    target = f"{pmkid.hex()}*{ap.hex()}*{sta.hex()}*{ssid.hex()}"

    pattern = _pattern("WPA-PMKID", 22000, regex=r"^\$?[0-9a-f]+\*")
    verifier = _make_verifier(target, pattern)
    assert verifier.fn("hashcat") is True
    assert verifier.fn("wrong") is False


def test_builtin_supports_known_and_unknown():
    assert builtin_supports(_pattern("MD5", 0)) is True
    assert builtin_supports(_pattern("Drupal7", 7900, regex=r"^\$S\$")) is True
    assert builtin_supports(_pattern("argon2id", None, regex=r"^\$argon2id\$")) is False


def test_builtin_supports_respects_optional_dependencies(monkeypatch):
    import hashvault.core.builtin as builtin

    monkeypatch.setattr(builtin, "_HAS_PASSLIB", False)
    assert builtin_supports(_pattern("md5crypt", 500)) is False
    assert builtin_supports(_pattern("MD5", 0)) is True


def test_builtin_cracker_end_to_end(tmp_path):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("wrong\npassword\n", encoding="utf-8")

    target = hashlib.md5(b"password").hexdigest()
    session = create_crack_session(config.paths.sessions_dir)
    result = BuiltinCracker(config).crack(target, _pattern(), wordlist, session)

    assert result.success is True
    assert result.plaintext == "password"
    assert Path(session.outfile_path).read_text(encoding="utf-8").strip() == "password"


def test_builtin_cracker_mask(tmp_path):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")

    target = hashlib.md5(b"ab12").hexdigest()
    session = create_crack_session(config.paths.sessions_dir)
    result = BuiltinCracker(config).crack(
        target,
        _pattern(),
        tmp_path / "unused.txt",
        session,
        attack_mode="mask",
        mask="?l?l?d?d",
        max_candidates=100_000,
    )

    assert result.success is True
    assert result.plaintext == "ab12"


def test_builtin_cracker_hybrid(tmp_path):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("pass\n", encoding="utf-8")

    target = hashlib.md5(b"pass7").hexdigest()
    session = create_crack_session(config.paths.sessions_dir)
    result = BuiltinCracker(config).crack(
        target,
        _pattern(),
        wordlist,
        session,
        attack_mode="hybrid",
        mask="?d",
    )

    assert result.success is True
    assert result.plaintext == "pass7"


def test_builtin_cracker_rules(tmp_path):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password\n", encoding="utf-8")
    rules = tmp_path / "test.rule"
    rules.write_text("u\n", encoding="utf-8")

    target = hashlib.md5(b"PASSWORD").hexdigest()
    session = create_crack_session(config.paths.sessions_dir)
    result = BuiltinCracker(config).crack(
        target, _pattern(), wordlist, session, rule_path=rules
    )

    assert result.success is True
    assert result.plaintext == "PASSWORD"


def test_builtin_cracker_best64_rule_file(tmp_path):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password\n", encoding="utf-8")

    target = hashlib.md5(b"Password!").hexdigest()
    session = create_crack_session(config.paths.sessions_dir)
    result = BuiltinCracker(config).crack(
        target,
        _pattern(),
        wordlist,
        session,
        rule_path=Path("data/rules/best64.rule"),
    )

    assert result.success is True
    assert result.plaintext == "Password!"


def test_builtin_cracker_dupeword_rule(tmp_path):
    """best64.rule includes p1 (append the word once), which must not be skipped."""
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password\n", encoding="utf-8")
    rules = tmp_path / "dupe.rule"
    rules.write_text("p1\n", encoding="utf-8")

    target = hashlib.md5(b"passwordpassword").hexdigest()
    session = create_crack_session(config.paths.sessions_dir)
    result = BuiltinCracker(config).crack(
        target, _pattern(), wordlist, session, rule_path=rules
    )

    assert result.success is True
    assert result.plaintext == "passwordpassword"


def test_builtin_cracker_rejects_unsupported_pattern(tmp_path):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password\n", encoding="utf-8")

    session = create_crack_session(config.paths.sessions_dir)
    result = BuiltinCracker(config).crack(
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
        _pattern("argon2id", None, regex=r"^\$argon2id\$"),
        wordlist,
        session,
    )

    assert result.success is False
    assert "No built-in verifier" in (result.error_message or "")

def test_django_sha1_verifier():
    from hashvault.core.builtin import _make_verifier

    pattern = _pattern("Django (SHA-1)", 124, regex=r"^sha1\$")
    verifier = _make_verifier(
        "sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004",
        pattern,
    )
    assert verifier.fn("john316") is True
    assert verifier.fn("wrong") is False


def test_mysql41_accepts_hash_without_star_prefix():
    pytest.importorskip("passlib")
    from hashvault.core.builtin import _make_verifier

    pattern = _pattern("MySQL4.1/MySQL5", 300, regex=r"^[0-9a-fA-F]{40}$")
    verifier = _make_verifier("fcf7c1b8749cf99d88e5f34271d636178fb5d130", pattern)
    assert verifier.fn("hashcat") is True
    assert verifier.fn("wrong") is False


def test_lm_half_hash_verifier():
    pytest.importorskip("passlib")
    from hashvault.core.builtin import _make_verifier

    pattern = _pattern("LM", 3000, regex=r"^[0-9a-fA-F]{16}$")
    verifier = _make_verifier("299bd128c1101fd6", pattern)
    assert verifier.fn("HASHCAT") is True
    assert verifier.fn("wrong") is False


@pytest.mark.parametrize(
    "mode,target",
    [
        (
            10900,
            "sha256:1000:NjI3MDM3:vVfavLQL9ZWjg8BUMq6/FB8FtpkIGWYk",
        ),
        (
            12000,
            "sha1:1000:MTYwNTM4MDU4Mzc4MzA=:aGghFQBtQ8+WVlMk5GEaMw==",
        ),
        (
            12100,
            "sha512:1000:NzY2:DNWohLbdIWIt4Npk9gpTvA==",
        ),
    ],
)
def test_pbkdf2_variable_digest_length(mode, target):
    from hashvault.core.builtin import _make_verifier

    pattern = _pattern(f"PBKDF2-{mode}", mode, regex=r".*")
    verifier = _make_verifier(target, pattern)
    assert verifier.fn("hashcat") is True
    assert verifier.fn("wrong") is False
