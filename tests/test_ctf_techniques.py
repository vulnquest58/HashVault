"""Technique coverage for the attack chains documented in the local writeups.

``Writeups_Vulnquest`` (HMV/HTB/THM) and ``vulnquest`` describe the following
credential-attack techniques but ship no raw hash dumps, so this module pins
the *formats* each technique produces and asserts that HashVault maps them to
the matching hashcat mode.

Evidence gathered by scanning 6840 writeup documents:

    kerberoasting      17 files   -> $krb5tgs$23 / $krb5tgs$18
    asrep_roasting     12 files   -> $krb5asrep$23
    responder           6 files   -> NetNTLMv2 challenge/response
    secretsdump         4 files   -> bare NTLM (32 hex)
    ntlm_relay          4 files   -> NTLM / NetNTLMv2
    shadow_file        11 files   -> $6$ / $1$ crypt
    jwt                10 files   -> hashcat -m 16500

Every vector below is a real example taken from the project's own verified
hashcat corpus, so a change in identification behaviour fails this test.
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session

from hashvault.config import load_config
from hashvault.core.database import init_db, reset_db_engine
from hashvault.core.identifier import identify
from hashvault.core.registry import ResolutionMethod
from hashvault.exceptions import NoCandidateError

# (technique, expected hashcat mode, vector, must resolve unambiguously)
TECHNIQUES = [
    (
        "kerberoasting_rc4",
        13100,
        "$krb5tgs$23$*user$realm$test/spn*$b548e10f5694a",
        True,
    ),
    (
        "kerberoasting_aes256",
        19700,
        "$krb5tgs$18$srv_http$synacktiv.local$16ce51f6eb",
        True,
    ),
    (
        "asrep_roasting",
        18200,
        "$krb5asrep$23$user@domain.com:3e156ada591263b8a",
        True,
    ),
    (
        "responder_netntlmv2",
        5600,
        "0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:"
        "aab8bf8675658dd2a939458a1077ba08:"
        "010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700",
        True,
    ),
    (
        "shadow_sha512crypt",
        1800,
        "$6$72820166$U4DVzpcYxgw7MVVDGGvB2/H5lRistD5.Ah4upwENR5UtffLR4X4SxSzfREv8z6wV"
        "l0jRFX40/KnYVvK4829kD1",
        True,
    ),
    ("shadow_md5crypt", 500, "$1$38652870$DUjsu4TTlTsOe/xxZ05uf/", True),
    ("wordpress_phpass", 400, "$P$946647711V1klyitUYhtB8Yw5DMA/w.", True),
    ("drupal7", 7900, "$S$C20340258nzjDWpoQthrdNTR02f0pmev0K/5/Nx80WSkOQcPEQRh", True),
    (
        "jwt_hs256",
        16500,
        "eyJhbGciOiJIUzI1NiJ9.eyIzNDM2MzQyMCI6NTc2ODc1NDd9."
        "f1nXZ3V_Hrr6ee-AFCTLaHRnrkiKmio2t3JqwL32guY",
        True,
    ),
    (
        "jwt_alg_none_empty_signature",
        16500,
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
        "eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
        True,
    ),
    (
        "jwt_long_hs256",
        16500,
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        True,
    ),
    # A bare 32-hex NTLM digest is inherently ambiguous (MD5/NTLM/LM share the
    # shape), so the contract is "NTLM ranks first" -- not "it resolves".
    ("secretsdump_ntlm", 1000, "b4b9b02e6f09a9bd760f388b67351e2b", False),
    (
        "htb_forest_admin_ntlm",
        1000,
        "32693b11e6aa90eb43d32c72a07ceea6",
        False,
    ),
]


@pytest.fixture
def session(tmp_path):
    reset_db_engine()
    engine = init_db(
        tmp_path / "techniques.db",
        seed_patterns_path="data/patterns/patterns.json",
    )
    db_session = Session(engine)
    yield db_session
    db_session.close()
    reset_db_engine()


@pytest.mark.parametrize(
    "technique,expected_mode,vector,must_resolve",
    TECHNIQUES,
    ids=[item[0] for item in TECHNIQUES],
)
def test_technique_maps_to_expected_mode(
    session, technique, expected_mode, vector, must_resolve
):
    config = load_config()

    result = identify(vector, session, config)

    assert result.candidates, f"{technique}: no candidates for {vector[:40]!r}"
    top = result.candidates[0]
    assert top.pattern.hashcat_mode == expected_mode, (
        f"{technique}: expected mode {expected_mode}, "
        f"got {top.pattern.hashcat_mode} ({top.pattern.name})"
    )

    if must_resolve:
        assert result.resolved is True, (
            f"{technique}: expected a resolved identification, got "
            f"{result.method} (conf={top.confidence:.2f})"
        )
        assert result.method != ResolutionMethod.AMBIGUOUS.value
    else:
        # Ambiguous by design: documented in the README.
        assert result.resolved is False


def test_jwt_is_not_hijacked_by_flask_session_cookie(session):
    """Regression: both patterns shared one auto-generated regex and confidence.

    The generated regexes encoded the literal '_' and '-' characters from the
    hashcat example, so a JWT without both was misread as a Flask session
    cookie (mode 29100).  The curated overrides give JWT an ``eyJ`` anchor.
    """
    config = load_config()
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    result = identify(token, session, config)

    modes = [c.pattern.hashcat_mode for c in result.candidates]
    assert 16500 in modes
    assert result.candidates[0].pattern.hashcat_mode == 16500
    assert 29100 not in modes[:1]


def test_unknown_garbage_raises_no_candidate(session):
    config = load_config()
    with pytest.raises(NoCandidateError):
        identify("this-is-not-a-hash-at-all!", session, config)


# ---------------------------------------------------------------------------
# The corpus file built from the local CTF/lab tree
# ---------------------------------------------------------------------------


def test_ctf_corpus_file_is_wired_into_default_corpora():
    from hashvault.corpus import DEFAULT_CORPUS_FILES, DEFAULT_CTF_CORPUS

    assert DEFAULT_CTF_CORPUS in DEFAULT_CORPUS_FILES
    assert DEFAULT_CTF_CORPUS.is_file()


def test_ctf_corpus_entries_load_and_are_marked_identification_only():
    from hashvault.corpus import DEFAULT_CTF_CORPUS, load_corpus_file

    entries = load_corpus_file(DEFAULT_CTF_CORPUS)

    assert len(entries) == 3
    for entry in entries:
        assert entry.source == "local-ctf-writeups"
        # No plaintext was recovered in the source material, so none may be
        # claimed: that keeps them out of the cracking benchmark.
        assert entry.expected_plaintext is None
        assert entry.usable_for_identification is True
        assert entry.usable_for_cracking is False


def test_ctf_corpus_identifies_to_its_declared_mode(session):
    from hashvault.corpus import DEFAULT_CTF_CORPUS, load_corpus_file

    config = load_config()
    for entry in load_corpus_file(DEFAULT_CTF_CORPUS):
        result = identify(entry.raw_input, session, config)
        assert result.candidates, f"{entry.id}: no candidates"
        top = result.candidates[0]
        assert top.pattern.hashcat_mode == entry.mode, (
            f"{entry.id}: corpus says mode {entry.mode}, "
            f"identifier says {top.pattern.hashcat_mode} ({top.pattern.name})"
        )


# ---------------------------------------------------------------------------
# Public corpus gathered from the web (TryHackMe Crack the Hash + writeups)
# ---------------------------------------------------------------------------


def test_public_ctf_corpus_is_wired_into_default_corpora():
    from hashvault.corpus import DEFAULT_CTF_PUBLIC_CORPUS, DEFAULT_CORPUS_FILES

    assert DEFAULT_CTF_PUBLIC_CORPUS in DEFAULT_CORPUS_FILES
    assert DEFAULT_CTF_PUBLIC_CORPUS.is_file()


def test_public_ctf_corpus_every_plaintext_reproduces_its_hash():
    """No entry may rely on a writeup's word: re-derive it here.

    Two published walkthroughs of the same room disagree on one answer, and
    the wrong one does not appear in rockyou at all -- so this check is the
    only thing standing between the corpus and fabricated ground truth.
    """
    import bcrypt
    import hashlib

    from hashvault.core.builtin import _md4
    from hashvault.corpus import DEFAULT_CTF_PUBLIC_CORPUS, load_corpus_file

    entries = load_corpus_file(DEFAULT_CTF_PUBLIC_CORPUS)
    assert len(entries) == 8

    verifiers = {
        0: lambda p: hashlib.md5(p.encode()).hexdigest(),
        100: lambda p: hashlib.sha1(p.encode()).hexdigest(),
        1400: lambda p: hashlib.sha256(p.encode()).hexdigest(),
        900: lambda p: _md4(p.encode()).hex(),
        1000: lambda p: _md4(p.encode("utf-16-le")).hex(),
    }

    for entry in entries:
        plaintext = entry.expected_plaintext
        assert plaintext, f"{entry.id}: every accepted entry needs a plaintext"

        if entry.mode in verifiers:
            produced = verifiers[entry.mode](plaintext)
            assert produced.lower() == entry.raw_input.lower(), (
                f"{entry.id}: mode {entry.mode} plaintext {plaintext!r} does not "
                f"reproduce {entry.raw_input}"
            )
        elif entry.mode == 3200:
            assert bcrypt.checkpw(
                plaintext.encode(), entry.raw_input.encode()
            ), f"{entry.id}: bcrypt plaintext mismatch"
        elif entry.mode == 1800:
            import passlib.hash

            assert passlib.hash.sha512_crypt.verify(
                plaintext, entry.raw_input
            ), f"{entry.id}: sha512-crypt plaintext mismatch"
        else:
            pytest.fail(f"{entry.id}: no verifier for mode {entry.mode}")


def test_public_ctf_corpus_modes_are_reachable_candidates(session):
    """Every declared mode must at least be a candidate for its own hash.

    Bare 32-hex digests are genuinely ambiguous (MD5 / MD4 / NTLM / LM all
    share the shape), so the contract is coverage, not top-1: MD4 (900) sits
    behind NTLM (1000) for the l1q5 vector, and forcing it to win would mean
    inventing a hint the tool does not have.
    """
    from hashvault.corpus import DEFAULT_CTF_PUBLIC_CORPUS, load_corpus_file

    config = load_config()
    for entry in load_corpus_file(DEFAULT_CTF_PUBLIC_CORPUS):
        result = identify(entry.raw_input, session, config)
        modes = [c.pattern.hashcat_mode for c in result.candidates]
        assert entry.mode in modes, (
            f"{entry.id}: declared mode {entry.mode} missing from candidates "
            f"{modes[:10]}"
        )


def test_prefixed_public_ctf_hashes_resolve_unambiguously(session):
    config = load_config()
    prefixed = {
        "thm-crackthehash-l1q4-bcrypt": (
            "$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom",
            3200,
        ),
        "thm-crackthehash-l2q3-sha512crypt": (
            "$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be."
            "cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.",
            1800,
        ),
    }

    for entry_id, (vector, expected_mode) in prefixed.items():
        result = identify(vector, session, config)
        assert result.resolved is True, f"{entry_id}: should resolve"
        assert result.candidates[0].pattern.hashcat_mode == expected_mode


def test_md4_and_ntlm_are_not_interchangeable():
    """Documents the trap behind the l1q5 / l2q2 corpus pair."""
    from hashvault.core.builtin import _md4

    # l1q5: MD4 over ASCII bytes
    assert (
        _md4("Eternity22".encode()).hex()
        == "279412f945939ba78ce0758d3fd83daa"
    )
    # l2q2: NTLM = MD4 over UTF-16LE
    assert (
        _md4("n63umy8lkf4i".encode("utf-16-le")).hex()
        == "1dfeca0c002ae40b8619ecf94819cc1b"
    )
    # The two encodings must not collide
    assert _md4("Eternity22".encode("utf-16-le")).hex() != (
        "279412f945939ba78ce0758d3fd83daa"
    )
