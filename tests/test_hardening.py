"""Regression tests for the hardening pass.

Covers bounded decompression, additive schema migration, prefix-only
identification, session artifact cleanup, John output parsing, and the
loopback-only LLM guard.

Every test is self-contained (``tmp_path`` or plain stubs) so it runs without
hashcat, John, a seeded database, or network access.
"""

from __future__ import annotations

import gzip
import zlib
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import create_engine

from hashvault.analysis.operations import (
    MAX_DECOMPRESS_BYTES,
    GzipDecompress,
    _bounded_decompress,
)
from hashvault.core.cracker import (
    _plaintext_from_show_output,
    create_crack_session,
    purge_session_dirs,
    release_session_artifacts,
)
from hashvault.core.database import ensure_schema, resolve_resource_path
from hashvault.core.identifier import Identifier
from hashvault.core.registry import ResolutionMethod
from hashvault.exceptions import ToolNotFoundError
from hashvault.models.orm import Base
from hashvault.mutation.context import ContextProfile
from hashvault.mutation.llm import LLMError, LLMSettings, OllamaSeeder, _is_loopback
from hashvault.utils.system import find_executable

# ---------------------------------------------------------------------------
# Bounded decompression (compression-bomb resistance)
# ---------------------------------------------------------------------------


def test_bounded_decompress_allows_small_payloads():
    payload = b"hello hashvault"
    assert _bounded_decompress("gzip", gzip.compress(payload)) == payload
    assert _bounded_decompress("zlib", zlib.compress(payload)) == payload


def test_bounded_decompress_rejects_oversized_output():
    bomb = gzip.compress(b"A" * (MAX_DECOMPRESS_BYTES + 1024), compresslevel=9)
    # The compressed form is tiny; only the *output* is huge.
    assert len(bomb) < 200_000
    assert _bounded_decompress("gzip", bomb, limit=4096) is None


def test_bounded_decompress_rejects_invalid_stream():
    assert _bounded_decompress("gzip", b"definitely not gzip") is None
    assert _bounded_decompress("unknown-codec", b"data") is None


def test_gzip_operation_refuses_compression_bomb():
    bomb = gzip.compress(b"B" * (MAX_DECOMPRESS_BYTES + 1024), compresslevel=9)
    assert GzipDecompress().apply(bomb.decode("latin-1")) is None


# ---------------------------------------------------------------------------
# Identifier: a prefix hint is a hint, never a resolution
# ---------------------------------------------------------------------------


class _StubPattern:
    """Minimal stand-in for ``models.orm.Pattern`` (no database required)."""

    def __init__(
        self,
        name: str,
        regex: str,
        prefix_hint: str | None = None,
        confidence_weight: float = 0.5,
    ) -> None:
        self.id = name
        self.name = name
        self.regex = regex
        self.prefix_hint = prefix_hint
        self.confidence_weight = confidence_weight
        self.hashcat_mode = None
        self.john_format = None
        self.popularity = 0
        self.category = "raw_generic"
        self.source_format_hints = None


_SHA512_CRYPT_RE = r"^\$6\$[^$]+\$[0-9a-f]{86}$"


def _sha_crypt_identifier() -> Identifier:
    return Identifier(
        [_StubPattern("sha-crypt", _SHA512_CRYPT_RE, prefix_hint="$6$")]
    )


def test_prefix_only_match_is_not_resolved():
    result = _sha_crypt_identifier().identify("$6$not-a-real-sha512-crypt-value")
    assert result.resolved is False
    assert result.chosen_pattern is None
    assert result.method == ResolutionMethod.AMBIGUOUS.value
    assert result.candidates
    assert result.candidates[0].pattern.name == "sha-crypt"
    assert result.candidates[0].confidence <= 0.3


def test_regex_confirmed_prefix_still_resolves():
    valid = "$6$saltsalt$" + "a" * 86
    result = _sha_crypt_identifier().identify(valid)
    assert result.resolved is True
    assert result.method == ResolutionMethod.PREFIX.value
    assert result.chosen_pattern.name == "sha-crypt"


# ---------------------------------------------------------------------------
# Additive schema migration
# ---------------------------------------------------------------------------


def test_ensure_schema_adds_missing_columns(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE patterns ("
            "id INTEGER PRIMARY KEY, name VARCHAR, regex TEXT)"
        )

    added = ensure_schema(engine)

    assert "patterns.confidence_weight" in added
    # Existing columns must not be touched.
    assert "patterns.name" not in added

    with engine.connect() as conn:
        present = {
            row[1]
            for row in conn.exec_driver_sql('PRAGMA table_info("patterns")')
        }
    model_columns = {
        column.name for column in Base.metadata.tables["patterns"].columns
    }
    assert model_columns <= present
    engine.dispose()


def test_ensure_schema_is_idempotent(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    Base.metadata.create_all(engine)

    assert ensure_schema(engine) == []
    assert ensure_schema(engine) == []
    engine.dispose()


def test_resolve_resource_path_falls_back_to_package_root(tmp_path, monkeypatch):
    # Nothing in tmp_path matches, so resolution must reach the package tree.
    monkeypatch.chdir(tmp_path)
    resolved = resolve_resource_path("hashvault/__init__.py")
    assert resolved.is_file()


def test_resolve_resource_path_falls_back_to_sys_prefix(tmp_path, monkeypatch):
    # Wheel installs place setuptools data-files under sys.prefix, outside the
    # package tree.
    prefix = tmp_path / "prefix"
    resource = prefix / "data" / "corpus" / "vectors.json"
    resource.parent.mkdir(parents=True)
    resource.write_text("[]", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "hashvault.core.database.package_root", lambda: tmp_path / "empty"
    )
    monkeypatch.setattr("hashvault.core.database.sys.prefix", str(prefix))
    assert resolve_resource_path("data/corpus/vectors.json") == resource.resolve()


# ---------------------------------------------------------------------------
# Session artifacts and directories
# ---------------------------------------------------------------------------


def test_release_session_artifacts_removes_plaintext_bearing_files(tmp_path):
    session = create_crack_session(tmp_path, target_hash="deadbeef", tool_used="builtin")
    session_dir = Path(session.outfile_path).parent
    (session_dir / "target.hash").write_text("deadbeef", encoding="utf-8")
    (session_dir / "hashcat.pot").write_text("deadbeef:secret", encoding="utf-8")
    Path(session.outfile_path).write_text("secret\n", encoding="utf-8")

    removed = release_session_artifacts(session)

    assert len(removed) == 3
    assert not (session_dir / "hashcat.pot").exists()
    assert not (session_dir / "target.hash").exists()
    assert not Path(session.outfile_path).exists()


def test_release_session_artifacts_honours_keep_flag(tmp_path):
    session = create_crack_session(tmp_path)
    session_dir = Path(session.outfile_path).parent
    (session_dir / "target.hash").write_text("deadbeef", encoding="utf-8")

    assert release_session_artifacts(session, keep=True) == []
    assert (session_dir / "target.hash").exists()


def test_purge_session_dirs_only_removes_uuid_directories(tmp_path):
    keep_file = tmp_path / "notes.txt"
    keep_file.write_text("keep me", encoding="utf-8")
    keep_dir = tmp_path / "manual"
    keep_dir.mkdir()
    session_dir = tmp_path / str(uuid4())
    session_dir.mkdir()

    removed = purge_session_dirs(tmp_path)

    assert removed == [session_dir]
    assert keep_file.exists()
    assert keep_dir.exists()


def test_purge_session_dirs_dry_run_keeps_everything(tmp_path):
    session_dir = tmp_path / str(uuid4())
    session_dir.mkdir()

    removed = purge_session_dirs(tmp_path, dry_run=True)

    assert removed == [session_dir]
    assert session_dir.exists()


# ---------------------------------------------------------------------------
# John output parsing
# ---------------------------------------------------------------------------


def test_show_output_strips_known_hash_prefix_with_colons():
    target = "user::domain:1122334455667788:deadbeef:0101"
    output = f"{target}:s3cret:with:colons\n1 password hash cracked, 0 left\n"
    assert _plaintext_from_show_output(output, target) == "s3cret:with:colons"


def test_show_output_falls_back_to_single_split():
    assert _plaintext_from_show_output("deadbeef:p@ssw0rd\n", "other:hash") == "p@ssw0rd"


def test_show_output_skips_summary_and_empty_lines():
    assert _plaintext_from_show_output("0 password hashes cracked, 1 left\n", "x") is None
    assert _plaintext_from_show_output("", "x") is None


# ---------------------------------------------------------------------------
# LLM locality guard
# ---------------------------------------------------------------------------


def test_is_loopback_detection():
    assert _is_loopback("http://127.0.0.1:11434/api/generate")
    assert _is_loopback("http://localhost:11434/api/generate")
    assert _is_loopback("http://[::1]:11434/api/generate")
    assert not _is_loopback("http://example.com/api/generate")
    assert not _is_loopback("https://10.0.0.5/api/generate")


def test_llm_refuses_remote_endpoint():
    seeder = OllamaSeeder(
        LLMSettings(enabled=True, base_url="http://example.com")
    )
    with pytest.raises(LLMError):
        seeder.suggest(ContextProfile(username="alice"), [], count=1)


def test_llm_allows_remote_endpoint_when_explicitly_enabled():
    # With the flag on, the locality guard must step aside.  The request then
    # fails at the transport layer (TEST-NET-1 address, nothing listening),
    # which proves we got past the guard.
    seeder = OllamaSeeder(
        LLMSettings(
            enabled=True,
            base_url="http://192.0.2.1:9",
            timeout_seconds=0.2,
            allow_remote_endpoint=True,
        )
    )
    with pytest.raises(LLMError) as excinfo:
        seeder.suggest(ContextProfile(username="alice"), [], count=1)
    assert "non-loopback" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# Binary resolution
# ---------------------------------------------------------------------------


def test_find_executable_raises_for_unknown_tool():
    with pytest.raises(ToolNotFoundError):
        find_executable("hashvault-definitely-not-installed-binary")
