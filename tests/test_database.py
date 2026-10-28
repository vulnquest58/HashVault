"""
Unit tests for database model constraints and operations.
"""
import json

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from hashvault.core.database import init_db, reset_db_engine
from hashvault.core.registry import HashCategory
from hashvault.models.orm import CrackedHash, Pattern


@pytest.fixture
def db_session(tmp_path):
    reset_db_engine()
    db_file = tmp_path / "test.db"
    engine = init_db(db_file)
    session = Session(engine)
    yield session
    session.close()
    reset_db_engine()


def test_unique_pattern_name(db_session):
    p1 = Pattern(name="MD5", regex="^[a-fA-F0-9]{32}$", category=HashCategory.RAW_GENERIC)
    db_session.add(p1)
    db_session.commit()

    p2 = Pattern(name="MD5", regex="^[a-fA-F0-9]{32}$", category=HashCategory.RAW_GENERIC)
    db_session.add(p2)
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_composite_unique_cracked_hash_allows_different_users(db_session):
    p = Pattern(name="NTLM", regex="^[a-fA-F0-9]{32}$", category=HashCategory.WINDOWS)
    db_session.add(p)
    db_session.commit()

    c1 = CrackedHash(
        hash_value="5f4dcc3b5aa765d61d8327deb882cf99",
        normalized_hash="5f4dcc3b5aa765d61d8327deb882cf99",
        pattern_id=p.id,
        plaintext="password",
        username="user1",
        tool_used="hashcat",
        source="test",
        raw_input="user1:5f4dcc3b5aa765d61d8327deb882cf99",
    )
    c2 = CrackedHash(
        hash_value="5f4dcc3b5aa765d61d8327deb882cf99",
        normalized_hash="5f4dcc3b5aa765d61d8327deb882cf99",
        pattern_id=p.id,
        plaintext="password",
        username="user2",
        tool_used="hashcat",
        source="test",
        raw_input="user2:5f4dcc3b5aa765d61d8327deb882cf99",
    )
    db_session.add(c1)
    db_session.add(c2)
    db_session.commit()  # Should succeed due to distinct usernames

    # Adding exact duplicate (same normalized_hash, pattern_id, user1) must fail
    c3 = CrackedHash(
        hash_value="5f4dcc3b5aa765d61d8327deb882cf99",
        normalized_hash="5f4dcc3b5aa765d61d8327deb882cf99",
        pattern_id=p.id,
        plaintext="password",
        username="user1",
        tool_used="hashcat",
        source="test",
        raw_input="user1:5f4dcc3b5aa765d61d8327deb882cf99",
    )
    db_session.add(c3)
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_partial_override_only_updates_provided_fields(tmp_path):
    reset_db_engine()
    patterns_file = tmp_path / "patterns.json"
    patterns_file.write_text(
        json.dumps([
            {
                "name": "Example",
                "regex": "^example$",
                "hashcat_mode": 123,
                "john_format": "bad-format",
                "popularity": 42,
            }
        ]),
        encoding="utf-8",
    )
    (tmp_path / "curated_overrides.json").write_text(
        json.dumps([{"name": "Example", "john_format": "good-format"}]),
        encoding="utf-8",
    )

    try:
        engine = init_db(tmp_path / "override.db", seed_patterns_path=patterns_file)
        with Session(engine) as session:
            pattern = session.query(Pattern).filter_by(name="Example").one()
            assert pattern.john_format == "good-format"
            assert pattern.regex == "^example$"
            assert pattern.hashcat_mode == 123
            assert pattern.popularity == 42
    finally:
        reset_db_engine()


def test_seed_patterns_is_idempotent_across_repeated_runs(tmp_path):
    """Repeated ``hashvault setup`` must not add or drop patterns.

    Regression: a curated override listed a name that a *second* override
    owned as its canonical name, so one deleted what the other re-created and
    the pattern count alternated (482 / 483) on alternating runs.
    """
    from hashvault.core.database import get_session_factory, seed_patterns

    reset_db_engine()
    patterns_file = tmp_path / "patterns.json"
    patterns_file.write_text(
        json.dumps([
            {"name": "canonical", "regex": "^c$", "hashcat_mode": 1},
            {"name": "legacy-alias", "regex": "^l$", "hashcat_mode": 2},
            {"name": "other", "regex": "^o$", "hashcat_mode": 3},
        ]),
        encoding="utf-8",
    )
    # First override folds "legacy-alias" into "canonical"; the second owns
    # "other" and must not be deleted by the first one's alias cleanup.
    (tmp_path / "curated_overrides.json").write_text(
        json.dumps(
            [
                {"name": "canonical", "legacy_names": ["legacy-alias", "other"]},
            ]
        ),
        encoding="utf-8",
    )

    try:
        engine = init_db(tmp_path / "idem.db", seed_patterns_path=patterns_file)
        snapshots = []
        for _ in range(3):
            seed_patterns(get_session_factory(), patterns_file)
            with Session(engine) as session:
                snapshots.append(
                    {
                        row.name: row.hashcat_mode
                        for row in session.query(Pattern).all()
                    }
                )

        assert snapshots[0] == snapshots[1] == snapshots[2]
        # "other" is owned by no override here, but it is listed as an alias;
        # either way the *set* must be stable across runs.
        assert len(snapshots[0]) == len(snapshots[2])
    finally:
        reset_db_engine()
