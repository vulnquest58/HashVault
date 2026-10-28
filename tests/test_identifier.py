"""
Unit tests for hash pattern scoring and identification engine.
"""
import pytest
from sqlalchemy.orm import Session

from hashvault.config import load_config
from hashvault.core.database import init_db, reset_db_engine, seed_patterns
from hashvault.core.identifier import identify
from hashvault.core.registry import HashCategory, ResolutionMethod, SourceFormat
from hashvault.exceptions import NoCandidateError
from hashvault.models.schemas import SourceContext


@pytest.fixture
def db_session(tmp_path):
    reset_db_engine()
    db_file = tmp_path / "test_id.db"
    seed_file = tmp_path / "patterns.json"
    
    # Write a minimal patterns seed
    seed_file.write_text("""[
        {
            "name": "MD5",
            "regex": "^[a-fA-F0-9]{32}$",
            "hashcat_mode": 0,
            "category": "raw_generic",
            "confidence_weight": 0.5,
            "min_length": 32,
            "max_length": 32
        },
        {
            "name": "Kerberos 5 TGS",
            "regex": "^\\\\$krb5tgs\\\\$23\\\\$.*",
            "hashcat_mode": 13100,
            "category": "kerberos",
            "prefix_hint": "$krb5tgs$23$",
            "confidence_weight": 1.0
        }
    ]""")

    engine = init_db(db_file)
    factory = reset_db_engine()
    engine = init_db(db_file, seed_patterns_path=seed_file)
    session = Session(engine)
    yield session
    session.close()
    reset_db_engine()


def test_identify_kerberos_prefix(db_session, tmp_path):
    config = load_config()
    res = identify("$krb5tgs$23$user@domain:hashdata", db_session, config)
    assert res.resolved is True
    assert res.method == ResolutionMethod.PREFIX
    assert res.candidates[0].pattern.name == "Kerberos 5 TGS"


def test_identify_generic_md5_scores_lower(db_session, tmp_path):
    config = load_config()
    res = identify("5f4dcc3b5aa765d61d8327deb882cf99", db_session, config)
    assert res.candidates[0].pattern.name == "MD5"
    assert res.candidates[0].confidence < 0.75  # MD5 confidence penalized due to generic hex length


def test_identify_unknown_hash_raises_nocandidate(db_session):
    config = load_config()
    with pytest.raises(NoCandidateError):
        identify("invalid_hash_value_xyz!", db_session, config)
