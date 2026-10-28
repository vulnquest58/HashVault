"""
Global Pytest configuration and shared fixtures for HashVault test suite.
"""
import os

import pytest
from sqlalchemy.orm import Session

from hashvault.core.database import init_db, reset_db_engine, seed_patterns


@pytest.fixture(scope="session", autouse=True)
def _isolate_runtime_paths(tmp_path_factory):
    """Keep test runs from writing sessions/logs into the repository.

    Prior runs created thousands of ``sessions/<uuid>/`` directories inside the
    checkout because every test loaded the real ``config/default.yaml``.  The
    environment override is applied by ``load_config`` *after* the YAML file,
    so it wins here.
    """
    root = tmp_path_factory.mktemp("hashvault-runtime")
    overrides = {
        "HASHVAULT_PATHS__SESSIONS_DIR": str(root / "sessions"),
        "HASHVAULT_PATHS__DATABASE": str(root / "hashvault.sqlite3"),
        "HASHVAULT_OUTPUT__LOG_FILE": str(root / "hashvault.log"),
    }
    previous = {key: os.environ.get(key) for key in overrides}
    os.environ.update(overrides)
    yield root
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


@pytest.fixture
def test_db_session(tmp_path):
    reset_db_engine()
    db_file = tmp_path / "test_suite.db"
    seed_file = "data/patterns/patterns.json"
    engine = init_db(db_file, seed_patterns_path=seed_file)
    session = Session(engine)
    yield session
    session.close()
    reset_db_engine()
