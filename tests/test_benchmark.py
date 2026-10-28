"""
Unit test for testing benchmark dataset and performance validation logic.
"""
from pathlib import Path
import json
from hashvault.config import load_config
from hashvault.core.database import init_db, get_db_session
from hashvault.core.orchestrator import process_single_hash

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_benchmark_dataset():
    config = load_config()
    test_hashes_file = PROJECT_ROOT / "data" / "test_hashes.json"
    assert test_hashes_file.exists()

    raw_data = json.loads(test_hashes_file.read_text(encoding="utf-8"))
    hashes = raw_data["vectors"] if isinstance(raw_data, dict) and "vectors" in raw_data else raw_data
    assert len(hashes) >= 30

    init_db(config.paths.database, seed_patterns_path=str(PROJECT_ROOT / "data" / "patterns" / "patterns.json"))

    with get_db_session() as session:
        for entry in hashes:
            res = process_single_hash(
                entry["raw_input"],
                session,
                config,
                auto_confirm=True,
                identify_only=True,
                use_cache=False,
            )
            assert res is not None
            assert res.candidate is not None, entry["id"]
