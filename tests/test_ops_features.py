"""Tests for doctor diagnostics, integrity audits, and audit insights."""

from datetime import datetime, timezone

from hashvault.config import load_config
from hashvault.core.database import get_session_factory, seed_corpus
from hashvault.core.doctor import FAIL, OK, WARN, run_doctor
from hashvault.core.insights import run_insights
from hashvault.core.integrity import (
    MISMATCH,
    UNSUPPORTED,
    VERIFIED,
    verify_cracked_hashes,
)
from hashvault.models.orm import (
    AnalysisLog,
    CrackAttempt,
    CrackedHash,
    Pattern,
    StrategyStat,
)

MD5 = "5f4dcc3b5aa765d61d8327deb882cf99"
SHA256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"


def test_doctor_reports_ready_environment(test_db_session, tmp_path):
    seed_corpus(get_session_factory(), replace=True)
    config = load_config()
    config.paths.database = str(tmp_path / "test_suite.db")
    config.paths.sessions_dir = str(tmp_path / "sessions")
    config.paths.quick_wordlist = str(tmp_path / "missing-quick.txt")

    report = run_doctor(config, test_db_session)

    checks = {(item.section, item.name): item for item in report.checks}
    assert checks[("Runtime", "Python")].status == OK
    assert checks[("Database", "Patterns")].status == OK
    assert checks[("Database", "Corpus")].status == OK
    assert checks[("Data", "Layer corpus")].status == OK
    assert checks[("Paths", "Quick wordlist")].status == WARN
    assert report.failures == 0
    assert report.ok is True
    assert report.to_dict()["summary"]["failures"] == 0


def test_doctor_flags_missing_enrichment_paths(test_db_session, tmp_path):
    config = load_config()
    config.paths.sessions_dir = str(tmp_path / "sessions")
    config.paths.quick_wordlist = str(tmp_path / "missing-quick.txt")
    config.llm.enabled = True
    config.llm.base_url = "http://10.0.0.5:11434"
    config.enrichment.enabled = True
    config.enrichment.wordlist_paths = [str(tmp_path / "missing-seeds.txt")]

    report = run_doctor(config, test_db_session)

    checks = {(item.section, item.name): item for item in report.checks}
    assert checks[("Optional services", "Local LLM")].status == WARN
    assert checks[("Optional services", "Enrichment")].status == WARN
    assert checks[("Database", "Corpus")].status == FAIL


def test_integrity_audit_detects_mismatch_and_unsupported(test_db_session):
    md5_pattern = (
        test_db_session.query(Pattern).filter(Pattern.hashcat_mode == 0).first()
    )
    sha256_pattern = (
        test_db_session.query(Pattern).filter(Pattern.hashcat_mode == 1400).first()
    )
    unsupported = (
        test_db_session.query(Pattern).filter(Pattern.name.like("%ZIP%")).first()
    )
    assert md5_pattern is not None
    assert sha256_pattern is not None
    assert unsupported is not None

    test_db_session.add_all(
        [
            CrackedHash(
                hash_value=MD5,
                normalized_hash=MD5,
                pattern_id=md5_pattern.id,
                plaintext="password",
                tool_used="builtin",
            ),
            CrackedHash(
                hash_value=SHA256,
                normalized_hash=SHA256,
                pattern_id=sha256_pattern.id,
                plaintext="wrong-password",
                tool_used="builtin",
            ),
            CrackedHash(
                hash_value="zip-target",
                normalized_hash="zip-target",
                pattern_id=unsupported.id,
                plaintext="irrelevant",
                tool_used="hashcat",
            ),
        ]
    )
    test_db_session.commit()

    report = verify_cracked_hashes(test_db_session)
    counts = report.counts()

    assert counts["verified"] == 1
    assert counts["mismatch"] == 1
    assert counts["unsupported"] == 1
    assert counts["errors"] == 0
    assert report.ok is False
    statuses = {item.status for item in report.results}
    assert statuses == {VERIFIED, MISMATCH, UNSUPPORTED}

    filtered = verify_cracked_hashes(test_db_session, pattern_name="md5")
    assert len(filtered.results) == 1
    assert filtered.results[0].status == VERIFIED
    assert filtered.ok is True


def test_insights_aggregates_audit_activity(test_db_session):
    pattern = (
        test_db_session.query(Pattern).filter(Pattern.hashcat_mode == 0).first()
    )
    assert pattern is not None
    now = datetime.now(timezone.utc)
    test_db_session.add_all(
        [
            AnalysisLog(
                raw_input="NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk=",
                finalized_input=MD5,
                resolved=True,
                confidence_score=0.9,
                chosen_pattern_id=pattern.id,
                layers_applied=1,
                layers_json='[{"operation": "Base64"}]',
                timestamp=now,
            ),
            AnalysisLog(
                raw_input="ambiguous",
                finalized_input="ambiguous",
                resolved=False,
                timestamp=now,
            ),
            CrackAttempt(
                raw_input=MD5,
                normalized_hash=MD5,
                pattern_name="MD5",
                tool_used="builtin",
                success=True,
                elapsed_seconds=0.2,
            ),
            CrackAttempt(
                raw_input=SHA256,
                normalized_hash=SHA256,
                pattern_name="SHA2-256",
                tool_used="hashcat",
                success=False,
                elapsed_seconds=0.3,
            ),
            CrackedHash(
                hash_value=MD5,
                normalized_hash=MD5,
                pattern_id=pattern.id,
                plaintext="password",
                tool_used="builtin",
            ),
            StrategyStat(
                feature_key="MD5|builtin|dictionary",
                pattern_name="MD5",
                tool="builtin",
                attack_mode="dictionary",
                attempts=2,
                successes=1,
                total_seconds=0.4,
            ),
        ]
    )
    test_db_session.commit()

    report = run_insights(test_db_session)

    assert report.analyses["total"] == 2
    assert report.analyses["resolved"] == 1
    assert report.analyses["ambiguous"] == 1
    assert report.analyses["resolution_rate"] == 0.5
    assert report.analyses["average_confidence"] == 0.9
    assert report.analyses["top_operations"][0]["operation"] == "Base64"
    assert report.cracking["attempts"] == 2
    assert report.cracking["successes"] == 1
    assert report.cracking["success_rate"] == 0.5
    assert report.cracking["average_seconds"] == 0.25
    assert report.cracked["records"] == 1
    assert report.strategies["rows"] == 1
    assert report.strategies["attempts"] == 2
    assert report.to_dict()["cracking"]["attempts"] == 2
    assert "No crack attempts are recorded" not in report.recommendations
