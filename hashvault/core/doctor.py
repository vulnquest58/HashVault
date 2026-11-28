"""Offline environment and capability diagnostics for HashVault."""

from __future__ import annotations

import importlib.util
import json
import platform
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from hashvault.config import Config
from hashvault.core.database import resolve_resource_path
from hashvault.corpus import DEFAULT_CORPUS_FILES
from hashvault.models.orm import CorpusEntryRecord, Pattern, Rule, Wordlist
from hashvault.utils.system import detect_gpu, find_executable

OK = "ok"
WARN = "warn"
FAIL = "fail"


@dataclass
class DoctorCheck:
    section: str
    name: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class DoctorReport:
    checks: list[DoctorCheck] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def failures(self) -> int:
        return sum(1 for check in self.checks if check.status == FAIL)

    @property
    def warnings(self) -> int:
        return sum(1 for check in self.checks if check.status == WARN)

    @property
    def ok(self) -> bool:
        return self.failures == 0

    def summary(self) -> dict[str, int]:
        return {
            "total": len(self.checks),
            "ok": sum(1 for check in self.checks if check.status == OK),
            "warnings": self.warnings,
            "failures": self.failures,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "ok": self.ok,
            "summary": self.summary(),
            "fixes": list(self.fixes),
            "checks": [check.to_dict() for check in self.checks],
        }


def _add(
    report: DoctorReport,
    section: str,
    name: str,
    status: str,
    detail: str,
) -> None:
    report.checks.append(
        DoctorCheck(section=section, name=name, status=status, detail=detail)
    )


def _count_entries(path: Path) -> Optional[int]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("entries", "cases", "vectors"):
            entries = data.get(key)
            if isinstance(entries, list):
                return len(entries)
    return None


def _module_available(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def _check_runtime(report: DoctorReport) -> None:
    version = platform.python_version()
    if sys.version_info >= (3, 11):
        detail = f"{version} on {platform.system()} {platform.machine()}"
        _add(report, "Runtime", "Python", OK, detail)
    else:
        _add(
            report,
            "Runtime",
            "Python",
            FAIL,
            f"{version} is below the supported 3.11 minimum",
        )


def _check_database(
    report: DoctorReport,
    config: Config,
    session: Optional[Session],
    db_error: Optional[str],
) -> None:
    if db_error:
        _add(report, "Database", "Connection", FAIL, db_error)
        return
    if session is None:
        _add(report, "Database", "Connection", FAIL, "No database session available")
        return

    db_path = Path(config.paths.database)
    if db_path.exists():
        _add(report, "Database", "File", OK, str(db_path))
    else:
        _add(report, "Database", "File", WARN, f"Database file not found: {db_path}")

    try:
        pattern_count = session.query(Pattern).count()
        corpus_count = session.query(CorpusEntryRecord).count()
    except Exception as exc:
        _add(report, "Database", "Queries", FAIL, str(exc))
        return

    catalog_path = Path(resolve_resource_path("data/patterns/patterns.json"))
    catalog_count = _count_entries(catalog_path)
    if pattern_count == 0:
        _add(
            report,
            "Database",
            "Patterns",
            FAIL,
            "No patterns registered; run `hashvault setup`",
        )
    elif catalog_count is not None and pattern_count < catalog_count:
        _add(
            report,
            "Database",
            "Patterns",
            FAIL,
            f"{pattern_count} registered, below the {catalog_count}-entry catalogue",
        )
    else:
        detail = f"{pattern_count} registered"
        if catalog_count is not None:
            additions = pattern_count - catalog_count
            detail += f" from a {catalog_count}-entry catalogue"
            if additions > 0:
                detail += f" plus {additions} curated/additional patterns"
        _add(report, "Database", "Patterns", OK, detail)

    file_counts = {
        path.name: _count_entries(path) for path in DEFAULT_CORPUS_FILES
    }
    if corpus_count == 0:
        _add(
            report,
            "Database",
            "Corpus",
            FAIL,
            "No benchmark corpus rows; run `hashvault setup`",
        )
    elif any(count is None for count in file_counts.values()):
        missing = ", ".join(
            name for name, count in file_counts.items() if count is None
        )
        _add(
            report,
            "Database",
            "Corpus",
            WARN,
            f"{corpus_count} rows; unreadable files: {missing}",
        )
    else:
        expected = sum(count or 0 for count in file_counts.values())
        status = OK if corpus_count == expected else WARN
        _add(
            report,
            "Database",
            "Corpus",
            status,
            f"{corpus_count} rows from {expected} bundled entries",
        )


def _check_data(report: DoctorReport, session: Optional[Session]) -> None:
    layer_path = Path(resolve_resource_path("data/corpus/layer_vectors.json"))
    layer_count = _count_entries(layer_path)
    if layer_count is None:
        _add(report, "Data", "Layer corpus", FAIL, f"Missing or invalid: {layer_path}")
    else:
        _add(report, "Data", "Layer corpus", OK, f"{layer_count} deterministic vectors")

    if session is None:
        return
    try:
        wordlists = session.query(Wordlist).count()
        rules = session.query(Rule).count()
    except Exception as exc:
        _add(report, "Data", "Resources", FAIL, str(exc))
        return

    if wordlists == 0:
        _add(
            report,
            "Data",
            "Wordlists",
            WARN,
            "No wordlists registered; built-in default will be used",
        )
    else:
        _add(report, "Data", "Wordlists", OK, f"{wordlists} registered")
    if rules == 0:
        _add(
            report,
            "Data",
            "Rules",
            WARN,
            "No rules registered; rule-based attacks are unavailable",
        )
    else:
        _add(report, "Data", "Rules", OK, f"{rules} registered")


def _check_paths(report: DoctorReport, config: Config) -> None:
    sessions_dir = Path(config.paths.sessions_dir)
    if sessions_dir.exists():
        _add(report, "Paths", "Sessions directory", OK, str(sessions_dir))
    else:
        _add(
            report,
            "Paths",
            "Sessions directory",
            WARN,
            f"Will be created on first crack: {sessions_dir}",
        )

    quick = Path(config.paths.quick_wordlist)
    if quick.exists():
        _add(report, "Paths", "Quick wordlist", OK, str(quick))
    else:
        _add(report, "Paths", "Quick wordlist", WARN, f"Not found: {quick}")

    for label, configured in (
        ("Wordlist directory", config.paths.wordlist_dir),
        ("Rules directory", config.paths.rules_dir),
    ):
        directory = Path(configured)
        if directory.exists():
            _add(report, "Paths", label, OK, str(directory))
        else:
            _add(report, "Paths", label, WARN, f"Not found: {directory}")


def _external_tool_check(
    report: DoctorReport,
    tool: str,
    configured_path: str,
) -> Optional[str]:
    try:
        resolved = find_executable(tool, configured_path)
    except Exception:
        _add(
            report,
            "Engines",
            tool.capitalize(),
            WARN,
            f"Not found: {configured_path}",
        )
        return None
    _add(report, "Engines", tool.capitalize(), OK, resolved)
    return resolved


def _check_engines(
    report: DoctorReport,
    config: Config,
    *,
    probe: bool,
) -> None:
    hashcat_path = _external_tool_check(report, "hashcat", config.paths.hashcat_bin)
    _external_tool_check(report, "john", config.paths.john_bin)

    try:
        from hashvault.core.builtin import _HAS_PASSLIB, _bcrypt
    except Exception as exc:
        _add(report, "Engines", "Built-in", FAIL, str(exc))
        return

    optional = {
        "passlib": _HAS_PASSLIB,
        "bcrypt": _bcrypt is not None,
        "argon2": _module_available("argon2"),
        "django": _module_available("django"),
    }
    detail = ", ".join(
        f"{name}={'yes' if available else 'no'}"
        for name, available in optional.items()
    )
    _add(report, "Engines", "Optional verifiers", OK, detail)

    if probe and hashcat_path:
        gpu = detect_gpu(
            hashcat_path,
            config.timeouts.gpu_detection_seconds,
            backend=config.strategy.hashcat_backend,
        )
        status = OK if gpu.available else WARN
        raw = gpu.details or (
            f"backend={gpu.backend} device_flag={gpu.device_flag}"
        )
        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        detail = lines[0] if lines else raw
        devices = raw.count("Backend Device ID #")
        if gpu.available and devices:
            detail = (
                f"{detail}; {devices} device(s) detected (discovery only)"
            )
        _add(report, "Engines", "Hashcat backend", status, detail[:300])


def _check_builtin_coverage(report: DoctorReport, session: Optional[Session]) -> None:
    if session is None:
        return
    try:
        from hashvault.core.builtin import builtin_supports

        patterns = session.query(Pattern).all()
        supported = sum(1 for pattern in patterns if builtin_supports(pattern))
    except Exception as exc:
        _add(
            report,
            "Engines",
            "Built-in coverage",
            WARN,
            f"Coverage probe failed: {exc}",
        )
        return
    detail = f"{supported}/{len(patterns)} registered patterns have a built-in verifier"
    _add(report, "Engines", "Built-in coverage", OK, detail)


def _check_quality_features(report: DoctorReport, config: Config) -> None:
    """Report the state of the audit/calibration/planning subsystems."""
    data_dir = Path(config.paths.wordlist_dir).parent
    patterns_dir = data_dir / "patterns"

    # Calibrated weights: is the empirical artefact present and usable?
    calibration_file = patterns_dir / "calibrated_weights.json"
    if calibration_file.is_file():
        try:
            payload = json.loads(calibration_file.read_text(encoding="utf-8"))
            weights = payload.get("weights", payload)
            count = len(weights) if isinstance(weights, dict) else 0
            ece = payload.get("expected_calibration_error")
            detail = f"{count} calibrated weight(s) applied on setup"
            if isinstance(ece, (int, float)):
                detail += f"; ECE {ece:.3f}"
            _add(report, "Quality", "Calibration", OK, detail)
        except (OSError, json.JSONDecodeError) as exc:
            _add(
                report,
                "Quality",
                "Calibration",
                WARN,
                f"calibrated_weights.json is unreadable: {exc}",
            )
    else:
        _add(
            report,
            "Quality",
            "Calibration",
            OK,
            "Using shipped weights (run `hashvault calibrate --out` to derive)",
        )

    # Pattern audit allowlist: documents tolerated upstream drift.
    allowlist = patterns_dir / "audit_allowlist.json"
    if allowlist.is_file():
        try:
            payload = json.loads(allowlist.read_text(encoding="utf-8"))
            known = payload.get("known_issues") or []
            _add(
                report,
                "Quality",
                "Audit allowlist",
                OK,
                f"{len(known)} documented upstream issue(s) suppressed",
            )
        except (OSError, json.JSONDecodeError):
            _add(
                report,
                "Quality",
                "Audit allowlist",
                WARN,
                "audit_allowlist.json is unreadable",
            )
    else:
        _add(
            report,
            "Quality",
            "Audit allowlist",
            OK,
            "No allowlist; every audit issue is reported",
        )

    # Trial disambiguation and cache verification toggles.
    trials = bool(getattr(config.strategy, "enable_trial_disambiguation", False))
    budget = float(getattr(config.strategy, "trial_budget_seconds", 0.0) or 0.0)
    _add(
        report,
        "Quality",
        "Trial disambiguation",
        OK if trials else WARN,
        (
            f"Enabled (max {getattr(config.strategy, 'trial_max_candidates', 3)} "
            f"candidates, {budget:g}s budget)"
            if trials
            else "Disabled; ambiguous formats stay unresolved"
        ),
    )

    verify_cache = bool(getattr(config.strategy, "verify_cache_entries", False))
    verify_slow = bool(getattr(config.strategy, "verify_slow_hashes", False))
    if not verify_cache:
        detail = "Disabled; cached plaintexts are trusted as stored"
        status = WARN
    elif verify_slow:
        detail = "Enabled for all formats (including bcrypt/argon2)"
        status = OK
    else:
        detail = "Enabled for fast formats; slow KDFs skipped"
        status = OK
    _add(report, "Quality", "Cache verification", status, detail)

    # Evidence signing availability.
    try:
        import cryptography  # noqa: F401

        _add(
            report,
            "Quality",
            "Evidence signing",
            OK,
            "Ed25519 available (`hashvault evidence --sign-key`)",
        )
    except ImportError:
        _add(
            report,
            "Quality",
            "Evidence signing",
            WARN,
            "cryptography not installed; reports cannot be signed",
        )


def _check_converters(report: DoctorReport, config: Config) -> None:
    """Report the managed converter store and John helper availability."""
    from hashvault.ingestors.converter_store import (
        ConverterStoreError,
        converter_store_status,
        resolve_converter_root,
    )

    try:
        root = resolve_converter_root(config.paths.converters_dir)
        status = converter_store_status(root)
    except (ConverterStoreError, OSError) as exc:
        _add(report, "Converters", "Managed store", WARN, str(exc))
        return
    if status.converters:
        _add(
            report,
            "Converters",
            "Managed store",
            OK,
            f"{status.converters} converter(s), {status.profiles} profile(s) in {status.root}",
        )
    else:
        _add(
            report,
            "Converters",
            "Managed store",
            WARN,
            f"empty store at {status.root}; run `hashvault convert --sync`",
        )
    if status.missing:
        _add(
            report,
            "Converters",
            "Missing profiles",
            WARN,
            ", ".join(status.missing[:8]),
        )
    else:
        _add(report, "Converters", "Missing profiles", OK, "None")


def apply_doctor_fixes(config: Config, report: DoctorReport) -> None:
    """Create safe local directories that doctor expects to exist."""
    directories = (
        ("Sessions directory", config.paths.sessions_dir),
        ("Wordlist directory", config.paths.wordlist_dir),
        ("Rules directory", config.paths.rules_dir),
        ("Converter store", config.paths.converters_dir),
        ("Conversions directory", config.paths.conversions_dir),
        ("Checkpoints directory", config.paths.checkpoints_dir),
    )
    for label, configured in directories:
        directory = Path(configured)
        if directory.exists():
            continue
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            report.fixes.append(f"could not create {label} ({directory}): {exc}")
        else:
            report.fixes.append(f"created {label}: {directory}")


def _check_optional_services(report: DoctorReport, config: Config) -> None:
    if not config.llm.enabled:
        _add(report, "Optional services", "Local LLM", OK, "Disabled")
    else:
        parsed = urlparse(config.llm.base_url)
        host = (parsed.hostname or "").lower()
        if host in {"127.0.0.1", "localhost", "::1"}:
            _add(
                report,
                "Optional services",
                "Local LLM",
                OK,
                f"Enabled for local endpoint {config.llm.base_url} "
                "(no network probe performed)",
            )
        else:
            _add(
                report,
                "Optional services",
                "Local LLM",
                WARN,
                f"Enabled for non-loopback endpoint {config.llm.base_url}; "
                "verify authorization",
            )

    missing = [
        path for path in config.enrichment.wordlist_paths if not Path(path).exists()
    ]
    if not config.enrichment.enabled:
        _add(report, "Optional services", "Enrichment", OK, "Disabled")
    elif missing:
        _add(
            report,
            "Optional services",
            "Enrichment",
            WARN,
            f"Enabled with missing local paths: {', '.join(missing)}",
        )
    elif not config.enrichment.wordlist_paths:
        _add(
            report,
            "Optional services",
            "Enrichment",
            WARN,
            "Enabled without local wordlist paths",
        )
    else:
        _add(
            report,
            "Optional services",
            "Enrichment",
            OK,
            f"{len(config.enrichment.wordlist_paths)} local source(s) configured",
        )


def run_doctor(
    config: Config,
    session: Optional[Session] = None,
    *,
    db_error: Optional[str] = None,
    probe: bool = False,
) -> DoctorReport:
    """Run offline diagnostics without contacting external services."""
    report = DoctorReport()
    _check_runtime(report)
    _check_database(report, config, session, db_error)
    _check_data(report, session)
    _check_paths(report, config)
    _check_engines(report, config, probe=probe)
    _check_builtin_coverage(report, session)
    _check_converters(report, config)
    _check_quality_features(report, config)
    _check_optional_services(report, config)
    return report
