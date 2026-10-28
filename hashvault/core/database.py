# hashvault/core/database.py
"""
Database management for HashVault.
Handles engine creation, session management, and initialization.
"""

import hashlib
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from contextlib import contextmanager
from typing import Iterable, Iterator, Optional, Generator

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from hashvault.models.orm import (
    AnalysisLog, Base, CorpusEntryRecord, CrackedHash, CrackSession,
    IdentificationLog, Pattern,
)
from hashvault.exceptions import DatabaseError, HashVaultError
from hashvault.core.registry import HashCategory

logger = logging.getLogger("hashvault.database")


def package_root() -> Path:
    """Absolute path to the installed repository/package root."""
    return Path(__file__).resolve().parent.parent.parent


def resolve_resource_path(path: str | Path) -> Path:
    """Resolve a bundled resource path to an absolute path.

    A relative path is tried against the current directory first (so working
    inside the repository keeps behaving as before) and then against the
    package root.  Without that second step, ``hashvault setup`` launched from
    any other directory silently seeded an empty pattern catalogue, and every
    later ``identify`` failed with "No patterns in database".
    """
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    if candidate.exists():
        return candidate.resolve()
    fallback = (package_root() / candidate).resolve()
    if fallback.exists():
        return fallback
    return candidate


def _literal_default(column) -> Optional[str]:  # type: ignore[no-untyped-def]
    """Render a Python-side column default as a SQL literal, when possible."""
    default = column.default
    if default is None or not getattr(default, "is_scalar", False):
        return None
    value = default.arg
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    return None


def _column_definition(column, dialect) -> tuple[str, bool]:  # type: ignore[no-untyped-def]
    """Build the ``ADD COLUMN`` clause body for ``column``.

    Returns ``(sql_fragment, made_nullable)``.  SQLite only allows adding a
    NOT NULL column when a non-NULL default is supplied, so a callable default
    (``datetime.utcnow``) falls back to ``CURRENT_TIMESTAMP`` for timestamps
    and to a nullable column otherwise.
    """
    type_sql = column.type.compile(dialect)
    default_sql = _literal_default(column)

    if default_sql is not None:
        return f"{type_sql} DEFAULT {default_sql}", False

    if column.server_default is not None:
        try:
            server_sql = str(column.server_default.arg)
        except Exception:  # pragma: no cover - non-textual default
            server_sql = ""
        if server_sql:
            return f"{type_sql} DEFAULT {server_sql}", False

    if column.nullable:
        return type_sql, False

    # NOT NULL with no literal default.
    type_name = type(column.type).__name__.lower()
    if "date" in type_name or "time" in type_name:
        return f"{type_sql} DEFAULT CURRENT_TIMESTAMP", False

    return type_sql, True


def ensure_schema(engine: Engine) -> list[str]:
    """Add columns that exist in the models but not yet in the database.

    ``Base.metadata.create_all`` creates missing *tables* but never alters
    existing ones, so every release that added a column left upgraded
    installations in an inconsistent state (``no such column`` at query time).
    SQLite supports ``ALTER TABLE ... ADD COLUMN`` for nullable/defaulted
    columns, which covers all additive migrations used here.
    """
    added: list[str] = []
    try:
        inspector = inspect(engine)
        existing_tables = set(inspector.get_table_names())
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Schema inspection failed: %s", exc)
        return added

    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            try:
                rows = conn.exec_driver_sql(
                    f'PRAGMA table_info("{table.name}")'
                ).fetchall()
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Could not read schema for %s: %s", table.name, exc)
                continue
            present = {row[1] for row in rows}
            for column in table.columns:
                if column.name in present:
                    continue
                definition, made_nullable = _column_definition(
                    column, engine.dialect
                )
                clause = (
                    f'ALTER TABLE "{table.name}" ADD COLUMN '
                    f'"{column.name}" {definition}'
                )
                conn.exec_driver_sql(clause)
                if made_nullable:
                    logger.warning(
                        "Added %s.%s as nullable: NOT NULL has no SQL default.",
                        table.name,
                        column.name,
                    )
                added.append(f"{table.name}.{column.name}")

    if added:
        logger.info("Applied %d schema addition(s): %s", len(added), ", ".join(added))
    return added


class Database:
    """Singleton database manager."""
    _instance: Optional["Database"] = None
    _engine: Optional[Engine] = None
    _session_factory: Optional[sessionmaker] = None

    def __new__(cls) -> "Database":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def initialize(self, db_path: str = "db/hashvault.sqlite3") -> None:
        """Initialize database connection and create tables."""
        try:
            # Ensure directory exists
            db_file = Path(db_path)
            db_file.parent.mkdir(parents=True, exist_ok=True)

            # Release the previous pool before replacing the engine; CLI
            # commands call initialize() repeatedly and every call used to
            # leave the old engine (and its open SQLite handles) behind.
            if self._engine is not None:
                try:
                    self._engine.dispose()
                except Exception:  # pragma: no cover - already closed
                    pass
                self._engine = None
                self._session_factory = None

            # Create engine with WAL mode
            self._engine = create_engine(
                f"sqlite:///{db_path}",
                connect_args={
                    "check_same_thread": False,
                    "timeout": 30,
                },
                poolclass=StaticPool,
                echo=False,
            )

            # Enable WAL mode via listener pragma
            @event.listens_for(self._engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL;")
                cursor.execute("PRAGMA foreign_keys=ON;")
                cursor.execute("PRAGMA synchronous=NORMAL;")
                cursor.close()

            # Create all tables
            Base.metadata.create_all(self._engine)

            # Additive migrations for databases created by older releases.
            ensure_schema(self._engine)

            # Create session factory
            self._session_factory = sessionmaker(
                bind=self._engine,
                expire_on_commit=False,
            )

        except Exception as e:
            raise DatabaseError(f"Failed to initialize database: {e}")

    @property
    def engine(self) -> Engine:
        """Get database engine."""
        if self._engine is None:
            raise DatabaseError("Database not initialized. Call initialize() first.")
        return self._engine

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Context manager for database sessions."""
        if self._session_factory is None:
            raise DatabaseError("Database not initialized. Call initialize() first.")

        session = self._session_factory()
        try:
            yield session
            session.commit()
        except HashVaultError:
            session.rollback()
            raise
        except Exception as e:
            session.rollback()
            raise DatabaseError(f"Database operation failed: {e}")
        finally:
            session.close()

    def get_session(self) -> Session:
        """Get a new session (must be closed manually)."""
        if self._session_factory is None:
            raise DatabaseError("Database not initialized. Call initialize() first.")
        return self._session_factory()


# Global database instance
db = Database()


@contextmanager
def _seed_lock(db_path: str | Path) -> Iterator[None]:
    """Serialize catalogue/corpus seeding across concurrent CLI processes."""
    digest = hashlib.sha256(str(Path(db_path).resolve()).encode("utf-8")).hexdigest()[:16]
    lock_path = Path(tempfile.gettempdir()) / f"hashvault-seed-{digest}.lock"
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            if os.fstat(fd).st_size == 0:
                os.write(fd, b"\0")
            os.lseek(fd, 0, os.SEEK_SET)
            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def init_db(
    db_path: str = "db/hashvault.sqlite3",
    seed_patterns_path: Optional[str] = None,
    seed_corpus_paths: Optional[Iterable[str | Path]] = None,
    *,
    apply_calibration: bool = True,
) -> Engine:
    """Initialize the database and optionally seed patterns/corpus entries."""
    db.initialize(db_path)
    with _seed_lock(db_path):
        if seed_patterns_path:
            patterns_path = resolve_resource_path(seed_patterns_path)
            if patterns_path.exists():
                seed_patterns(
                    db._session_factory,
                    patterns_path,
                    apply_calibration=apply_calibration,
                )
            else:
                logger.warning(
                    "Pattern seed file not found: %s (database left empty).",
                    seed_patterns_path,
                )
        if seed_corpus_paths is not None:
            seed_corpus(db._session_factory, seed_corpus_paths)
    return db.engine


def get_db() -> Database:
    """Get database instance."""
    return db


def reset_db_engine() -> None:
    """Reset singleton database instance for tests."""
    if db._engine:
        db._engine.dispose()
    db._engine = None
    db._session_factory = None


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Context manager for obtaining a database session."""
    with db.session() as s:
        yield s


def get_session_factory(engine: Optional[Engine] = None) -> Optional[sessionmaker]:
    """Return current session factory."""
    return db._session_factory


def _load_calibrated_weights(directory: Path) -> dict[str, float]:
    """Read ``calibrated_weights.json`` written by ``hashvault calibrate``.

    Returns an empty mapping when the file is missing or malformed, so a bad
    calibration artefact degrades to the shipped constants instead of
    breaking ``setup``.
    """
    path = directory / "calibrated_weights.json"
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Ignoring malformed %s: %s", path.name, exc)
        return {}

    payload = raw.get("weights") if isinstance(raw, dict) else raw
    if not isinstance(payload, dict):
        return {}

    weights: dict[str, float] = {}
    for name, value in payload.items():
        try:
            weight = float(value)
        except (TypeError, ValueError):
            continue
        if 0.0 < weight <= 1.0:
            weights[str(name)] = weight
    if weights:
        logger.info("Loaded %d calibrated pattern weight(s).", len(weights))
    return weights


def seed_patterns(
    session_factory: Optional[sessionmaker],
    patterns_file: str | Path,
    *,
    apply_calibration: bool = True,
) -> int:
    """Seed patterns table from a JSON file."""
    if not session_factory:
        return 0
    patterns_path = resolve_resource_path(patterns_file)
    if not patterns_path.exists():
        logger.warning("Pattern file not found: %s", patterns_file)
        return 0

    with open(patterns_path, "r", encoding="utf-8") as f:
        patterns_data = json.load(f)

    # Curated overrides live next to the generated pattern catalogue.  They
    # correct upstream naming/mode errors and add formats hashcat 6.2.6 does
    # not ship (Argon2, yescrypt, Werkzeug PBKDF2, Gogs/Gitea, Timeroast).
    overrides_path = patterns_path.parent / "curated_overrides.json"
    overrides_data = []
    if overrides_path.exists():
        try:
            with open(overrides_path, "r", encoding="utf-8") as f:
                overrides_data = json.load(f)
        except (OSError, json.JSONDecodeError):
            overrides_data = []

    # Calibrated weights are read for diagnostics only; the identifier never
    # rewrites confidence_weight (see the note at the end of this function).
    calibrated_weights = (
        _load_calibrated_weights(patterns_path.parent) if apply_calibration else {}
    )

    inserted_count = 0
    with session_factory() as session:
        existing_patterns = {p.name: p for p in session.query(Pattern).all()}
        legacy_index = {name: p for name, p in existing_patterns.items()}

        # Names that a curated override renames into another pattern.  Without
        # this guard the generated catalogue re-inserts an alias on the very
        # next run (the override deleted it in this one), so ``hashvault
        # setup`` alternated between 482 and 483 patterns on alternating runs.
        override_alias_names = {
            legacy
            for item in overrides_data
            for legacy in (item.get("legacy_names") or [])
            if item.get("name") and legacy != item.get("name")
        }
        # Canonical names owned by an override; an alias with one of these
        # names belongs to another override and must never be deleted.
        override_target_names = {
            item["name"] for item in overrides_data if item.get("name")
        }

        def apply_fields(p: Pattern, item: dict, partial: bool = False) -> None:
            if "category" in item or not partial:
                category_val = item.get("category", "raw_generic")
                try:
                    cat_enum = HashCategory(category_val)
                except ValueError:
                    cat_enum = HashCategory.RAW_GENERIC
                p.category = cat_enum
            if "regex" in item:
                p.regex = item["regex"]
            elif not partial:
                raise KeyError("regex")
            for field, default in (
                ("hashcat_mode", None),
                ("john_format", None),
                ("popularity", 0),
                ("description", ""),
                ("is_slow", False),
                ("min_length", None),
                ("max_length", None),
                ("prefix_hint", None),
                ("confidence_weight", 1.0),
            ):
                if not partial or field in item:
                    setattr(p, field, item.get(field, default))
            if not partial or "source_format_hints" in item:
                p.source_format_hints = (
                    json.dumps(item.get("source_format_hints"))
                    if item.get("source_format_hints") else None
                )

        for item in patterns_data:
            name = item["name"]
            if name in existing_patterns:
                apply_fields(existing_patterns[name], item)
                continue
            if name in override_alias_names:
                # A curated override folds this name into another pattern;
                # re-inserting it here would resurrect the alias.
                continue

            category_val = item.get("category", "raw_generic")
            try:
                cat_enum = HashCategory(category_val)
            except ValueError:
                cat_enum = HashCategory.RAW_GENERIC

            pattern = Pattern(
                name=name,
                regex=item["regex"],
                hashcat_mode=item.get("hashcat_mode"),
                john_format=item.get("john_format"),
                popularity=item.get("popularity", 0),
                description=item.get("description", ""),
                is_slow=item.get("is_slow", False),
                category=cat_enum,
                min_length=item.get("min_length"),
                max_length=item.get("max_length"),
                prefix_hint=item.get("prefix_hint"),
                confidence_weight=item.get("confidence_weight", 1.0),
                source_format_hints=json.dumps(item.get("source_format_hints")) if item.get("source_format_hints") else None,
            )
            session.add(pattern)
            existing_patterns[name] = pattern
            legacy_index[name] = pattern
            inserted_count += 1

        def pattern_references(pattern_id: int) -> int:
            return sum(
                session.query(model)
                .filter_by(**{field: pattern_id})
                .count()
                for model, field in (
                    (CrackedHash, "pattern_id"),
                    (CrackSession, "pattern_id"),
                    (IdentificationLog, "chosen_pattern_id"),
                    (AnalysisLog, "chosen_pattern_id"),
                )
            )

        for item in overrides_data:
            name = item.get("name")
            if not name:
                continue

            target = existing_patterns.get(name)
            if target is None:
                for legacy in item.get("legacy_names", []) or []:
                    candidate = legacy_index.get(legacy) or existing_patterns.get(legacy)
                    if candidate is not None:
                        target = candidate
                        break

            created = target is None
            if target is None:
                if "regex" not in item:
                    continue
                pattern = Pattern(name=name, regex=item["regex"])
                session.add(pattern)
                existing_patterns[name] = pattern
                legacy_index[name] = pattern
                inserted_count += 1
                target = pattern
            elif target.name != name:
                canonical = existing_patterns.get(name)
                if canonical is None:
                    target.name = name
                    canonical = target
                target = canonical
                existing_patterns[name] = target
                legacy_index[name] = target

            apply_fields(target, item, partial=not created)
            for legacy in item.get("legacy_names", []) or []:
                # An alias may itself be the canonical name of another
                # override (e.g. the Gogs entry lists ``Gogs/Gitea
                # PBKDF2-SHA256`` as a legacy name while a second override
                # owns that exact name).  Deleting it here made the two
                # overrides fight, so ``setup`` alternated between 482 and
                # 483 patterns.  Never remove a row another override targets.
                if legacy in override_target_names:
                    legacy_index[legacy] = target
                    continue
                alias = existing_patterns.get(legacy) or legacy_index.get(legacy)
                if (
                    alias is not None
                    and alias is not target
                    and alias.hashcat_mode in (None, target.hashcat_mode)
                    and pattern_references(alias.id) == 0
                ):
                    session.delete(alias)
                    existing_patterns.pop(alias.name, None)
                    legacy_index.pop(alias.name, None)
                legacy_index[legacy] = target

        # Calibration is deliberately NOT applied to confidence_weight.
        # The weight orders candidates, and rewriting it inverted real
        # decisions: NTLM was demoted 0.50 -> 0.25 while MD5 -- which never
        # wins, so never gets measured -- kept 0.40 and leapfrogged it on every
        # 32-hex digest.  Confidence calibration is applied as a monotone map
        # over the *reported* confidence instead (core/calibration.py).
        session.commit()
    return inserted_count


def seed_corpus(
    session_factory: Optional[sessionmaker],
    corpus_files: Optional[Iterable[str | Path]] = None,
    *,
    replace: bool = False,
) -> int:
    """Idempotently load corpus JSON files into ``corpus_entries``.

    Returns the number of newly inserted entries. Existing rows are updated in
    place so repeated setup runs do not duplicate data.
    """
    if not session_factory:
        return 0
    from hashvault.corpus import DEFAULT_CORPUS_FILES, load_corpora

    paths = tuple(corpus_files) if corpus_files is not None else DEFAULT_CORPUS_FILES
    entries = load_corpora(paths)
    fields = (
        "source", "mode", "name", "raw_input", "expected_plaintext", "category",
        "username", "domain", "box", "url", "example_format", "slow_hash",
        "is_binary", "truncated", "usable_for_identification",
        "usable_for_cracking", "unusable_reason", "reference", "notes",
        "upstream_repo", "upstream_path", "upstream_commit", "upstream_url",
        "license", "verified", "verification",
    )

    with session_factory() as session:
        if replace:
            session.query(CorpusEntryRecord).delete()
        existing = {row.id: row for row in session.query(CorpusEntryRecord).all()}
        inserted = 0
        for entry in entries:
            record = existing.get(entry.id)
            if record is None:
                record = CorpusEntryRecord(id=entry.id)
                session.add(record)
                inserted += 1
            for field_name in fields:
                setattr(record, field_name, getattr(entry, field_name))
        session.commit()
    return inserted
