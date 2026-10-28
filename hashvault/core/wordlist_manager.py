"""
Wordlist and Rule resource manager for HashVault v2.0.
Registers, verifies, and lists wordlist dictionary files and hashcat/john rule files.
"""
import shutil
from pathlib import Path
from typing import List, Optional
from sqlalchemy.orm import Session

from hashvault.config import Config
from hashvault.exceptions import RuleNotFoundError, WordlistNotFoundError
from hashvault.models.orm import RuleRecord, WordlistRecord
from hashvault.models.schemas import RuleDTO, WordlistDTO
from hashvault.utils.helpers import validate_safe_path


def import_wordlist(
    file_path: str | Path,
    name: Optional[str],
    db_session: Session,
    config: Config,
) -> WordlistDTO:
    """Import a external wordlist into HashVault managed data directory and DB register."""
    src = Path(file_path).resolve()
    if not src.exists() or not src.is_file():
        raise WordlistNotFoundError(str(file_path))

    target_name = name or src.name
    dest_dir = Path(config.paths.wordlist_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / target_name

    if src != dest:
        shutil.copy2(src, dest)

    # Count lines and size
    size_bytes = dest.stat().st_size
    line_count = 0
    with open(dest, "r", encoding="utf-8", errors="ignore") as f:
        for _ in f:
            line_count += 1

    existing = db_session.query(WordlistRecord).filter(WordlistRecord.name == target_name).first()
    if existing:
        existing.path = str(dest)
        existing.line_count = line_count
        existing.size_bytes = size_bytes
        record = existing
    else:
        record = WordlistRecord(
            name=target_name,
            path=str(dest),
            line_count=line_count,
            size_bytes=size_bytes,
        )
        db_session.add(record)

    db_session.commit()
    db_session.refresh(record)
    return WordlistDTO.model_validate(record)


def get_default_wordlist(config: Config) -> Path:
    """Return default wordlist path, creating a fallback wordlist if none exists."""
    wordlist_dir = Path(config.paths.wordlist_dir)
    wordlist_dir.mkdir(parents=True, exist_ok=True)
    default_file = wordlist_dir / "default.txt"

    if not default_file.exists():
        default_file.write_text("password\n123456\npassword123\nadmin\nletmein\n", encoding="utf-8")

    return default_file


def resolve_wordlist(name: str | None, db_session: Session, config: Config) -> Path:
    """Resolve a wordlist by name or return default wordlist.

    All resolved paths are confined to the managed wordlist directory to
    prevent ``--wordlist ../../etc/passwd`` style traversal.
    """
    if not name:
        return get_default_wordlist(config)

    base_dir = Path(config.paths.wordlist_dir).resolve()
    record = db_session.query(WordlistRecord).filter(WordlistRecord.name == name).first()
    if record and Path(record.path).exists():
        try:
            return validate_safe_path(record.path, base_dir)
        except Exception:
            pass

    # Fallback to checking filename directly in wordlist directory
    direct = base_dir / name
    try:
        direct_path = validate_safe_path(direct, base_dir)
    except Exception as exc:
        raise WordlistNotFoundError(f"Unsafe wordlist path: {name}") from exc
    if direct_path.exists():
        return direct_path

    raise WordlistNotFoundError(name)


def resolve_rule(name: str | None, config: Config) -> Path | None:
    """Resolve a rule file safely within the managed rules directory.

    ``name`` may be a bare filename (``best64.rule``) or an absolute path that
    lives inside ``paths.rules_dir``.  Traversal outside the directory is
    rejected.
    """
    if not name:
        return None

    base_dir = Path(config.paths.rules_dir).resolve() if config.paths.rules_dir else None
    if base_dir is None:
        raise RuleNotFoundError("No rules directory configured")

    candidate = Path(name)
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    try:
        resolved = validate_safe_path(candidate, base_dir)
    except Exception as exc:
        raise RuleNotFoundError(f"Unsafe rule path: {name}") from exc

    if not resolved.is_file():
        raise RuleNotFoundError(name)
    return resolved


def import_rule(
    file_path: str | Path,
    name: Optional[str],
    db_session: Session,
    config: Config,
) -> RuleDTO:
    """Import a cracking rule file into HashVault managed data directory and DB register."""
    src = Path(file_path).resolve()
    if not src.exists() or not src.is_file():
        raise RuleNotFoundError(str(file_path))

    target_name = name or src.name
    dest_dir = Path(config.paths.rules_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / target_name

    if src != dest:
        shutil.copy2(src, dest)

    existing = db_session.query(RuleRecord).filter(RuleRecord.name == target_name).first()
    if existing:
        existing.path = str(dest)
        record = existing
    else:
        record = RuleRecord(name=target_name, path=str(dest))
        db_session.add(record)

    db_session.commit()
    db_session.refresh(record)
    return RuleDTO.model_validate(record)


def list_wordlists(db_session: Session) -> List[WordlistDTO]:
    """Retrieve all registered wordlists."""
    records = db_session.query(WordlistRecord).all()
    return [WordlistDTO.model_validate(r) for r in records]


def list_rules(db_session: Session) -> List[RuleDTO]:
    """Retrieve all registered rules."""
    records = db_session.query(RuleRecord).all()
    return [RuleDTO.model_validate(r) for r in records]
