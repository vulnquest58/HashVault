"""Managed storage for John the Ripper file-to-hash converters.

HashVault can copy the helper programs that ship with John the Ripper into a
stable, category-based tree under ``tools/converters``.  The tree is local and
does not replace John: it makes converter availability independent of the
caller's current directory and keeps every supported format in one place.

The store is intentionally simple:

* converters are ordinary John helper files (``zip2john.py``, ``rar2john.exe``)
* categories mirror the conversion gallery (archive, documents, wallets, ...)
* a generated ``manifest.json`` records provenance and SHA-256 hashes
* nothing is downloaded and no helper is ever resolved from ``PATH``/cwd
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

CONVERTER_SUFFIXES: tuple[str, ...] = (".exe", ".py", ".pl", ".js", ".lua")

CATEGORY_DIRECTORIES: dict[str, str] = {
    "Archive": "archive",
    "Document": "documents",
    "Password manager": "password-managers",
    "Disk encryption": "disk-encryption",
    "Private key": "private-keys",
    "Windows": "windows",
    "Enterprise": "enterprise",
    "Database": "databases",
    "Network": "network",
    "Wireless": "wireless",
    "Wallet": "wallets",
    "Application": "applications",
}

SUPPORT_FILES: tuple[str, ...] = ("jtrconf.pm", "jtr_rulez.pm")
MANIFEST_NAME = "manifest.json"
MANIFEST_SCHEMA_VERSION = 1


class ConverterStoreError(RuntimeError):
    """Raised when the converter store cannot be created or synchronized."""


@dataclass
class ConverterSyncEntry:
    profile: str
    converter: str
    category: str
    source: str
    stored: str
    runtime: str
    sha256: str
    status: str

    def to_dict(self) -> dict[str, str]:
        return {
            "profile": self.profile,
            "converter": self.converter,
            "category": self.category,
            "source": self.source,
            "stored": self.stored,
            "runtime": self.runtime,
            "sha256": self.sha256,
            "status": self.status,
        }


@dataclass
class ConverterSyncReport:
    source: str
    destination: str
    entries: list[ConverterSyncEntry] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    support_files: list[str] = field(default_factory=list)
    manifest: str = ""

    @property
    def copied(self) -> int:
        return sum(1 for entry in self.entries if entry.status == "copied")

    @property
    def stored(self) -> int:
        return len({entry.profile for entry in self.entries})

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "destination": self.destination,
            "profiles": len(self.entries) + len(self.missing),
            "stored_profiles": self.stored,
            "copied_files": self.copied,
            "missing": list(self.missing),
            "support_files": list(self.support_files),
            "manifest": self.manifest,
            "files": [entry.to_dict() for entry in self.entries],
        }


@dataclass
class ConverterStoreStatus:
    root: str
    exists: bool
    manifest: bool
    converters: int
    profiles: int
    missing: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.exists and self.converters > 0 and not self.missing

    def to_dict(self) -> dict[str, object]:
        return {
            "root": self.root,
            "exists": self.exists,
            "manifest": self.manifest,
            "converters": self.converters,
            "profiles": self.profiles,
            "missing": list(self.missing),
            "unknown": list(self.unknown),
            "ok": self.ok,
        }


def default_converter_root() -> Path:
    """Return the repository's default ``tools/converters`` directory."""
    return Path(__file__).resolve().parents[2] / "tools" / "converters"


def resolve_converter_root(configured: str | Path | None = None) -> Path:
    """Resolve a configured store path, defaulting to the project tree."""
    if configured:
        return Path(configured).expanduser().resolve()
    return default_converter_root().resolve()


def category_directory(category: str) -> str:
    """Map a gallery category to its stable directory name."""
    if category in CATEGORY_DIRECTORIES:
        return CATEGORY_DIRECTORIES[category]
    slug = re.sub(r"[^a-z0-9]+", "-", category.strip().lower()).strip("-")
    return slug or "other"


def ensure_store_layout(root: str | Path | None = None) -> list[Path]:
    """Create the store root, category directories, and library directory."""
    base = resolve_converter_root(root)
    created: list[Path] = []
    for directory in [base, base / "lib", *(base / name for name in CATEGORY_DIRECTORIES.values())]:
        if not directory.exists():
            directory.mkdir(parents=True, exist_ok=True)
            created.append(directory)
    return created


def _is_converter_name(path: Path) -> bool:
    return (
        path.is_file()
        and path.suffix.lower() in CONVERTER_SUFFIXES
        and "2john" in path.stem.lower()
    )


def iter_stored_converters(
    root: str | Path | None = None,
) -> list[Path]:
    """Return every converter file in the managed store."""
    base = resolve_converter_root(root)
    if not base.is_dir():
        return []
    return sorted(path for path in base.rglob("*") if _is_converter_name(path))


def _suffix_order(path: Path) -> int:
    try:
        return CONVERTER_SUFFIXES.index(path.suffix.lower())
    except ValueError:
        return len(CONVERTER_SUFFIXES)


def find_stored_converter(
    profile: object,
    root: str | Path | None = None,
) -> Path | None:
    """Find the best stored converter for a profile-like object."""
    converter = str(getattr(profile, "converter", "") or "")
    if not converter:
        return None
    requested = Path(converter)
    stem = requested.stem.lower()
    base = resolve_converter_root(root)
    if not base.is_dir():
        return None

    candidates: list[Path] = []
    exact = base / category_directory(str(getattr(profile, "category", ""))) / requested.name
    if exact.is_file():
        candidates.append(exact)
    for path in base.rglob("*"):
        if not _is_converter_name(path):
            continue
        if path.stem.lower() != stem:
            continue
        if path not in candidates:
            candidates.append(path)
    if not candidates:
        return None
    candidates.sort(key=lambda path: (_suffix_order(path), str(path)))
    return candidates[0]


def _run_converter_candidates(
    run_dir: Path,
    converter: str,
) -> list[Path]:
    requested = Path(converter)
    stem = requested.stem.lower()
    exact = run_dir / requested.name
    candidates: list[Path] = []
    if exact.is_file() and exact.suffix.lower() in CONVERTER_SUFFIXES:
        candidates.append(exact)
    for path in run_dir.glob("*2john*"):
        if not _is_converter_name(path):
            continue
        if path.stem.lower() != stem:
            continue
        if path not in candidates:
            candidates.append(path)
    candidates.sort(key=lambda path: (_suffix_order(path), path.name))
    return candidates


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_manifest(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def sync_converters(
    john_bin: str,
    destination: str | Path | None = None,
    *,
    profiles: Sequence[object] | None = None,
    force: bool = False,
    dry_run: bool = False,
) -> ConverterSyncReport:
    """Copy available John converters into the managed store.

    The source is the John run directory resolved from ``john_bin``.  The
    destination defaults to ``tools/converters``.  Existing files are kept
    unless ``force`` is set, so a local patch is never silently overwritten.
    """
    from hashvault.ingestors.john_catalog import (
        PROFILES,
        john_run_dir,
        resolve_runtime,
    )

    selected = list(profiles if profiles is not None else PROFILES)
    run_dir = john_run_dir(john_bin)
    base = resolve_converter_root(destination)
    if run_dir is None or not run_dir.is_dir():
        raise ConverterStoreError(
            f"John run directory not found for {john_bin!r}; install John the Ripper "
            "or set paths.john_bin in config/default.yaml."
        )

    report = ConverterSyncReport(source=str(run_dir), destination=str(base))
    if not dry_run:
        ensure_store_layout(base)

    for profile in selected:
        key = str(getattr(profile, "key", "unknown"))
        converter = str(getattr(profile, "converter", ""))
        category = str(getattr(profile, "category", ""))
        candidates = _run_converter_candidates(run_dir, converter)
        if not candidates:
            report.missing.append(key)
            continue
        for candidate in candidates:
            target = base / category_directory(category) / candidate.name
            status = "dry-run"
            if not dry_run:
                if target.exists() and not force:
                    status = "kept"
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(candidate, target)
                    status = "copied"
            _, runtime, _ = resolve_runtime(candidate)
            report.entries.append(
                ConverterSyncEntry(
                    profile=key,
                    converter=candidate.name,
                    category=category_directory(category),
                    source=str(candidate),
                    stored=str(target),
                    runtime=runtime,
                    sha256=_sha256(candidate),
                    status=status,
                )
            )

    support_targets: list[str] = []
    for name in SUPPORT_FILES:
        source = run_dir / name
        if not source.is_file():
            continue
        target = base / "lib" / name
        support_targets.append(str(target))
        if not dry_run and (force or not target.exists()):
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    report.support_files = support_targets

    if not dry_run:
        manifest_path = base / MANIFEST_NAME
        _write_manifest(
            manifest_path,
            {
                "schema_version": MANIFEST_SCHEMA_VERSION,
                "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "source": str(run_dir),
                "destination": str(base),
                "profiles": len(selected),
                "stored_profiles": report.stored,
                "missing": list(report.missing),
                "support_files": list(support_targets),
                "files": [entry.to_dict() for entry in report.entries],
            },
        )
        report.manifest = str(manifest_path)
    return report


def converter_store_status(
    configured: str | Path | None = None,
    *,
    profiles: Iterable[object] | None = None,
) -> ConverterStoreStatus:
    """Summarize the managed store for diagnostics."""
    from hashvault.ingestors.john_catalog import PROFILES

    selected = list(profiles if profiles is not None else PROFILES)
    base = resolve_converter_root(configured)
    stored = iter_stored_converters(base)
    stored_stems = {path.stem.lower() for path in stored}
    missing = [
        str(getattr(profile, "key", "unknown"))
        for profile in selected
        if Path(str(getattr(profile, "converter", ""))).stem.lower()
        not in stored_stems
    ]
    known_stems = {
        Path(str(getattr(profile, "converter", ""))).stem.lower()
        for profile in selected
    }
    unknown = sorted(stem for stem in stored_stems if stem not in known_stems)
    return ConverterStoreStatus(
        root=str(base),
        exists=base.is_dir(),
        manifest=(base / MANIFEST_NAME).is_file(),
        converters=len(stored),
        profiles=len(selected),
        missing=missing,
        unknown=unknown,
    )
