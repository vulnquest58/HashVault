"""Integrity auditing for locally stored cracked-hash records."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from hashvault.core.builtin import verify_plaintext
from hashvault.models.orm import CrackedHash, Pattern


VERIFIED = "verified"
MISMATCH = "mismatch"
UNSUPPORTED = "unsupported"
ERROR = "error"


@dataclass
class VerificationRecord:
    record_id: int
    pattern: str
    tool: str
    hash_preview: str
    username: Optional[str]
    status: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationReport:
    results: list[VerificationRecord] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {
            "verified": sum(1 for item in self.results if item.status == VERIFIED),
            "mismatch": sum(1 for item in self.results if item.status == MISMATCH),
            "unsupported": sum(
                1 for item in self.results if item.status == UNSUPPORTED
            ),
            "errors": sum(1 for item in self.results if item.status == ERROR),
        }

    @property
    def ok(self) -> bool:
        counts = self.counts()
        return counts["mismatch"] == 0 and counts["errors"] == 0

    def to_dict(self) -> dict[str, Any]:
        counts = self.counts()
        return {
            "ok": self.ok,
            "summary": {"total": len(self.results), **counts},
            "results": [item.to_dict() for item in self.results],
        }


def _preview(value: str) -> str:
    if len(value) <= 32:
        return value
    return f"{value[:16]}...{value[-12:]}"


def verify_cached_plaintext(
    normalized_hash: str,
    pattern: Any,
    plaintext: str,
) -> Optional[bool]:
    """Verify one cached plaintext.

    Returns ``True``/``False`` when a verifier exists, or ``None`` when the
    pattern has no built-in verifier (in which case the caller must trust the
    stored value rather than discarding a possibly-correct record).
    """
    if pattern is None or not plaintext:
        return None
    try:
        return verify_plaintext(normalized_hash, pattern, plaintext)
    except Exception:  # pragma: no cover - defensive
        return None


def verify_cracked_hashes(
    session: Session,
    *,
    pattern_name: Optional[str] = None,
    limit: Optional[int] = None,
) -> VerificationReport:
    """Re-verify stored plaintexts against their canonical hashes."""
    query = session.query(CrackedHash).options(joinedload(CrackedHash.pattern))
    if pattern_name:
        query = query.join(Pattern).filter(
            func.lower(Pattern.name) == pattern_name.strip().lower()
        )
    query = query.order_by(CrackedHash.id)
    if limit is not None and limit > 0:
        query = query.limit(limit)

    report = VerificationReport()
    for record in query.all():
        pattern = record.pattern
        pattern_label = getattr(pattern, "name", "?")
        status = ERROR
        detail = ""
        try:
            verdict = verify_plaintext(
                record.normalized_hash,
                pattern,
                record.plaintext,
            )
        except Exception as exc:
            detail = str(exc)
        else:
            if verdict is None:
                status = UNSUPPORTED
                detail = "No built-in verifier for this pattern"
            elif verdict:
                status = VERIFIED
            else:
                status = MISMATCH
                detail = "Plaintext does not reproduce the stored hash"

        report.results.append(
            VerificationRecord(
                record_id=record.id,
                pattern=pattern_label,
                tool=record.tool_used,
                hash_preview=_preview(record.normalized_hash),
                username=record.username,
                status=status,
                detail=detail,
            )
        )
    return report
