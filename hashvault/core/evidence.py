"""Tamper-evident audit evidence built from locally verified results.

An audit finding is only useful if it can be shown to be (a) reproducible and
(b) untampered with.  A CSV of cracked passwords provides neither: nothing
proves which tool version produced it, which corpus it was checked against, or
that a row was not edited afterwards.

This module produces a signed, canonical document that:

* records **no plaintext** -- only a SHA-256 of each hash, so the report can be
  handed to an auditor without leaking credentials;
* pins the tool version and fingerprints of the pattern catalogue and corpus,
  so the same inputs reproduce the same verdict;
* signs the canonical JSON with Ed25519, and can verify it later.

Signing needs ``cryptography``, which is already a hard dependency.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


class EvidenceError(RuntimeError):
    """Raised when a report cannot be built, signed or verified."""


@dataclass
class EvidenceRecord:
    """One audited credential, identified by digest only."""

    record_id: int
    hash_digest: str
    pattern: str
    tool: str
    verification: str
    username_present: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceReport:
    generated_at: str
    tool_version: str
    schema_version: int
    patterns_fingerprint: str
    corpus_fingerprint: str
    database_fingerprint: str
    records: list[EvidenceRecord] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def payload(self) -> dict[str, Any]:
        """The document that gets signed (everything except the signature)."""
        return {
            "kind": "hashvault.evidence.report",
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "tool_version": self.tool_version,
            "patterns_fingerprint": self.patterns_fingerprint,
            "corpus_fingerprint": self.corpus_fingerprint,
            "database_fingerprint": self.database_fingerprint,
            "summary": self.summary,
            "metadata": self.metadata,
            "records": [record.to_dict() for record in self.records],
        }

    def canonical_bytes(self) -> bytes:
        """Deterministic serialisation: the exact bytes that are signed."""
        return json.dumps(
            self.payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")


def fingerprint_file(path: str | Path) -> str:
    """SHA-256 of a file's bytes, or empty string when it is missing."""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def fingerprint_files(paths: list[str | Path]) -> str:
    """Combined fingerprint of several files, order-independent by name."""
    digest = hashlib.sha256()
    for path in sorted((Path(item) for item in paths), key=lambda item: str(item)):
        digest.update(str(path).encode("utf-8"))
        digest.update(fingerprint_file(path).encode("utf-8"))
    return digest.hexdigest()


def _tool_version() -> str:
    try:
        from hashvault import __version__ as version  # type: ignore[attr-defined]

        return str(version)
    except Exception:  # noqa: BLE001  # pragma: no cover - package metadata optional
        return "unknown"


def build_evidence_report(
    session: Any,
    *,
    patterns_file: str | Path | None = None,
    corpus_files: list[str | Path] | None = None,
    limit: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> EvidenceReport:
    """Collect verification results into an unsigned evidence document."""
    from hashvault.core.integrity import verify_cracked_hashes
    from hashvault.models.orm import CrackedHash

    report = verify_cracked_hashes(session, limit=limit)

    query = session.query(CrackedHash).order_by(CrackedHash.id)
    if limit is not None and limit > 0:
        query = query.limit(limit)
    rows = {row.id: row for row in query.all()}

    records: list[EvidenceRecord] = []
    for item in report.results:
        row = rows.get(item.record_id)
        if row is None:
            continue
        records.append(
            EvidenceRecord(
                record_id=item.record_id,
                # Only the digest leaves the database -- never the plaintext.
                hash_digest=hashlib.sha256(
                    str(row.normalized_hash).encode("utf-8")
                ).hexdigest(),
                pattern=item.pattern,
                tool=item.tool,
                verification=item.status,
                username_present=bool(item.username),
            )
        )

    counts = report.counts()
    database_fingerprint = ""
    try:
        database_fingerprint = hashlib.sha256(
            "|".join(
                sorted(
                    f"{record.record_id}:{record.hash_digest}:{record.verification}"
                    for record in records
                )
            ).encode("utf-8")
        ).hexdigest()
    except Exception:  # noqa: BLE001  # pragma: no cover - defensive
        database_fingerprint = ""

    return EvidenceReport(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        tool_version=_tool_version(),
        schema_version=SCHEMA_VERSION,
        patterns_fingerprint=(
            fingerprint_file(patterns_file) if patterns_file else ""
        ),
        corpus_fingerprint=(
            fingerprint_files(corpus_files) if corpus_files else ""
        ),
        database_fingerprint=database_fingerprint,
        records=records,
        summary={"total": len(records), **counts, "ok": report.ok},
        metadata=dict(metadata or {}),
    )


# ---------------------------------------------------------------------------
# Signing / verification
# ---------------------------------------------------------------------------


def generate_keypair() -> tuple[bytes, bytes]:
    """Create an Ed25519 keypair as PEM (private, public)."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as exc:  # pragma: no cover - dependency present
        raise EvidenceError(
            "Signing requires the 'cryptography' package."
        ) from exc

    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def public_key_id(public_key_pem: bytes) -> str:
    """Return a stable short identifier for an Ed25519 public key."""
    return "ed25519:" + hashlib.sha256(public_key_pem).hexdigest()[:16]


def sign_report(
    report: EvidenceReport,
    private_key_pem: bytes,
    *,
    key_id: str = "",
) -> dict[str, Any]:
    """Attach an Ed25519 signature over the canonical payload."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as exc:  # pragma: no cover
        raise EvidenceError(
            "Signing requires the 'cryptography' package."
        ) from exc

    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except Exception as exc:
        raise EvidenceError(f"Invalid private key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise EvidenceError("Signing key must be Ed25519.")

    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload = report.canonical_bytes()
    signature = key.sign(payload)

    document = report.payload()
    document["signature"] = {
        "algorithm": "ed25519",
        "value": signature.hex(),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "key_id": key_id or public_key_id(public_pem),
        "public_key": public_pem.decode("utf-8"),
    }
    return document


def verify_report(
    document: dict[str, Any],
    public_key_pem: bytes | None = None,
    *,
    allow_embedded: bool = False,
) -> tuple[bool, list[str]]:
    """Check the signature and the payload digest of a signed report.

    Returns ``(ok, reasons)``; ``reasons`` explains every failed check.  When
    no key is supplied only payload integrity is checked.  Set
    ``allow_embedded`` to verify against the public key stored in the
    signature block; that proves self-consistency, not publisher identity.
    """
    reasons: list[str] = []
    signature_block = document.get("signature")
    if not isinstance(signature_block, dict):
        return False, ["document is not signed"]

    if signature_block.get("algorithm") != "ed25519":
        reasons.append(
            f"unsupported signature algorithm: {signature_block.get('algorithm')!r}"
        )

    payload = {
        key: value for key, value in document.items() if key != "signature"
    }
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")

    recorded = signature_block.get("payload_sha256")
    actual = hashlib.sha256(canonical).hexdigest()
    if recorded and recorded != actual:
        reasons.append(
            "payload digest mismatch: the document was modified after signing"
        )

    if public_key_pem is None and allow_embedded:
        embedded = signature_block.get("public_key")
        if isinstance(embedded, str) and embedded.strip():
            public_key_pem = embedded.encode("utf-8")

    if public_key_pem is None:
        # Integrity of the payload is still checkable without the key.
        return (not reasons), reasons

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:  # pragma: no cover
        raise EvidenceError(
            "Verification requires the 'cryptography' package."
        ) from exc

    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except Exception as exc:
        raise EvidenceError(f"Invalid public key: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise EvidenceError("Verification key must be Ed25519.")

    try:
        key.verify(bytes.fromhex(signature_block.get("value", "")), canonical)
    except (InvalidSignature, ValueError):
        reasons.append("signature does not match the public key")
    except Exception as exc:  # noqa: BLE001  # pragma: no cover - malformed input
        reasons.append(f"signature verification failed: {exc}")

    return (not reasons), reasons


def verify_document(
    document: dict[str, Any],
    public_key_pem: bytes | None = None,
    *,
    trust_store: Any = None,
) -> tuple[bool, list[str], str]:
    """Verify either an evidence report or a campaign certificate.

    ``trust_store`` is a :class:`hashvault.core.evidence_schema.TrustStore`.
    When supplied, the document's ``signature.key_id`` must resolve to a
    non-revoked key in the store; embedded keys are not trusted.
    """
    from hashvault.core.evidence_schema import (
        CERTIFICATE_KIND,
        public_key_from_trust_store,
        validate_evidence_document,
    )

    kind = ""
    try:
        from hashvault.core.evidence_schema import detect_document_kind

        kind = detect_document_kind(document)
    except Exception:  # noqa: BLE001  # pragma: no cover - defensive
        kind = ""

    errors = validate_evidence_document(document)
    if errors:
        return False, errors, kind

    if trust_store is not None:
        trusted = public_key_from_trust_store(document, trust_store)
        if trusted is None:
            return (
                False,
                ["signing key is unknown or revoked in the trust store"],
                kind,
            )
        public_key_pem = trusted

    if kind == CERTIFICATE_KIND:
        from hashvault.campaign.certificate import verify_certificate

        ok, reasons = verify_certificate(document, public_key_pem)
        return ok, reasons, kind

    ok, reasons = verify_report(
        document,
        public_key_pem,
        allow_embedded=public_key_pem is None,
    )
    return ok, reasons, kind


def write_report(document: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return target
