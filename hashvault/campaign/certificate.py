"""Plaintext-free, signed recovery certificates for campaign results."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from hashvault.campaign.models import CampaignReport, Target
from hashvault.core.evidence import EvidenceError, generate_keypair, public_key_id


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _target_certificate(target: Target) -> dict[str, Any]:
    data: dict[str, Any] = {
        "target_id": target.target_id,
        "hash": target.normalized_hash,
        "hash_sha256": _sha256(target.normalized_hash),
        "username": target.username,
        "source": target.source,
        "status": target.status,
        "pattern": target.pattern_name,
        "patterns": target.pattern_names(),
        "method": target.method,
        "evidence": [item.to_dict() for item in target.evidence],
    }
    if target.plaintext is not None:
        data["plaintext_sha256"] = _sha256(target.plaintext)
        data["plaintext_length"] = len(target.plaintext)
    return data


def build_certificate(report: CampaignReport) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": 1,
        "version": 1,
        "kind": "hashvault.campaign.certificate",
        "campaign_id": report.campaign_id,
        "created_at": report.created_at.isoformat(),
        "summary": report.summary(),
        "targets": [_target_certificate(target) for target in report.targets],
    }
    return {"payload": payload, "signature": None}


def sign_certificate(
    document: dict[str, Any],
    private_key_pem: bytes,
    *,
    key_id: str = "",
) -> dict[str, Any]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError as exc:
        raise EvidenceError("Signing requires the 'cryptography' package.") from exc

    try:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    except Exception as exc:
        raise EvidenceError(f"Invalid private key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise EvidenceError("Signing key must be Ed25519.")

    payload = document.get("payload")
    if not isinstance(payload, dict):
        raise EvidenceError("Certificate is missing a payload object.")
    canonical = _canonical(payload)
    signature = key.sign(canonical)
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    document = dict(document)
    document["signature"] = {
        "algorithm": "ed25519",
        "value": signature.hex(),
        "payload_sha256": hashlib.sha256(canonical).hexdigest(),
        "key_id": key_id or public_key_id(public_pem),
    }
    document["signer_public_key"] = public_pem.decode("utf-8")
    return document


def verify_certificate(
    document: dict[str, Any], public_key_pem: bytes | None = None
) -> tuple[bool, list[str]]:
    from hashvault.core.evidence_schema import validate_certificate_document

    schema_errors = validate_certificate_document(document)
    if schema_errors:
        return False, schema_errors

    reasons: list[str] = []
    payload = document.get("payload")
    signature_block = document.get("signature")
    if not isinstance(payload, dict):
        return False, ["certificate is missing a payload object"]
    if not isinstance(signature_block, dict):
        return False, ["certificate is not signed"]

    canonical = _canonical(payload)
    recorded = signature_block.get("payload_sha256")
    actual = hashlib.sha256(canonical).hexdigest()
    if recorded != actual:
        reasons.append("payload digest mismatch: the certificate was modified")

    if public_key_pem is None:
        embedded = document.get("signer_public_key")
        if isinstance(embedded, str):
            public_key_pem = embedded.encode("utf-8")
    if public_key_pem is None:
        reasons.append("no public key available for signature verification")
        return False, reasons

    recorded_key_id = signature_block.get("key_id")
    if (
        isinstance(recorded_key_id, str)
        and recorded_key_id.startswith("ed25519:")
        and recorded_key_id != public_key_id(public_key_pem)
    ):
        reasons.append("signature key id does not match the verification key")

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:
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
        key.verify(bytes.fromhex(str(signature_block.get("value", ""))), canonical)
    except (InvalidSignature, ValueError):
        reasons.append("signature does not match the public key")
    return not reasons, reasons


def write_certificate(document: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return target


def generate_certificate_keypair() -> tuple[bytes, bytes]:
    return generate_keypair()
