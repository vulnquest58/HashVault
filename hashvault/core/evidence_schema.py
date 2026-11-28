"""Structural validation and trust-store helpers for evidence documents.

The signed JSON documents are intentionally small and stable.  This module
provides a dependency-free validator so a third party can check the shape of a
report or campaign certificate before deciding whether to trust its signature.

Two document kinds are supported:

* ``hashvault.evidence.report`` -- the database audit report produced by
  ``hashvault evidence``
* ``hashvault.campaign.certificate`` -- a campaign recovery certificate
  produced by ``hashvault campaign run --certificate``
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPORT_KIND = "hashvault.evidence.report"
CERTIFICATE_KIND = "hashvault.campaign.certificate"
SUPPORTED_KINDS = (REPORT_KIND, CERTIFICATE_KIND)
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass
class TrustStore:
    """Public keys and revocations loaded from a local trust-store file."""

    keys: dict[str, bytes] = field(default_factory=dict)
    revoked: set[str] = field(default_factory=set)

    def key_for(self, key_id: str) -> bytes | None:
        if not key_id or key_id in self.revoked:
            return None
        return self.keys.get(key_id)


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX64.match(value))


def detect_document_kind(document: Any) -> str:
    """Return the document kind, or an empty string when it is unknown."""
    if not isinstance(document, dict):
        return ""
    kind = document.get("kind")
    if isinstance(kind, str) and kind:
        return kind
    payload = document.get("payload")
    if isinstance(payload, dict):
        nested = payload.get("kind")
        if isinstance(nested, str):
            return nested
    # Older evidence reports did not include a kind field.
    if "records" in document and "schema_version" in document:
        return REPORT_KIND
    if isinstance(payload, dict) and "campaign_id" in payload and "targets" in payload:
        return CERTIFICATE_KIND
    return ""


def _validate_signature(document: dict[str, Any], errors: list[str]) -> None:
    signature = document.get("signature")
    if signature is None:
        return
    if not isinstance(signature, dict):
        errors.append("signature must be an object or null")
        return
    algorithm = signature.get("algorithm")
    if not isinstance(algorithm, str) or not algorithm:
        errors.append("signature.algorithm must be a non-empty string")
        return
    if algorithm == "none":
        return
    value = signature.get("value")
    if not isinstance(value, str) or not value:
        errors.append("signature.value must be a non-empty hex string")
    else:
        try:
            bytes.fromhex(value)
        except ValueError:
            errors.append("signature.value is not valid hex")
    if not _is_hex64(signature.get("payload_sha256")):
        errors.append("signature.payload_sha256 must be a SHA-256 hex digest")
    key_id = signature.get("key_id")
    if key_id is not None and not isinstance(key_id, str):
        errors.append("signature.key_id must be a string when present")


def validate_report_document(document: Any) -> list[str]:
    """Return structural errors for an evidence report."""
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["evidence report must be a JSON object"]
    version = document.get("schema_version")
    if not isinstance(version, int) or version < 1:
        errors.append("schema_version must be a positive integer")
    for field_name in ("generated_at", "tool_version"):
        if not isinstance(document.get(field_name), str):
            errors.append(f"{field_name} must be a string")
    if not isinstance(document.get("summary"), dict):
        errors.append("summary must be an object")
    records = document.get("records")
    if not isinstance(records, list):
        errors.append("records must be a list")
    else:
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                errors.append(f"records[{index}] must be an object")
                continue
            if not isinstance(record.get("record_id"), int):
                errors.append(f"records[{index}].record_id must be an integer")
            if not _is_hex64(record.get("hash_digest")):
                errors.append(f"records[{index}].hash_digest must be SHA-256 hex")
            for field_name in ("pattern", "tool", "verification"):
                if not isinstance(record.get(field_name), str):
                    errors.append(f"records[{index}].{field_name} must be a string")
    _validate_signature(document, errors)
    return errors


def validate_certificate_document(document: Any) -> list[str]:
    """Return structural errors for a campaign certificate."""
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["campaign certificate must be a JSON object"]
    payload = document.get("payload")
    if not isinstance(payload, dict):
        return ["certificate is missing a payload object"]
    if payload.get("kind") not in (CERTIFICATE_KIND, None):
        errors.append("payload.kind must be hashvault.campaign.certificate")
    if not isinstance(payload.get("version"), int) or payload.get("version") < 1:
        errors.append("payload.version must be a positive integer")
    for field_name in ("campaign_id", "created_at"):
        if not isinstance(payload.get(field_name), str):
            errors.append(f"payload.{field_name} must be a string")
    if not isinstance(payload.get("summary"), dict):
        errors.append("payload.summary must be an object")
    targets = payload.get("targets")
    if not isinstance(targets, list):
        errors.append("payload.targets must be a list")
    else:
        for index, target in enumerate(targets):
            if not isinstance(target, dict):
                errors.append(f"payload.targets[{index}] must be an object")
                continue
            if not isinstance(target.get("target_id"), str):
                errors.append(f"payload.targets[{index}].target_id must be a string")
            if not isinstance(target.get("hash"), str):
                errors.append(f"payload.targets[{index}].hash must be a string")
            if not _is_hex64(target.get("hash_sha256")):
                errors.append(f"payload.targets[{index}].hash_sha256 must be SHA-256 hex")
            if target.get("plaintext") is not None:
                errors.append("certificate targets must not contain plaintext")
            if target.get("plaintext_sha256") is not None and not _is_hex64(
                target.get("plaintext_sha256")
            ):
                errors.append(
                    f"payload.targets[{index}].plaintext_sha256 must be SHA-256 hex"
                )
    embedded = document.get("signer_public_key")
    if embedded is not None and not isinstance(embedded, str):
        errors.append("signer_public_key must be a PEM string when present")
    _validate_signature(document, errors)
    return errors


def validate_evidence_document(document: Any) -> list[str]:
    """Validate either supported document kind."""
    kind = detect_document_kind(document)
    if kind == REPORT_KIND:
        return validate_report_document(document)
    if kind == CERTIFICATE_KIND:
        return validate_certificate_document(document)
    return [f"unsupported evidence document kind: {kind or 'unknown'}"]


def load_trust_store(path: str | Path) -> TrustStore:
    """Load a JSON trust store.

    Accepted forms::

        {"keys": [{"key_id": "...", "public_key": "-----BEGIN ..."}]}
        {"key-id": "-----BEGIN PUBLIC KEY-----..."}
    """
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    store = TrustStore()
    if isinstance(document, dict) and "keys" in document:
        entries = document.get("keys")
        if not isinstance(entries, list):
            raise ValueError("trust store keys must be a list")
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            key_id = entry.get("key_id")
            pem = entry.get("public_key") or entry.get("pem")
            if not isinstance(key_id, str) or not isinstance(pem, str):
                continue
            if entry.get("revoked"):
                store.revoked.add(key_id)
            else:
                store.keys[key_id] = pem.encode("utf-8")
        return store
    if isinstance(document, dict):
        for key_id, pem in document.items():
            if isinstance(key_id, str) and isinstance(pem, str):
                store.keys[key_id] = pem.encode("utf-8")
        return store
    raise ValueError("trust store must be a JSON object")


def key_id_from_document(document: dict[str, Any]) -> str:
    """Return the recorded signing key id, if any."""
    signature = document.get("signature")
    if isinstance(signature, dict) and isinstance(signature.get("key_id"), str):
        return str(signature["key_id"])
    return ""


def public_key_from_trust_store(
    document: dict[str, Any],
    store: TrustStore,
) -> bytes | None:
    """Resolve the document's key id against a trust store."""
    return store.key_for(key_id_from_document(document))
