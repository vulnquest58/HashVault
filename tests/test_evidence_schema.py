"""Tests for evidence document schemas, key ids, and trust stores."""

from __future__ import annotations

import json

from hashvault.campaign import (
    CampaignEngine,
    Target,
    build_certificate,
    sign_certificate,
)
from hashvault.core.evidence import (
    EvidenceReport,
    generate_keypair,
    public_key_id,
    sign_report,
    verify_document,
)
from hashvault.core.evidence_schema import (
    CERTIFICATE_KIND,
    REPORT_KIND,
    TrustStore,
    detect_document_kind,
    load_trust_store,
    validate_certificate_document,
    validate_evidence_document,
)
from hashvault.core.registry import HashCategory
from hashvault.models.schemas import PatternSchema


def _report() -> EvidenceReport:
    return EvidenceReport(
        generated_at="2026-01-01T00:00:00+00:00",
        tool_version="test",
        schema_version=1,
        patterns_fingerprint="",
        corpus_fingerprint="",
        database_fingerprint="",
        records=[],
        summary={"total": 0, "ok": True},
    )


def _store(public_pem: bytes, key_id: str, *, revoked: bool = False) -> TrustStore:
    return TrustStore(
        keys={} if revoked else {key_id: public_pem},
        revoked={key_id} if revoked else set(),
    )


def test_report_document_kind_and_schema_validate():
    private_pem, public_pem = generate_keypair()
    key_id = public_key_id(public_pem)
    document = sign_report(_report(), private_pem, key_id=key_id)
    assert detect_document_kind(document) == REPORT_KIND
    assert validate_evidence_document(document) == []
    ok, reasons, kind = verify_document(
        document, trust_store=_store(public_pem, key_id)
    )
    assert ok, reasons
    assert kind == REPORT_KIND


def test_revoked_trust_store_key_is_rejected():
    private_pem, public_pem = generate_keypair()
    key_id = public_key_id(public_pem)
    document = sign_report(_report(), private_pem, key_id=key_id)
    ok, reasons, _ = verify_document(
        document, trust_store=_store(public_pem, key_id, revoked=True)
    )
    assert not ok
    assert any("unknown or revoked" in reason for reason in reasons)


def test_unknown_trust_store_key_is_rejected():
    private_pem, _public_pem = generate_keypair()
    document = sign_report(_report(), private_pem)
    ok, reasons, _ = verify_document(
        document, trust_store=TrustStore(keys={}, revoked=set())
    )
    assert not ok
    assert any("unknown or revoked" in reason for reason in reasons)


def test_report_key_id_is_embedded_and_stable():
    private_pem, public_pem = generate_keypair()
    document = sign_report(_report(), private_pem)
    assert document["signature"]["key_id"] == public_key_id(public_pem)
    assert document["signature"]["public_key"] == public_pem.decode("utf-8")


def test_certificate_document_verifies_through_trust_store():
    target = Target(
        target_id="t0001",
        raw_hash="5f4dcc3b5aa765d61d8327deb882cf99",
        normalized_hash="5f4dcc3b5aa765d61d8327deb882cf99",
        username="alice",
        patterns=[
            PatternSchema(
                name="MD5",
                regex="^[a-fA-F0-9]{32}$",
                hashcat_mode=0,
                category=HashCategory.RAW_GENERIC,
            )
        ],
    )
    report = CampaignEngine(
        [target], known_plaintexts={"t0001": "password"}
    ).run()
    private_pem, public_pem = generate_keypair()
    key_id = public_key_id(public_pem)
    document = sign_certificate(build_certificate(report), private_pem, key_id=key_id)
    assert detect_document_kind(document) == CERTIFICATE_KIND
    assert validate_certificate_document(document) == []
    ok, reasons, kind = verify_document(
        document, trust_store=_store(public_pem, key_id)
    )
    assert ok, reasons
    assert kind == CERTIFICATE_KIND


def test_certificate_schema_rejects_plaintext():
    document = {
        "payload": {
            "version": 1,
            "kind": CERTIFICATE_KIND,
            "campaign_id": "abc",
            "created_at": "2026-01-01T00:00:00+00:00",
            "summary": {},
            "targets": [
                {
                    "target_id": "t1",
                    "hash": "abc",
                    "hash_sha256": "0" * 64,
                    "plaintext": "password",
                }
            ],
        },
        "signature": None,
    }
    errors = validate_certificate_document(document)
    assert any("must not contain plaintext" in error for error in errors)


def test_load_trust_store_accepts_both_shapes(tmp_path):
    _, public_pem = generate_keypair()
    pem = public_pem.decode("utf-8")
    key_id = public_key_id(public_pem)

    list_store = tmp_path / "list.json"
    list_store.write_text(
        json.dumps(
            {
                "keys": [
                    {"key_id": key_id, "public_key": pem},
                    {"key_id": "old", "public_key": pem, "revoked": True},
                ]
            }
        ),
        encoding="utf-8",
    )
    loaded = load_trust_store(list_store)
    assert loaded.key_for(key_id) == public_pem
    assert loaded.key_for("old") is None

    map_store = tmp_path / "map.json"
    map_store.write_text(json.dumps({key_id: pem}), encoding="utf-8")
    assert load_trust_store(map_store).key_for(key_id) == public_pem
