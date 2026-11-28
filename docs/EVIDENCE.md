# Evidence Reports and Trust

HashVault produces two signed JSON document kinds:

| Kind | Produced by | Contains plaintext? |
| --- | --- | --- |
| `hashvault.evidence.report` | `hashvault evidence` | No |
| `hashvault.campaign.certificate` | `hashvault campaign run --certificate` | No |

Both documents are canonicalised JSON, signed with Ed25519, and carry a
`signature.key_id` plus a payload SHA-256 digest. Evidence reports also embed
the public key so a recipient can check self-consistency; a campaign certificate
stores it in `signer_public_key`.

## Build and verify a report

```bash
# Generate a signing key once
hashvault evidence --generate-key evidence.key

# Build and sign a report
hashvault evidence --sign-key evidence.key --out evidence.json

# Verify with the matching public key
hashvault evidence --verify evidence.json --public-key evidence.pub.pem
```

`--verify` auto-detects whether the file is an evidence report or a campaign
certificate. Use `--json` for machine-readable output:

```json
{
  "valid": true,
  "kind": "hashvault.evidence.report",
  "reasons": [],
  "trust_store": "trust.json"
}
```

Without `--public-key` or `--trust-store`, HashVault checks the payload digest
and reports that the signer was not authenticated. That is useful for detecting
accidental edits, but it is not proof of publisher identity.

## Trust store

A trust store maps approved `key_id` values to public keys and records
revocations:

```json
{
  "keys": [
    {
      "key_id": "ed25519:0123456789abcdef",
      "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
    },
    {
      "key_id": "ed25519:oldkey",
      "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "revoked": true
    }
  ]
}
```

The compact map form is also accepted:

```json
{
  "ed25519:0123456789abcdef": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
}
```

Verify against it:

```bash
hashvault evidence --verify evidence.json --trust-store trust.json
hashvault campaign verify campaign.json --trust-store trust.json
```

When a trust store is supplied, the document's `signature.key_id` must resolve
to a non-revoked key. Embedded keys are not trusted. An unknown or revoked key
is a verification failure.

## Key rotation

1. Generate the new key with `hashvault evidence --generate-key new.key`.
2. Publish the new public key in the trust store alongside the old key.
3. Sign new documents with the new key.
4. After the retention window, mark the old key `"revoked": true`.
5. Re-verify retained documents before relying on them; revoked keys fail even
   if the signature is mathematically valid.

Keep private keys offline, owner-readable only (`chmod 600`), and never commit
them. A key compromise invalidates every document signed with that key.

## Threat model

| Threat | Mitigation |
| --- | --- |
| Edited report fields | Canonical payload digest and Ed25519 signature |
| Forged report signed by an unknown key | Trust store lookup by `key_id` |
| Stolen or retired key | Revocation entries; short-lived signing keys |
| Plaintext leakage in an audit artefact | Reports contain only SHA-256 digests of hashes, never plaintext |
| Substituted key in the document | Trust store wins over embedded keys |
| Silent schema drift | Structural validation before signature checks |

Signatures prove integrity and, with a trust store, publisher identity. They do
not prove that the underlying cracking was lawful, correct, or complete. Treat
evidence as one input to an audit, not a substitute for review.

## Structural validation

`hashvault.core.evidence_schema` is dependency-free and validates:

- schema version and required fields,
- record and target shapes,
- SHA-256 digest fields,
- signature block shape and key-id type,
- absence of plaintext in certificates.

Third-party verifiers can use the same checks before invoking Ed25519. A
signature over a malformed document is still rejected.

## Verification checklist

- [ ] The document kind is one of the two supported kinds.
- [ ] Structural validation passes.
- [ ] The payload digest matches the canonical payload.
- [ ] The signature verifies with a trusted, non-revoked key.
- [ ] The `generated_at`/`created_at` timestamp is within the expected window.
- [ ] The tool version and corpus fingerprints match the engagement record.
