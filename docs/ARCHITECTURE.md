# Architecture

HashVault is organized as a pipeline with an offline operations layer and a
corpus-level campaign engine. The design goal is reproducible, verifiable work:
every stage should be able to explain what it saw and what it did.

## High-level flow

```text
input
  |
  v
[0] convert (optional)  file -> hash material
  |
  v
[1] analyzer            bounded beam search across reversible operations
  |
  v
[2] identifier          catalogue + curated patterns + confidence
  |
  v
[3] canonicalizer       split username, normalize payload
  |
  v
[4] router              hashcat / John / built-in, adaptive ordering
  |
  v
[5] executor            session-isolated subprocesses, budgets, retries
  |
  v
[6] reporter            Rich / JSON / CSV, attempts, ambiguity, recipes
  |
  v
[7] operations          doctor / audit / insights / stats / evidence
```

## Components

| Path | Responsibility |
| --- | --- |
| `hashvault/analysis/` | Reversible-operation search, hypothesis ranking, recipes |
| `hashvault/core/identifier.py` | Pattern matching, source context, confidence scoring |
| `hashvault/core/canonicalizer.py` | Payload normalization and username splitting |
| `hashvault/core/router.py` | Tool and format selection |
| `hashvault/core/orchestrator.py` | Session-isolated execution, budgets, and retries |
| `hashvault/core/cracker.py` | Cracking orchestration and result handling |
| `hashvault/core/builtin.py` | Dependency-light verifier and cracking engine |
| `hashvault/core/database.py` | SQLite catalogue, cache, analysis log, sessions |
| `hashvault/core/doctor.py` | Offline readiness checks |
| `hashvault/core/integrity.py` | Cracked-record verification |
| `hashvault/core/insights.py` | Aggregate analytics without plaintext exposure |
| `hashvault/core/evidence.py` | Ed25519 evidence primitives and unified verification |
| `hashvault/core/evidence_schema.py` | Document validation, key ids, trust stores |
| `hashvault/core/corpus_validator.py` | Corpus schema, provenance, count, and duplicate checks |
| `hashvault/ingestors/converter_store.py` | Managed John converter store and manifest |
| `hashvault/ingestors/conversion_service.py` | Ranked auto-conversion orchestration |
| `hashvault/campaign/` | Corpus ingestion, planning, mutations, recovery, checkpoints, potfiles, certificates |
| `hashvault/cli.py` | Typer command surface |
| `hashvault/ui/` | Rich rendering and interactive shell |
| `config/default.yaml` | Runtime defaults |

## Campaign engine

The campaign engine is intentionally separate from single-hash cracking. It
operates on a parsed corpus and treats each target as a unit of evidence.

1. **Ingest** - parse pwdump, shadow, and generic `username:hash` inputs into
   normalized targets with source context.
2. **Plan** - identify candidate patterns per target, bounded by
   `max_patterns`, and order work from cheapest/most likely to most expensive.
3. **Exact reuse** - when a plaintext is recovered, test it immediately against
   every compatible target. This catches shared passwords without a wordlist.
4. **Mutations** - derive bounded candidates from usernames, domains, dates,
   known plaintexts, and optional context. Slow KDFs are skipped unless
   `include_slow` is set.
5. **Wordlist pass** - optionally test a supplied wordlist against remaining
   fast targets.
6. **Verification** - every reported recovery is verified against its target
   hash before it is accepted.
7. **Checkpoint** - optionally write verified recoveries and stage counters so
   a long run can resume. Restored plaintexts are re-verified.
8. **Potfile import** - merge already-recovered hashcat/John values and record
   their source in recovery evidence.
9. **Certificate** - emit a plaintext-free report containing hashes, methods,
   plaintext SHA-256 commitments, coverage notes, and uncertainty.

`--shard INDEX/TOTAL` assigns records deterministically for parallel workers.
The engine is deterministic for a fixed corpus, configuration, and candidate
limit. It does not call external services.

## Evidence and certificates

Campaign certificates and `hashvault evidence` reports share the same principle:
commit to facts without leaking secrets.

- Plaintexts are represented by SHA-256 commitments, not values.
- Certificates include target hashes, pattern decisions, methods, and coverage
  notes.
- Ed25519 signatures protect the canonical payload.
- Verification checks both the payload digest and the signature.
- A trust store maps approved key ids to public keys and revocations; embedded
  keys are not trusted when a store is supplied.

The signing key is generated with `hashvault campaign keygen`. Treat private
keys as sensitive; public keys can be distributed with the evidence.

## Security boundaries

- All subprocess calls use `shell=False`.
- John helpers are resolved from the configured John installation or
  `tools/john`; PATH and working-directory lookups are refused.
- Cracking sessions are isolated and cleaned up by default.
- Decompression and archive extraction are byte-capped.
- Input size is capped at 64 MiB by default (`HASHVAULT_MAX_INPUT_BYTES`).
- History does not store plaintext.
- LLM and enrichment are local-only and disabled by default.
- Non-loopback LLM endpoints are refused unless explicitly enabled.

## Design trade-offs

- **Bounded search over exhaustive search.** The analyzer is designed to be
  fast and explainable, not to enumerate every possible transform.
- **Verification over heuristics.** A candidate is not reported as recovered
  until it verifies against the target.
- **Evidence over screenshots.** Certificates and evidence reports are
  machine-verifiable and reproducible.
- **Local-first over convenience.** No telemetry, no cloud dependencies, and no
  implicit uploads.
