# FAQ

## Is HashVault a replacement for hashcat or John the Ripper?

No. HashVault is an analysis, orchestration, and evidence layer. It can call
hashcat and John, and it includes a dependency-light built-in engine for common
formats and correctness checks. For high-throughput cracking, use the dedicated
engines.

## Is it safe to use on customer data?

Only with explicit authorization and a defined handling policy. HashVault is
offline-first and avoids telemetry, but you are responsible for the data you
load, the reports you generate, and the keys you use. Do not commit databases,
potfiles, session artifacts, or plaintext reports to the repository.

## What is a campaign?

A campaign treats a credential corpus as a set of related evidence. It plans
work, reuses recovered plaintexts, applies bounded context mutations, verifies
recoveries, and can emit a plaintext-free signed certificate.

## What is in a campaign certificate?

Target hashes, pattern decisions, methods, plaintext SHA-256 commitments, and
coverage/uncertainty notes. It does not contain recovered plaintext. A private
signing key is required to sign; the public key verifies.

## Why are slow hashes skipped?

bcrypt, sha512crypt, and similar KDFs are intentionally expensive. Mutation and
wordlist stages skip them by default so a campaign does not spend its budget on
a few targets. Use `--include-slow` when that is the intended trade-off.

## Why does identification report multiple candidates?

Some digest shapes are inherently ambiguous. A bare 32-hex value could be MD5,
NTLM, LM, or several other formats. Use source context (`--hint`) or a pattern
override when it is known. HashVault preserves ambiguity rather than inventing
certainty.

## Does HashVault upload hashes or plaintext?

No, not by default. The core workflows are local. Optional LLM and enrichment
features are disabled by default, use local endpoints/paths, and never send data
off-host unless explicitly configured.

## Where did the test hashes come from?

The 0xdf corpus is derived from published Hack The Box writeups at
<https://0xdf.gitlab.io/>. Every accepted plaintext is verified against its
hash. See [CORPUS.md](CORPUS.md) for provenance and the verification policy.

## Can I contribute a corpus case?

Yes, if it is published, non-sensitive, and verifiable. Include the source URL,
the hash material, the expected plaintext, and a test. Do not submit customer
data or live credentials. See [CONTRIBUTING.md](../CONTRIBUTING.md).

## Why is the legacy code not fully lint-clean?

The project grew quickly during v2.0. The campaign package is lint-clean and
covered by CI, while the legacy tree has a tracked `ruff`/`mypy` backlog. We
prefer focused, reviewable fixes over a mass-formatting commit.

## How do I report a security issue?

Use GitHub private vulnerability reporting:
<https://github.com/vulnquest58/HashVault/security/advisories/new>. See
[SECURITY.md](../SECURITY.md).
