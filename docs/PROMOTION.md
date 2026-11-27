# Launch and Promotion Kit

This kit keeps public messaging accurate, useful, and non-spammy. Promote the
project by explaining the problem it solves and inviting specific
contributions.

## One-line description

HashVault is an evidence-driven password hash workbench for authorized security
testing, with corpus recovery campaigns and plaintext-free signed certificates.

## Short description

HashVault identifies hashes, unwraps encoded inputs, routes work to hashcat,
John the Ripper, or a built-in engine, and records verifiable evidence. Its
campaign engine reuses recovered plaintexts across a corpus and emits signed
certificates that commit to results without exposing plaintext.

## GitHub repository settings

- Description: `Evidence-driven password hash analysis, recovery, and audit reporting`
- Topics: `password-security`, `hash-identification`, `password-auditing`,
  `security-tools`, `hashcat`, `john-the-ripper`, `ctf`, `digital-forensics`,
  `python`, `ed25519`
- Homepage: repository README or project docs
- Enable Issues and Discussions
- Enable private vulnerability reporting
- Pin the release and contribution guide

## Launch post

> HashVault v2.0 is out. It is an offline-first hash analysis and recovery
> workbench for authorized security testing. The new campaign engine treats a
> credential corpus as evidence: recovered plaintexts are reused across targets,
> context drives bounded mutations, and every recovery is verified. Results can
> be exported as plaintext-free Ed25519-signed certificates.
>
> The repo includes a verified 0xdf-derived corpus, 436 tests, a built-in
> engine, and optional hashcat/John integration. Contributions welcome,
> especially corpus cases, verifier tests, and documentation.
>
> Authorized use only.

## Show HN / forum post

Title: `Show HN: HashVault - evidence-driven hash analysis and recovery`

Body:

> I built HashVault because most hash tools stop at identification. During
> authorized audits I wanted a repeatable record of what was tried, what was
> recovered, and what remained uncertain.
>
> HashVault v2.0 adds a corpus campaign engine: exact-reuse propagation,
> context mutations, wordlist passes, and plaintext-free signed certificates.
> It also has a 54-operation analyzer, 482 curated patterns, and optional
> hashcat/John/built-in engines.
>
> It is offline-first and MIT licensed. The test corpus includes verified cases
> from 0xdf's HTB writeups. Feedback on the campaign model and certificate
> format is especially welcome.
>
> Authorized security testing only.

## Social post variants

Short:

> HashVault v2.0: hash identification, corpus recovery campaigns, and
> plaintext-free signed evidence for authorized security testing. MIT licensed.
> 436 tests. Contributions welcome.

Technical:

> New in HashVault v2.0: campaign recovery. Seed one known plaintext, propagate
> exact reuse across a corpus, apply bounded username/date/domain mutations,
> verify every recovery, and export an Ed25519-signed certificate with SHA-256
> commitments instead of plaintext. Offline-first, MIT.

## Contribution asks

- Add a verified 0xdf corpus case with provenance.
- Add a verifier test for an under-covered format.
- Improve campaign tests for shadow/pwdump edge cases.
- Review the certificate schema and threat model.
- Improve docs for a workflow you use.
- Report a reproducible bug with a minimal fixture.

## Blog post outline

1. The problem: identification is not an audit trail.
2. The pipeline: analyze, identify, route, execute, report.
3. Campaign recovery: exact reuse, mutations, verification.
4. Certificates: commit to results without leaking plaintext.
5. Corpus provenance and the 0xdf cases.
6. How to contribute.

## Rules for promotion

- Do not post customer data, live hashes, or engagement details.
- Do not encourage unauthorized access.
- Do not mass-post the same message across communities.
- Follow each community's self-promotion rules.
- Lead with the problem and the evidence model, not just feature counts.
- Correct mistakes publicly and link to the changelog.
