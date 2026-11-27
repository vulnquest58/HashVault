# Roadmap

This roadmap describes direction, not commitments. Priorities may change based
on security, correctness, and contributor interest.

## v2.0 - Public foundation

- [x] Corpus recovery campaign engine.
- [x] Plaintext-free signed certificates.
- [x] 0xdf-derived verified corpus and demo fixtures.
- [x] Professional documentation and contribution infrastructure.
- [x] CI baseline on Python 3.11-3.13.
- [x] Public repository and first GitHub release.

## v2.1 - Contributor experience

- [ ] Reduce legacy `ruff` and `mypy` debt without mass-formatting unrelated
      files.
- [ ] Add more campaign regression cases for shadow, pwdump, and mixed corpora.
- [ ] Publish a short "add a verifier" guide with a worked example.
- [ ] Improve error messages for unsupported or ambiguous formats.
- [ ] Add a reproducible benchmark report to the documentation.

## v2.2 - Evidence and interoperability

- [ ] Export campaign certificates as a documented JSON schema.
- [ ] Add a verifier command for third-party evidence documents.
- [ ] Improve hashcat/John result import and reconciliation.
- [ ] Add structured machine-readable plan output for campaign jobs.
- [ ] Document threat models for shared evidence and key handling.

## v2.3 - Corpus and analysis quality

- [ ] Expand the 0xdf corpus with newly verified cases.
- [ ] Add a corpus contribution validator and review checklist.
- [ ] Improve analyzer ranking with explainable feature contributions.
- [ ] Add more negative tests for decompression and archive limits.
- [ ] Evaluate additional verifier libraries behind optional extras.

## Good first issues

- Fix a documentation typo or broken link.
- Add a test for a published hash format using a verified vector.
- Improve an error message with a reproduction.
- Add a 0xdf case with provenance and a verification test.
- Add a small example to `examples/` with attribution.
- Improve CLI help text for an existing option.
- Add a FAQ entry based on a real question.

## Non-goals

- Unauthorized access, credential theft, or stealth/evasion features.
- Cloud processing of customer hashes by default.
- Silent telemetry.
- Replacing hashcat or John for high-throughput cracking.
