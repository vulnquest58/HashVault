# Changelog

All notable changes to HashVault are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-11-27

### Added

- Corpus recovery campaign engine with staged planning, exact-reuse
  propagation, bounded context mutations, optional wordlist passes, and
  slow-KDF controls.
- Campaign CLI commands: `campaign plan`, `campaign run`, `campaign keygen`,
  and `campaign verify`.
- Plaintext-free Ed25519 recovery certificates with SHA-256 plaintext
  commitments and coverage/uncertainty notes.
- `tests/test_campaign.py` coverage for corpus ingestion, propagation,
  mutation, wordlists, slow-target handling, plan ordering, and certificate
  signing/tamper detection.
- Professional documentation set: CLI reference, architecture, corpus
  provenance, release process, roadmap, launch kit, FAQ, security policy,
  contribution guide, code of conduct, and changelog.
- GitHub CI workflow, issue forms, pull request template, and release
  checklist.
- `examples/0xdf-demo.txt` and `examples/0xdf-known.json` fixtures derived from
  the verified 0xdf corpus.

### Changed

- Version aligned to `2.0.0` across package metadata and documentation.
- README rewritten for public adoption, with accurate clone URL, quick start,
  campaign examples, architecture, and documentation links.
- Console entry point now dispatches through `hashvault.__main__:main`.
- Corpus documentation records 0xdf provenance and verification policy.

### Fixed

- `.gitignore` now unignores package `__init__.py` files while still ignoring
  caches, databases, sessions, and SQLite sidecar files.
- `pyproject.toml` dependency placement corrected and `bcrypt` added to the
  development extra.
- Removed garbled documentation text and stale private-repository publishing
  instructions.
- Removed the obsolete private-repository publishing script and generated
  `live-test-*` wordlist artifacts from the repository.
- Fixed Python 3.11 compatibility in the CLI f-string used by `analyze`.
- Fixed the release workflow's source-distribution content check.
- Debian working copy no longer carries a stray root-level `cli.py`.

### Verification

- `436 passed` on Windows and Debian.
- Campaign package passes `ruff check`.
- Campaign CLI smoke path and certificate verification pass.

## [0.1.0] - Initial development

- Initial HashVault security auditing toolkit: identification, analysis,
  cracking, conversion, database, reporting, and interactive shell.
