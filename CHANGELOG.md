# Changelog

All notable changes to HashVault are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/).

## [2.2.0] - 2026-11-28

### Added

- Managed John converter store under `tools/converters` with category layout,
  shared Perl modules, SHA-256 manifest, and `hashvault convert --sync`.
- Unified `hashvault convert` workflow: gallery, automatic profile selection,
  built-in fallback, `--paths`, `--save`, `--out-dir`, and JSON attempt
  reporting.
- Bounded-memory file-type detection for conversions: magic bytes only, with
  JSON parsing limited to small inputs.
- Resumable campaigns: checkpoints, `--checkpoint`, `--resume`, stage progress,
  and re-verification of every restored plaintext.
- Hashcat/John potfile import through `--potfile`, including `$HEX[...]`
  plaintext decoding and source provenance in recovery evidence.
- Deterministic campaign sharding with `--shard INDEX/TOTAL`.
- Streaming corpus ingestion through `iter_corpus_file`.
- Evidence schema and trust layer: document kind detection, structural
  validation, `key_id` support, trust stores, revocation, and unified
  `verify_document` for reports and certificates.
- `hashvault corpus validate` with schema, provenance, count, duplicate-id,
  duplicate-hash, and negative-case checks.
- `hashvault doctor --fix` for safe local directory creation and converter
  store diagnostics.
- Windows CI, coverage gate, package smoke test, and corpus validation in CI.
- Documentation: `docs/CONVERSIONS.md`, `docs/EVIDENCE.md`, expanded CLI,
  corpus, README, and release guidance.

### Changed

- Campaign certificates now include `schema_version`, `signature.key_id`, and
  schema validation before signature checks.
- Evidence reports include `kind` and `signature.key_id`; embedded-key
  verification is explicit and trust-store lookup takes precedence.
- `convert` output paths are configurable through `paths.conversions_dir` and
  `paths.checkpoints_dir`.
- Test baseline increased to 464 tests with 70% coverage gate.

## [2.0.1] - 2026-11-27

### Fixed

- Installed packages now bundle the runtime `data/` and `config/` trees and
  resolve them from the active virtual environment when the working directory
  is elsewhere.
- `load_config` now finds the bundled `config/default.yaml` for installed
  packages.
- Verified `hashvault setup`, `identify`, `doctor`, and `campaign run` from a
  clean wheel installation outside the repository.
- Added wheel data-file packaging and a release smoke test for the installed
  package layout.

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
