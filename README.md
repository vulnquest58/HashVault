# HashVault - Security Auditing Tool

<p align="center">
  <img src="docs/banner.svg" alt="HashVault wordmark" width="460">
</p>

<p align="center">
  <b>vulnquest</b> · <a href="https://github.com/vulnquest58">github.com/vulnquest58</a><br>
  <a href="https://github.com/vulnquest58/HashVault">github.com/vulnquest58/HashVault</a>
</p>

HashVault is a professional security auditing tool designed for authorized penetration testing and password strength assessment. It provides advanced hash identification and cracking capabilities with a focus on security, reliability, and ease of use.

The wordmark is also available in the CLI:

```bash
hashvault banner          # coloured
hashvault banner --plain  # no ANSI colour
hashvault banner --json   # {project, author, github, wordmark}
```

## Legal & Ethical Use

**IMPORTANT**: HashVault is designed exclusively for authorized security professionals and system administrators. It must only be used:

- On systems you own or have explicit written permission to test
- As part of authorized penetration testing engagements
- For legitimate security auditing purposes
- In compliance with all applicable laws and regulations

**Unauthorized use of this tool is illegal and unethical.** Always obtain proper authorization before testing any system or retrieving any password hashes.

This tool is distributed under the MIT License and follows the same ethical guidelines as industry-standard tools like hashcat and John the Ripper. Users are solely responsible for ensuring their use complies with all relevant laws and regulations.

## Features

- **473 hashcat modes + curated patterns** — generated from `hashcat --example-hashes`, with local curated overrides for 482 registered patterns on a fresh setup
- **CyberChef-style deep analysis** (`analyze`): unwraps arbitrary encoded/wrapped input across 54 operations (Base64, Hex, URL, UTF-16, Gzip/Zlib/archives, classical ciphers, keyed XOR/RC4/AES, extractors) down to a bare hash before identification
- **Live analysis view** (`--live`): beam-search progress, terminal branches, node/depth counters, and the winning chain in real time
- **End-to-end self-test** (`selftest`): 68-case analysis matrix covering every operation, per-operation JSON coverage, and a built-in cracking handoff
- **File-to-hash converter gallery** (`convert`): 70 curated John profiles for archives, documents, password managers, encrypted disks, private keys, enterprise captures, wallets, and applications, with runtime availability checks
- Multi-layer hash identification with confidence scoring and ambiguity handling
- **Canonicalizer + Router**: normalises the hash payload for each tool and automatically routes to the best cracking engine (hashcat → John → built-in) with fallback logic
- **Closed-loop analysis retries**: when a decoded branch fails, alternative hypotheses are re-identified and trial-cracked with per-hash or per-attempt budgets
- **Layered recipe benchmark** (`benchmark-layers`): deterministic wrapped-hash vectors check the full unwrap chain, target mode, and optional plaintext recovery
- **Portable recipes** (`--recipe-out`, `replay`): export and deterministically replay every unwrap operation without re-running beam search
- **Context-aware mutation** (`mutate`): bounded username/organization/date/keyword candidates, Arabic/Arabizi variants, local history/wordlist enrichment, and generated Hashcat rules
- **Hash parameter analysis** (`parameters`): parse bcrypt, sha-crypt, PBKDF2, Argon2, scrypt, and Cisco type 8 parameters and estimate offline work factor
- **Adaptive strategy feedback** (`strategies stats`): local UCB-style tool/pattern success tracking used to order cracking attempts
- **Offline environment doctor** (`doctor`): checks database, patterns, corpora, wordlists, rules, paths, engines, optional dependencies, and LLM/enrichment configuration; `--probe` runs local hashcat device discovery
- **Cracked-record integrity audit** (`audit`): re-verifies stored plaintexts against canonical hashes and reports mismatches, unsupported verifiers, and errors without exposing plaintext in the report
- **Audit insights** (`insights`): aggregates analysis resolution/ambiguity, attempt success, top patterns/tools, and adaptive feedback into text or JSON with actionable recommendations
- **Optional local-only LLM seeds**: disabled-by-default Ollama bridge for authorized offline audits
- **Analysis log**: every analysis run is recorded to `analysis_log` for quality tracking and aggregate insight trends
- Multi-tool support (hashcat, John the Ripper, and a dependency-light pure-Python built-in engine)
- **Built-in engine** (`--tool builtin`): dictionary, rules, mask, and hybrid attacks for common hash families without external binaries
- Interactive and CLI modes with enhanced hash-paste detection
- Session isolation for parallel cracking operations
- Comprehensive reporting (Rich tables, JSON, CSV)
- Secure resource management with strict subprocess controls (`shell=False` everywhere)
- **Pattern quality audit** (`patterns-audit`): uncompilable regexes, regexes that accept impossible input, modes their own hashcat example fails, and pattern groups whose identical regex + weight make ranking arbitrary
- **Confidence calibration** (`calibrate`): Brier score and expected calibration error against corpus truth, plus pattern weights derived from observed accuracy
- **Cracking budget planner** (`plan`): keyspace and measured-or-reference hash rate to an ETA, flagged against an audit window
- **Empirical disambiguation** (`crack --resolve-trials`): separates formats that share a regex by trial-cracking the top candidates
- **Signed audit evidence** (`evidence`): plaintext-free Ed25519-signed report pinning tool, catalogue, corpus and record fingerprints

## Installation

### Prerequisites

- Python 3.11 or higher
- [hashcat](https://hashcat.net/hashcat/) (optional, for cracking)
- [John the Ripper](https://www.openwall.com/john/) (optional, alternative cracking)
- Perl, Node.js, or Lua for the corresponding John converter profiles; missing runtimes are reported as unavailable in the gallery

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/HashVault.git
cd HashVault

# Install with uv (recommended)
uv pip install -e .

# Or with pip
pip install -e .

# Optional: add passlib/bcrypt verifiers beyond the built-in engine
pip install -e ".[builtin]"

# Initialize the database and fetch resources
hashvault setup

# Verify the local installation, database, corpora, and engines
hashvault doctor

# Refresh resources from a terminal on any platform
hashvault fetch-resources
# POSIX alternative:
bash scripts/fetch_resources.sh
```

## Quick Start

### Interactive Mode
```bash
hashvault
# or explicitly
hashvault interactive
```

The prompt includes tab completion, history auto-suggestions, and a live
toolbar showing auto-crack, adaptive ordering, retry, and budget state.
`F1` help, `F2` toggles auto-crack, `F3` refreshes completions, `F4` opens
strategy stats, `F5` inserts `parameters`, and `F6` inserts `mutate`.
`gallery <file>` lists the matching John converters, their availability, and
lets you select a profile for conversion. `Ctrl+C` cancels the current line;
`Ctrl+D` exits. Runtime controls:

```text
set auto-crack on|off
set adaptive on|off
set retry on|off
set budget <seconds>     # 0 = unlimited
```

### Diagnose the Environment
```bash
hashvault doctor
# Offline checks: database, patterns, corpora, resources, paths, engines,
# optional verifiers, and LLM/enrichment configuration.

hashvault doctor --json
# CI-friendly report with ok/warn/fail checks.

hashvault doctor --probe
# Also runs hashcat device discovery to check backend availability.
```

### Audit Stored Results and Review Insights
```bash
hashvault audit
# Recompute each stored plaintext against its canonical hash.

hashvault audit --pattern MD5 --limit 100 --json
# Scope the integrity check and emit per-record results.

hashvault insights
hashvault insights --days 30 --json
# Aggregate analysis resolution, cracking attempts, top patterns/tools,
# adaptive feedback, and recommendations without exposing plaintexts.
```

### Deep-Analyse Any Input (CyberChef-style)
```bash
hashvault analyze NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk=
# Unwraps the Base64 layer, then identifies the inner hash.

hashvault analyze --file payload.txt --live --extractors
# Live beam-search view; extractors allowed for URLs/configs/code blobs.

hashvault analyze --file data.bin --key aes_key=hex:001122... --key aes_iv=hex:...
# Keyed transforms: vigenere_key, xor_key, rc4_key, aes_key, aes_iv, aes_nonce, aes_tag.

hashvault analyze --file payload.b64 --crack --wordlist rockyou.txt
# After analysis, hand the resolved hash to the cracker with the chosen pattern.
```

### Run the Self-Test Matrix
```bash
hashvault selftest
# 68 analysis cases, all 54 operations covered.

hashvault selftest --crack --report matrix.json
# Adds built-in cracking checks and writes the full JSON report.

hashvault selftest --live
# Streams each matrix case as it completes.

hashvault selftest --json
# Machine-readable report: summary, per-operation coverage, and every case.
```

### Identify a Hash
```bash
hashvault identify 5f4dcc3b5aa765d61d8327deb882cf99
hashvault identify NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk= --json
# Wrapped input includes the decoded chain and analysis branches in JSON.

hashvault identify hashes.txt --file --json
# File mode emits one JSON array, with an entry per parsed record.
```

### Regenerate the Full Pattern Catalogue
```bash
python scripts/build_patterns_from_hashcat.py
# Reads tools/hashcat --example-hashes, regenerates data/patterns/patterns.json
# (473 modes), plus patterns.meta.json and patterns.report.json. Curated
# overrides in data/patterns/curated_overrides.json bring a clean seeded
# database to 482 registered patterns.
```

### Build and Benchmark the Corpus
```bash
# Verify the generated Hashcat corpus is current
python scripts/build_hash_corpus.py --check

# Fetch pinned upstream tests and rebuild the verified crypto-vector corpus
python scripts/build_crypto_corpus.py
python scripts/build_crypto_corpus.py --check

# Identify all bundled corpora (Hashcat + 0xdf + crypto vectors)
python scripts/benchmark_corpus.py

# Load the same entries from SQLite (seeded by `hashvault setup`)
python scripts/benchmark_corpus.py --from-db

# Limit to one source, run the built-in cracker, and save the report
python scripts/benchmark_corpus.py --source crypto --crack \
  --json reports/crypto-corpus.json

# Build/verify the deterministic layered-recipe corpus
python scripts/build_layer_corpus.py
python scripts/build_layer_corpus.py --check

# Check every unwrap chain, target mode, and optional plaintext recovery
python scripts/benchmark_layers.py --crack
# Equivalent CLI command:
hashvault benchmark-layers --crack --json reports/layers.json
```

The benchmark loads 311 usable Hashcat examples, 20 verified real-world 0xdf
cases, 158 locally verified crypto-library vectors (32 modes) from
`data/corpus/crypto_vectors.json`, 3 artefacts recovered from the local
CTF/lab tree (`data/corpus/ctf_writeups.json`), and 8 public CTF challenges
(`data/corpus/ctf_public.json`, TryHackMe *Crack the Hash* and its published
writeups). Every plaintext in the two CTF corpora is re-derived locally —
md5/sha1/sha256/md4/bcrypt/sha512-crypt — and compared against the published
digest before it is accepted; published answers that could not be reproduced
were dropped. Truncated and binary-only examples are skipped unless
`--include-unusable` is passed. Cracking uses a one-word list per entry for
correctness checks; pass `--wordlist rockyou.txt` for throughput measurements.
`hashvault setup` seeds `corpus_entries` for DB-backed runs.
File-mode benchmarks seed a clean temporary catalogue; `--from-db` uses the
configured SQLite catalogue. The current reference run identifies 327/489
evaluated hashes exactly and 466/489 in the candidate set, and the built-in
cracker recovers 220/220 attempted plaintexts. The layered reference corpus
passes 18/18 chains, target modes, and plaintext checks.

### Crack a Hash
```bash
hashvault crack 5f4dcc3b5aa765d61d8327deb882cf99

# Force a pattern and use the built-in engine
hashvault crack '$S$C337...' --pattern Drupal7 --tool builtin

# Mask attack (hashcat syntax; also supported by the built-in engine)
hashvault crack 5f4dcc3b5aa765d61d8327deb882cf99 --attack-mode mask --mask '?l?l?l?l?d?d'

# Retry unresolved analysis branches with a 60-second total budget
hashvault crack NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk= --auto \
  --budget-seconds 60 --max-alternative-attempts 3

# Export a successful recipe and replay it later
hashvault crack NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk= --auto \
  --recipe-out recipes/case.json
hashvault replay recipes/case.json
```

Bare 32-hex digests are inherently ambiguous (MD5, NTLM, LM, and several
password schemes share the shape). Use `--hint windows` or `--pattern NTLM`
when the source is known; the analyzer otherwise preserves the ambiguity and
reports ranked candidates.

### Batch Processing
```bash
hashvault crack --file hashes.txt --format secretsdump
```

### Targeted Mutation from Authorized Context
```bash
hashvault mutate context.yaml --limit 500 \
  --wordlist-out audit-wordlist.txt --rules-out audit.rule

hashvault mutate --term ahmed --term acme --year 2026
hashvault mutate --history --enrich local-names.txt --language both
hashvault mutate context.json --llm   # only when enabled in config/default.yaml
```

Context files accept JSON or YAML fields such as `username`, `email`,
`display_name`, `organization`, `project`, `domain`, `dates`, `locale`, and
`keywords`. Mutation output is deterministic and bounded. Local enrichment is
opt-in; the Ollama bridge is disabled by default and never sends data off-host
unless explicitly configured.

### Hash Parameter Analysis
```bash
hashvault parameters '$2b$12$...'
hashvault parameters hashes.txt --file --json
```
This reports salts, iteration/cost parameters, work factor, cost class, and
whether an audit should cap runtime. It never predicts or invents unknown
parameters.

### Adaptive Strategy Feedback
```bash
hashvault strategies stats
hashvault strategies stats --json
hashvault strategies reset --yes
```
Successful and failed tool/pattern/mode attempts are stored locally and used
for exploration-aware ordering. Disable it with `--no-adaptive`. Use
`hashvault insights` for aggregated strategy leaders and audit recommendations.

### Convert an Encrypted File → Hash
```bash
# Browse the curated John converter gallery:
hashvault convert --gallery
hashvault convert --gallery --filter archive
hashvault convert --gallery --filter keepass --json

# Inspect the profiles that match a file, then select one:
hashvault convert vault.kdbx --gallery
hashvault convert vault.kdbx --profile keepass --hash-out hashes.john

# Legacy automatic detection remains available:
hashvault convert vault.kdbx

# Extract and immediately analyze:
hashvault convert vault.kdbx --profile keepass --analyze

# Extract and crack with a wordlist:
hashvault convert archive.zip --profile zip --crack --wordlist rockyou
```

The gallery exposes 70 curated profiles across archives, documents, password
managers, encrypted disks, private keys, enterprise captures, wallets, and
applications. Each row reports the bundled converter, target John format,
hashcat mode, and whether the required runtime is installed. Python helpers run
through a compatibility bridge so legacy scripts that parse under Python 3 can
still be used without modifying the bundled John files. `--list-formats` remains
an alias for `--gallery`.

### Check a Cached Hash
```bash
hashvault check 5f4dcc3b5aa765d61d8327deb882cf99
```

### Audit the Pattern Catalogue
```bash
hashvault patterns-audit
hashvault patterns-audit --strict          # non-zero exit on any error
hashvault patterns-audit --json            # machine-readable, for CI
```
Checks every pattern for a regex that does not compile, a regex that accepts
impossible input (a 32-character string of `!`), a hashcat example that its own
mode's patterns reject, and groups of patterns that share an identical regex
*and* confidence weight (where ranking is arbitrary). Defects that are
upstream hashcat drift rather than pattern bugs are documented in
`data/patterns/audit_allowlist.json` and reported separately, so a new
regression cannot hide behind them.

### Measure Identification Confidence
```bash
hashvault calibrate
hashvault calibrate --limit 200 --json
hashvault calibrate --out data/patterns/calibrated_weights.json
```
Reports the **Brier score** and **expected calibration error** of the
identifier against corpus ground truth, prints a reliability diagram, and
derives replacement `confidence_weight` values from observed accuracy instead
of hand-tuned constants. Patterns observed fewer than `--min-samples` times are
left alone unless `--force-weights` is given.

### Plan a Cracking Job
```bash
hashvault plan '$6$rounds=5000$salt$hash...' --wordlist rockyou.txt --rules 51
hashvault plan '<hash>' --mask '?l?l?l?l?d?d' --budget 3600
hashvault plan '<hash>' --keyspace 10000000 --rate 2500000 --budget 600
```
Multiplies wordlist size by rule count (or counts a mask keyspace), applies a
measured or reference hash rate, and reports the ETA against your audit budget.
The rate source is always stated: `measured` is evidence about this machine,
`reference` is a labelled order-of-magnitude guess.

### Resolve Ambiguity by Trial Cracking
```bash
hashvault crack 279412f945939ba78ce0758d3fd83daa --resolve-trials
hashvault crack '<hash>' --trial-budget 30 --resolve-trials
```
Formats that share a shape (`md5($pass.$salt)` vs `md5($salt.$pass)`, or a bare
32-hex digest that could be MD5, MD4, NTLM or LM) cannot be separated by regex.
This tries the top candidates with the built-in engine on the quick wordlist
and promotes the one that actually cracks, reporting `empirical_trial` as the
resolution method. Bounded by `--trial-budget` and `strategy.trial_max_candidates`.

### Produce Signed Audit Evidence
```bash
hashvault evidence --generate-key auditor.pem
hashvault evidence --sign-key auditor.pem --out audit-evidence.json
hashvault evidence --verify audit-evidence.json --public-key auditor.pub.pem
```
Builds a document that records **no plaintext** — only a SHA-256 of each hash —
together with the tool version and fingerprints of the pattern catalogue, the
corpus and the record set. The canonical payload is signed with Ed25519, so a
row edited afterwards is detectable. `--verify` checks both the payload digest
and the signature; without `--public-key` it still detects edits.

### Export and Import
```bash
hashvault export-db --format json --output cracked.json
hashvault import-wordlist rockyou.txt --name rockyou
hashvault import-patterns data/patterns/patterns.json
```

## Command Reference

| Command | Purpose |
|---|---|
| `hashvault` / `interactive` | Launch the prompt_toolkit shell |
| `identify` | Identify a hash or wrapped input; `--json` for candidates and ambiguity |
| `analyze` | Beam-search unwrapping, live view, optional cracking, recipe export |
| `crack` | Crack one hash with retries, budgets, adaptive tools, and recipe export |
| `check` | Query the local cracked-hash cache |
| `audit` | Re-verify stored cracked plaintexts against their hashes |
| `doctor` | Offline health/capability checks; `--probe` runs hashcat device discovery |
| `insights` | Aggregate local analysis, cracking, and strategy activity |
| `parameters` | Parse encoded hash parameters and estimate work factor |
| `mutate` | Build bounded context-aware candidates, Arabizi variants, and rules |
| `replay` | Deterministically replay a saved analysis recipe |
| `convert` | Browse the John converter gallery and extract crackable hashes from files |
| `selftest` | Run the 68-case operation/cracking matrix |
| `benchmark-layers` | Validate layered recipe chains and optional plaintext recovery |
| `stats` | Show database, session, attempt, and analysis-log counters |
| `strategies stats` | Show adaptive tool/pattern feedback |
| `strategies reset --yes` | Clear adaptive feedback |
| `sessions` | List isolated cracking sessions; `--purge` deletes their working directories |
| `patterns-audit` | Check the pattern catalogue for broken regexes, mode/example drift and arbitrary ranking ties |
| `calibrate` | Measure identification confidence against corpus truth (Brier score, ECE) and suggest weights |
| `plan` | Estimate cracking time for a wordlist/mask and check it against an audit budget |
| `evidence` | Build or verify a signed, plaintext-free audit evidence report |
| `setup` | Initialize/migrate the database and seed bundled resources |
| `fetch-resources` | Refresh wordlists/rules and rerun setup |
| `import-wordlist` | Register an external wordlist |
| `import-patterns` | Import/update hash pattern definitions |
| `export-db` | Export cracked records as JSON or CSV |

## Configuration

`config/default.yaml` is the default configuration source. Environment
variables use the `HASHVAULT_` prefix with double-underscore nesting:

```bash
HASHVAULT_STRATEGY__RETRY_ALTERNATIVES=false
HASHVAULT_STRATEGY__DEFAULT_BUDGET_SECONDS=60
HASHVAULT_MUTATION__MAX_CANDIDATES=1000
HASHVAULT_LLM__ENABLED=true
HASHVAULT_ENRICHMENT__WORDLIST_PATHS='["data/wordlists/local-names.txt"]'
```

Key configuration areas:

| Section | Controls |
|---|---|
| `paths` | Database, wordlist/rule directories, sessions, quick wordlist, tool binaries |
| `timeouts` | Fast/slow hash cracking timeouts and hashcat backend probe timeout |
| `strategy` | Default tool, trial disambiguation, retries, budget, adaptive ordering, hashcat backend/workload, session artifact retention (`keep_session_artifacts`), cached-plaintext re-verification (`verify_cache_entries`) |
| `mutation` | Candidate limits, history/enrichment seed caps, years, Arabic/Arabizi mode |
| `llm` | Disabled-by-default Ollama endpoint, model, timeout, candidate cap |
| `enrichment` | Opt-in local wordlist sources |
| `output` | Silent-by-default mode, log file, and log level |

LLM and enrichment settings never cause HashVault to upload hashes or
plaintexts. Only configured local endpoints/paths are used.

## Operational Notes

- Hashcat and John are optional; `doctor` reports binary availability, and
  `doctor --probe` reports hashcat device discovery. A successful probe does
  not guarantee every hash mode can compile or run on the detected backend.
- The built-in engine is the dependency-light fallback. Optional `passlib`,
  `bcrypt`, Argon2, and Django packages extend verifier coverage; `doctor`
  reports which are available.
- `audit` skips records whose pattern has no built-in verifier and reports them
  as `unsupported` rather than treating them as mismatches.
- `insights` reads local SQLite tables only and excludes plaintext values from
  all output.

## Pipeline Architecture

```
User Input (hash / encoded text / encrypted file)
       │
  [0] CONVERT (optional) — file → raw hash string
       │
  [1] ANALYZER — bounded beam search across 54 reversible operations
       │   encodings / compression / archives / ciphers / keyed / extractors
       │   → ranked terminal hypotheses, provenance trace, analysis_log DB table
       │   → alternative branches recover inputs the primary hypothesis cannot map
       │
  [2] IDENTIFIER — catalogue + curated-pattern regex + confidence scoring
       │   prefix_hint → single_match → confidence_margin → ambiguous
       │
  [3] CANONICALIZER — splits username, canonicalizes the *unwrapped* payload
       │
  [4] ROUTER — hashcat mode / john format / built-in verifier → adaptive engine order
        │
  [5] EXECUTOR — hashcat / John / built-in (session-isolated, shell=False)
        │   per-attempt records + strategy feedback; remaining budget is enforced
        │   alternative-analysis branches are re-identified and trial-cracked
        │
  [6] REPORTER — Rich table / JSON / CSV, attempts, ambiguity, budget, recipe
       │
  [7] OPERATIONS (offline) — doctor / audit / insights / stats
       │   readiness checks, cracked-record re-verification, aggregate metrics
```

## Documentation

- Usage, CLI flags, and examples are documented in the sections above.
- Analyzer internals live in `hashvault/analysis/`; the bounded search starts at `hashvault/analysis/search.py`.
- Identification scoring and source-context rules are in `hashvault/core/identifier.py`.
- Offline health checks live in `hashvault/core/doctor.py`.
- Cracked-record verification lives in `hashvault/core/integrity.py`.
- Aggregate audit analytics live in `hashvault/core/insights.py`.
- Runtime settings are defined in `config/default.yaml` and `hashvault/config.py`.
- Security and operational limits are covered in [Security](#security).

## Security

HashVault implements strict security measures:

- No `shell=True` in subprocess calls
- Isolated sessions for each cracking operation
- John helpers are resolved only from the configured John installation or `tools/john`; `PATH`/working-directory lookups are refused to prevent binary planting
- Decompression and archive extraction are byte-capped, so a compression bomb cannot exhaust memory
- Session artifacts (potfiles, `out.txt`, `target.hash`) are deleted after each attempt; `hashvault sessions --purge [--older-than-days N] [--dry-run]` clears leftovers from earlier runs, and `strategy.keep_session_artifacts: true` opts back into retention
- `analyze`/`--file` inputs are size-capped (64 MiB, `HASHVAULT_MAX_INPUT_BYTES`)
- Secure history management (no plaintext storage)
- Resource validation and path sanitization
- Local-only enrichment and disabled-by-default Ollama access; non-loopback LLM endpoints are refused unless `llm.allow_remote_endpoint: true` is set explicitly
- `doctor`, `audit`, and `insights` work offline against local files/databases; `doctor --probe` executes only the configured local hashcat binary
- Integrity audits and insights never print stored plaintexts or send data off-host
- Bounded retries, time budgets, mutation counts, and recipe serialization
- Comprehensive exception handling

## Contributing

```powershell
# Publish to GitHub as a PRIVATE repository (creates the repo and pushes)
pwsh -File scripts/publish_private.ps1 -DryRun   # safety audit only
pwsh -File scripts/publish_private.ps1           # create + push
```

The script refuses to run unless `git` and an authenticated `gh` are present,
blocks the push when a database/potfile/session directory or a >95 MB blob is
present, and verifies the repository visibility is `PRIVATE` afterwards.

Contributions are welcome! Please ensure:
- `python -m pytest -q` passes
- `python -m compileall -q hashvault scripts tests` succeeds
- Corpus checks remain current (`build_hash_corpus.py --check`, `build_crypto_corpus.py --check`, `build_layer_corpus.py --check`)
- Tests are included for new features
- Security guidelines are followed
- Documentation is updated
- `ruff check` and `mypy` are run when those optional tools are installed

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- [hashcat](https://hashcat.net/hashcat/) - World's fastest password cracker
- [John the Ripper](https://www.openwall.com/john/) - Password security auditing tool
- [SecLists](https://github.com/danielmiessler/SecLists) - Security testing wordlists
