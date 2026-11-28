# HashVault CLI Reference

This document is the complete command reference for HashVault v2.3.0.

## Legal and Ethical Use

HashVault is for authorized security testing, credential audits, CTF
environments, and research only. Use it only on systems and data you own or
have explicit written permission to assess. Unauthorized use may violate law
and professional ethics.

The tool is distributed under the MIT License. Users are solely responsible for
their use of it.

## Installation

```bash
git clone https://github.com/vulnquest58/HashVault.git
cd HashVault

uv venv
uv pip install -e ".[dev,builtin]"

hashvault setup
hashvault doctor
```

Optional external engines:

- [hashcat](https://hashcat.net/hashcat/)
- [John the Ripper](https://www.openwall.com/john/)

`hashvault doctor` reports which engines, optional verifiers, wordlists, rules,
and corpora are available.

## Interactive Shell

```bash
hashvault
hashvault interactive
```

The prompt supports tab completion, history suggestions, and a status toolbar.
`F1` opens help; `F2` toggles auto-crack; `F3` refreshes completions; `F4`
shows strategy stats; `F5` inserts `parameters`; `F6` inserts `mutate`.
`Ctrl+C` cancels the current line and `Ctrl+D` exits.

The wordmark is available from the CLI:

```bash
hashvault banner
hashvault banner --plain
hashvault banner --json
```

## Command Reference

| Command | Purpose |
| --- | --- |
| `hashvault` / `interactive` | Launch the interactive shell |
| `identify` | Identify a hash or wrapped input; `--json` for candidates and ambiguity |
| `analyze` | Beam-search unwrapping, live view, optional cracking, recipe export |
| `crack` | Crack one hash or a file with retries, budgets, adaptive tools, and recipe export |
| `check` | Query the local cracked-hash cache |
| `audit` | Re-verify stored cracked plaintexts against their hashes |
| `doctor` | Offline health/capability checks; `--probe` runs hashcat device discovery; `--fix` creates missing data directories |
| `insights` | Aggregate local analysis, cracking, and strategy activity |
| `parameters` | Parse encoded hash parameters and estimate work factor |
| `mutate` | Build bounded context-aware candidates, Arabizi variants, and rules |
| `replay` | Deterministically replay a saved analysis recipe |
| `convert` | Browse the John converter gallery and extract crackable hashes from files; `--sync`, `--paths`, `--save` |
| `auto2john` | Run the official auto2john engine with HashVault paths; `--detect-only`, `--list`, `--list-tools` |
| `campaign plan` | Show the staged recovery plan for a corpus |
| `campaign run` | Run a corpus recovery campaign; `--potfile`, `--checkpoint`, `--resume`, `--shard`, `--progress` |
| `campaign keygen` | Generate an Ed25519 certificate signing keypair |
| `campaign verify` | Verify a recovery certificate payload and signature; `--trust-store` |
| `selftest` | Run the operation/cracking matrix |
| `benchmark-layers` | Validate layered recipe chains and optional plaintext recovery |
| `stats` | Show database, session, attempt, and analysis-log counters |
| `strategies stats` | Show adaptive tool/pattern feedback |
| `strategies reset --yes` | Clear adaptive feedback |
| `corpus validate` | Validate corpus schema, provenance, counts, and duplicate ids |
| `sessions` | List isolated cracking sessions; `--purge` deletes their working directories |
| `patterns-audit` | Check the pattern catalogue for broken regexes, mode/example drift, and ranking ties |
| `calibrate` | Measure identification confidence against corpus truth and suggest weights |
| `plan` | Estimate cracking time for a wordlist/mask and check it against an audit budget |
| `evidence` | Build or verify a signed, plaintext-free audit evidence report |
| `setup` | Initialize/migrate the database and seed bundled resources |
| `fetch-resources` | Refresh wordlists/rules and rerun setup |
| `import-wordlist` | Register an external wordlist |
| `import-patterns` | Import or update hash pattern definitions |
| `export-db` | Export cracked records as JSON or CSV |

## Identify

```bash
hashvault identify 5f4dcc3b5aa765d61d8327deb882cf99
hashvault identify '$2y$10$...' --json
hashvault identify --file hashes.txt --format secretsdump
```

Bare 32-hex digests are ambiguous by nature. Use `--hint windows` or
`--pattern NTLM` when the source is known; otherwise HashVault preserves the
ambiguity and reports ranked candidates.

## Analyze

```bash
hashvault analyze 'NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk='
hashvault analyze '...' --live
hashvault analyze '...' --auto --budget-seconds 60
hashvault analyze '...' --recipe-out recipes/case.json
```

The analyzer performs a bounded beam search over reversible operations,
including encodings, compression, archives, classical ciphers, keyed
transforms, and extractors. It reports ranked hypotheses and a provenance
trace. `--live` shows search progress in real time.

## Crack

```bash
hashvault crack 5f4dcc3b5aa765d61d8327deb882cf99
hashvault crack '$S$C337...' --pattern Drupal7 --tool builtin
hashvault crack 5f4dcc3b5aa765d61d8327deb882cf99 \
  --attack-mode mask --mask '?l?l?l?l?d?d'
hashvault crack NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk= \
  --auto --budget-seconds 60 --max-alternative-attempts 3
hashvault crack NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk= \
  --auto --recipe-out recipes/case.json
hashvault replay recipes/case.json
```

Batch mode:

```bash
hashvault crack --file hashes.txt --format secretsdump
```

Engine selection, budgets, retries, and adaptive ordering are controlled by
the `strategy` configuration section.

## Campaign Recovery

```bash
hashvault campaign plan examples/0xdf-demo.txt

hashvault campaign run examples/0xdf-demo.txt \
  --known-file examples/0xdf-known.json \
  --max-candidates 50000 \
  --json > report.json

hashvault campaign run examples/0xdf-demo.txt \
  --known-file examples/0xdf-known.json \
  --wordlist data/wordlists/quick_1000.txt

hashvault campaign keygen campaign.key campaign.pub
hashvault campaign run examples/0xdf-demo.txt \
  --known-file examples/0xdf-known.json \
  --certificate campaign.json --sign-key campaign.key
hashvault campaign verify campaign.json --public-key campaign.pub
```

Options:

| Option | Meaning |
| --- | --- |
| `--known key=value` | Seed one known plaintext; repeatable |
| `--known-file FILE` | JSON object or list of known plaintexts |
| `--wordlist FILE` | Add a wordlist pass |
| `--max-candidates N` | Cap synthetic candidates |
| `--max-patterns N` | Candidate patterns per target |
| `--include-slow` | Include slow KDFs in mutation/wordlist stages |
| `--redact` | Hide recovered plaintext in terminal and JSON output |
| `--certificate FILE` | Write a plaintext-free recovery certificate |
| `--sign-key FILE` | Sign the certificate with an Ed25519 private key |
| `--json` | Emit machine-readable JSON |

Certificates contain target hashes, pattern decisions, methods, plaintext
SHA-256 commitments, and coverage/uncertainty notes. They never contain
recovered plaintext.

## Mutation

```bash
hashvault mutate context.yaml --limit 500 \
  --wordlist-out audit-wordlist.txt --rules-out audit.rule
hashvault mutate --term ahmed --term acme --year 2026
hashvault mutate --history --enrich local-names.txt --language both
hashvault mutate context.json --llm
```

Context files accept JSON or YAML fields such as `username`, `email`,
`display_name`, `organization`, `project`, `domain`, `dates`, `locale`, and
`keywords`. Output is deterministic and bounded. Local enrichment is opt-in;
the Ollama bridge is disabled by default and never sends data off-host unless
explicitly configured.

## Parameters

```bash
hashvault parameters '$2b$12$...'
hashvault parameters hashes.txt --file --json
```

Reports salts, iteration/cost parameters, work factor, cost class, and whether
an audit should cap runtime. It never predicts or invents unknown parameters.

## Convert

```bash
hashvault convert --gallery
hashvault convert --list-formats
hashvault convert archive.zip
hashvault convert archive.zip --profile zip2john
hashvault convert archive.zip --analyze
hashvault convert archive.zip --crack --wordlist rockyou.txt
hashvault convert archive.zip --hash-out extracted.hash --json
```

The converter gallery includes curated John profiles for archives, documents,
password managers, encrypted disks, private keys, enterprise captures,
wallets, and applications. Runtime availability is checked before use.

## Auto2john

```bash
hashvault auto2john --list
hashvault auto2john --list-tools --json
hashvault auto2john protected.zip --detect-only
hashvault auto2john protected.zip
hashvault auto2john protected.zip --out-dir extracted --json
hashvault auto2john protected.zip --profile zip --force
hashvault auto2john protected.zip --tool-arg=--extra
```

`auto2john` is the official vendored engine from
[github.com/vulnquest58/auto2john](https://github.com/vulnquest58/auto2john).
It uses `paths.john_bin` and `paths.converters_dir`, defaults output to
`paths.conversions_dir`, and writes `<stem>.hash`. Detection prefers specific
magic signatures over generic containers, then filename hints, extensions, and
an optional `python-magic` hint. Use `--detect-only` to inspect the decision
without running a helper.

The command accepts repeatable `--tool-dir` values and passes
`--john-bin`, `--profile`, `--out`, `--out-dir`, `--force`, `--dry-run`,
`--json`, `--no-libmagic`, and `--timeout` through to the engine. For values
that start with a dash, use the equals form: `--tool-arg=--flag`.

## Operations

```bash
hashvault doctor
hashvault doctor --probe
hashvault doctor --json
hashvault audit
hashvault audit --json
hashvault insights
hashvault insights --json
hashvault patterns-audit
hashvault calibrate
hashvault plan 5f4dcc3b5aa765d61d8327deb882cf99 \
  --wordlist rockyou.txt --rate 1000000 --budget 28800
hashvault stats
hashvault strategies stats
hashvault sessions
hashvault sessions --purge --older-than-days 7 --dry-run
```

`doctor` works offline. `--probe` runs only the configured local hashcat binary.
`audit` re-verifies stored plaintexts without exposing them in reports.
`insights` reads local SQLite tables only.

## Conversions

```bash
hashvault convert --gallery
hashvault convert --sync
hashvault convert protected.zip
hashvault convert protected.7z --save
hashvault convert --paths
hashvault auto2john protected.zip --detect-only
hashvault auto2john protected.zip --json
```

The managed store lives under `paths.converters_dir` (default
`tools/converters`). `--sync` copies John helper programs and shared modules
from the configured John installation; nothing is downloaded. `--save` writes
to `paths.conversions_dir`, and `--out-dir` writes elsewhere. The
`auto2john` command is the official standalone engine vendored into HashVault
and defaults to the same conversions directory. See
[docs/CONVERSIONS.md](CONVERSIONS.md).

## Campaign Recovery

```bash
hashvault campaign plan corpus.txt --shard 1/4
hashvault campaign run corpus.txt --known-file known.json
hashvault campaign run corpus.txt --potfile hashcat.potfile
hashvault campaign run corpus.txt --checkpoint checkpoints/run.json
hashvault campaign run corpus.txt --resume checkpoints/run.json --progress
hashvault campaign run corpus.txt --certificate campaign.json --sign-key key.pem
hashvault campaign verify campaign.json --trust-store trust.json
```

Checkpoints contain verified recoveries and are re-verified on resume. They may
contain plaintext, so keep them under the gitignored `checkpoints/` directory
or encrypted storage. `--shard INDEX/TOTAL` assigns records deterministically
for parallel workers. `--potfile` imports hashcat/John `hash:plaintext` lines,
including `$HEX[...]` plaintexts, and records the source in recovery evidence.

## Corpus Validation

```bash
hashvault corpus validate
hashvault corpus validate --json
hashvault corpus validate --strict
```

Validation checks schema, stable and duplicate ids, provenance, multiline or
empty hash material, contradictory usability flags, and declared counts.

## Evidence

```bash
hashvault evidence --generate-key auditor.pem
hashvault evidence --sign-key auditor.pem --out audit-evidence.json
hashvault evidence --verify audit-evidence.json --public-key auditor.pub.pem
hashvault evidence --verify audit-evidence.json --trust-store trust.json
```

Evidence documents record no plaintext, only SHA-256 commitments, together with
the tool version and fingerprints of the pattern catalogue, corpus, and record
set. The canonical payload is signed with Ed25519. `--verify` checks both the
payload digest and the signature.

## Data Management

```bash
hashvault setup
hashvault fetch-resources
hashvault import-wordlist rockyou.txt --name rockyou
hashvault import-patterns data/patterns/patterns.json
hashvault export-db --format json --output cracked.json
hashvault check 5f4dcc3b5aa765d61d8327deb882cf99
```

## Configuration

`config/default.yaml` is the default configuration source. Environment variables
use the `HASHVAULT_` prefix with double-underscore nesting:

```bash
HASHVAULT_STRATEGY__RETRY_ALTERNATIVES=false
HASHVAULT_STRATEGY__DEFAULT_BUDGET_SECONDS=60
HASHVAULT_MUTATION__MAX_CANDIDATES=1000
HASHVAULT_LLM__ENABLED=true
HASHVAULT_ENRICHMENT__WORDLIST_PATHS='["data/wordlists/local-names.txt"]'
```

| Section | Controls |
| --- | --- |
| `paths` | Database, wordlist/rule directories, sessions, quick wordlist, converter store, conversions, checkpoints, tool binaries |
| `timeouts` | Fast/slow hash cracking timeouts and hashcat backend probe timeout |
| `strategy` | Default tool, trial disambiguation, retries, budget, adaptive ordering, hashcat backend/workload, session artifact retention, cache verification |
| `mutation` | Candidate limits, history/enrichment seed caps, years, Arabic/Arabizi mode |
| `llm` | Disabled-by-default Ollama endpoint, model, timeout, candidate cap |
| `enrichment` | Opt-in local wordlist sources |
| `output` | Silent-by-default mode, log file, and log level |

LLM and enrichment settings never cause HashVault to upload hashes or
plaintexts. Only configured local endpoints and paths are used.

## Operational Notes

- Hashcat and John are optional. `doctor` reports binary availability, and
  `doctor --probe` reports hashcat device discovery. A successful probe does
  not guarantee every mode can compile on the detected backend.
- The built-in engine is the dependency-light fallback. Optional `passlib`,
  `bcrypt`, Argon2, and Django packages extend verifier coverage.
- `audit` reports records without a built-in verifier as `unsupported`, not as
  mismatches.
- `insights` excludes plaintext values from all output.
- Existing repositories may use CRLF line endings; new files should use LF.

## Exit Codes

HashVault uses the Typer/Click conventions: `0` for success, `1` for a handled
runtime failure, and `2` for invalid command usage. Scripts should check both
the exit code and the JSON output when automation is involved.
