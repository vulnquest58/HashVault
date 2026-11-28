# File-to-Hash Conversions

HashVault can turn protected files into hash material that John the Ripper or
hashcat can attack. It does not implement every extractor itself: it uses the
`*2john` helpers that ship with John, keeps a managed copy of them, and falls
back to a small built-in extractor for common archive and document formats.

HashVault also includes the official **auto2john** engine as a vendored
component. The standalone project at
[github.com/vulnquest58/auto2john](https://github.com/vulnquest58/auto2john)
owns a focused detection and tool-resolution engine with 57 profiles; HashVault
keeps its larger 70-profile conversion gallery and uses auto2john as a
high-confidence detection and extraction path.

This is the "one workflow" entry point:

```text
protected file -> convert -> hash material -> identify/crack -> recover -> evidence
```

## Quick start

```bash
# Inspect the conversion gallery
hashvault convert --gallery

# Extract hashes from a file (auto-selects a profile)
hashvault convert protected.zip

# Copy John helpers into the managed store first
hashvault convert --sync

# Save extracted material under the configured conversions directory
hashvault convert protected.7z --save

# Choose a profile explicitly
hashvault convert protected.rar --profile rar

# Run the official auto2john engine with HashVault paths
hashvault auto2john protected.zip
hashvault auto2john protected.zip --detect-only
hashvault auto2john --list-tools
```

## Managed converter store

The store lives at `tools/converters` by default and is configured by
`paths.converters_dir`. It is a local cache, not a vendored copy of John:

- `tools/converters/<category>/` contains helper programs (`zip2john.py`,
  `rar2john.exe`, and so on).
- `tools/converters/lib/` contains shared Perl modules such as `jtrconf.pm`.
- `tools/converters/manifest.json` records source paths, SHA-256 hashes,
  runtimes, and missing profiles.

The store is intentionally gitignored for generated helpers. The directory
layout, README, and manifest format are tracked so a fresh checkout explains
where files belong. `hashvault convert --sync` copies helpers from the
configured John installation and never downloads anything.

Resolution order for a converter is:

1. the managed store,
2. the John `run` directory.

Nothing is resolved from `PATH` or the current working directory, which avoids
picking up an unexpected helper from an untrusted project.

The `hashvault auto2john` command additionally accepts repeatable
`--tool-dir` paths. It searches the configured store first, then each explicit
directory, then the configured John binary and its run directory.

## Official auto2john engine

`hashvault auto2john` runs the vendored upstream engine directly:

```bash
# Detect without running a helper
hashvault auto2john protected.zip --detect-only --json

# Convert and write to the configured conversions directory
hashvault auto2john protected.7z

# Write somewhere else, or overwrite an existing output
hashvault auto2john protected.7z --out-dir extracted
hashvault auto2john protected.7z --force

# Inspect the profile list and managed helper availability
hashvault auto2john --list
hashvault auto2john --list-tools --json

# Pass an argument that starts with a dash
hashvault auto2john protected.zip --tool-arg=--extra
```

The command uses `paths.john_bin` and `paths.converters_dir` from the HashVault
configuration, and defaults its output directory to `paths.conversions_dir`.
Detection prefers a specific built-in magic signature over a generic container,
then filename hints, then extensions, then an optional `python-magic` MIME
hint. For example, an OOXML document renamed to `.zip` is detected as `office`,
not as a generic ZIP archive.

The bridge in `hashvault/ingestors/auto2john_bridge.py` maps upstream profile
keys to HashVault keys (`applenotes` to `notes`, `androidbackup` to
`android-backup`) and feeds the detection into `hashvault convert`. This gives
`convert` a high-confidence first candidate and lets it try an auto2john
profile even when the gallery has no filename or extension match.

`hashvault auto2john` and `hashvault convert` are complementary. Use
`auto2john` when you want the upstream engine's focused behavior, JSON output,
and `--detect-only` inspection. Use `convert` when you want the larger gallery,
built-in fallback, cracking handoff, or managed-store synchronization.

## Auto-selection

`hashvault convert <file>` builds candidates from filename and extension hints,
then ranks them by:

1. the auto2john detection hint,
2. HashVault's magic-byte detection,
3. remaining filename and extension order,
4. John profile availability,
5. the built-in extractor.

It tries each available profile and reports every attempt. If no profile works,
the command prints the attempted profiles and the built-in error instead of
claiming the file is unsupported without evidence. If auto2john detects a
profile that the gallery did not match, that profile is added to the attempt
list rather than replacing the gallery.

## Output and paths

`hashvault convert` options:

| Option | Effect |
| --- | --- |
| `--save` | Write `<stem>.john` under `paths.conversions_dir` |
| `--out-dir DIR` | Write `<stem>.john` under `DIR` |
| `--profile KEY` | Use one gallery profile |
| `--paths` | Show store, conversions, checkpoints, and John paths |
| `--sync` | Refresh the managed store from John |
| `--json` | Machine-readable result, including attempts and storage source |

`hashvault auto2john` options:

| Option | Effect |
| --- | --- |
| `--out FILE` | Write exactly to `FILE` |
| `--out-dir DIR` | Write `<stem>.hash` under `DIR`; defaults to `paths.conversions_dir` |
| `--profile KEY` | Force an auto2john profile |
| `--tool-dir DIR` | Add a converter directory (repeatable) |
| `--john-bin PATH` | Override `paths.john_bin` |
| `--detect-only` | Detect and print the profile without running a helper |
| `--dry-run` | Show the resolved command and output path |
| `--force` | Replace an existing output file |
| `--json` | Machine-readable detection, command, output, and hash count |
| `--list` / `--list-tools` | List profiles or resolved helper availability |

`conversions/` and `checkpoints/` are gitignored because they can contain hash
material or recovered plaintext. Keep them on encrypted storage when working
with client data. auto2john writes atomically with mode `0600` on POSIX
systems, refuses symlink outputs, and refuses to overwrite unless `--force` is
explicit.

## Troubleshooting

- **No converter found** - run `hashvault convert --paths` and
  `hashvault convert --sync`; confirm the configured John binary exists.
- **auto2john reports a missing tool** - run `hashvault auto2john --list-tools`
  and check `--tool-dir` or `paths.converters_dir`. The upstream engine also
  searches the John run directory and common local install paths.
- **Profile reports "unsupported"** - the helper may require Python or Perl.
  Check `hashvault doctor` and the converter's runtime.
- **Wrong file type detected** - pass `--profile` explicitly, or inspect the
  gallery row for the expected extension. Use
  `hashvault auto2john FILE --detect-only` to see the auto2john decision.
- **Large file** - conversion reads only the first 512 bytes for magic
  detection; it does not load the whole file into memory for type detection.

## Security notes

- Converters are ordinary local programs. Treat a modified helper as untrusted
  code and verify the manifest hashes.
- The vendored auto2john engine is synchronized from the standalone project.
  Review upstream changes before updating the vendored copy.
- Hash material is sensitive even when it is not plaintext. Do not commit
  conversion output.
- Only convert files you are authorized to assess.
