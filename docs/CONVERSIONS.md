# File-to-Hash Conversions

HashVault can turn protected files into hash material that John the Ripper or
hashcat can attack. It does not implement every extractor itself: it uses the
`*2john` helpers that ship with John, keeps a managed copy of them, and falls
back to a small built-in extractor for common archive and document formats.

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

## Auto-selection

`hashvault convert <file>` ranks candidates by:

1. filename and extension hints,
2. magic-byte detection,
3. John profile availability,
4. the built-in extractor.

It tries each available profile and reports every attempt. If no profile works,
the command prints the attempted profiles and the built-in error instead of
claiming the file is unsupported without evidence.

## Output and paths

| Option | Effect |
| --- | --- |
| `--save` | Write `<stem>.john` under `paths.conversions_dir` |
| `--out-dir DIR` | Write `<stem>.john` under `DIR` |
| `--profile KEY` | Use one gallery profile |
| `--paths` | Show store, conversions, checkpoints, and John paths |
| `--sync` | Refresh the managed store from John |
| `--json` | Machine-readable result, including attempts and storage source |

`conversions/` and `checkpoints/` are gitignored because they can contain hash
material or recovered plaintext. Keep them on encrypted storage when working
with client data.

## Troubleshooting

- **No converter found** — run `hashvault convert --paths` and
  `hashvault convert --sync`; confirm the configured John binary exists.
- **Profile reports "unsupported"** — the helper may require Python or Perl.
  Check `hashvault doctor` and the converter's runtime.
- **Wrong file type detected** — pass `--profile` explicitly, or inspect the
  gallery row for the expected extension.
- **Large file** — conversion reads only the first 512 bytes for magic
  detection; it does not load the whole file into memory for type detection.

## Security notes

- Converters are ordinary local programs. Treat a modified helper as untrusted
  code and verify the manifest hashes.
- Hash material is sensitive even when it is not plaintext. Do not commit
  conversion output.
- Only convert files you are authorized to assess.
