# Managed converter store

HashVault uses John the Ripper's `*2john` helper programs to turn protected
files into hash lines that hashcat, John, or the built-in engine can verify.

This directory is the **managed store**. It keeps the helpers in one stable,
category-based tree so conversion does not depend on the current working
directory or on a particular John installation layout.

## Layout

```text
tools/converters/
  archive/              zip2john, rar2john, 7z2john, ...
  documents/            office2john, pdf2john, ...
  password-managers/    keepass2john, bitwarden2john, ...
  disk-encryption/      luks2john, veracrypt2john, ...
  private-keys/         ssh2john, pem2john, ...
  windows/              DPAPImk2john, ...
  enterprise/           aix2john, rab2john-style enterprise helpers, ...
  databases/            mongodb2john, ...
  network/              radius2john, ...
  wireless/             wpapcap2john, ...
  wallets/              bitcoin2john, ethereum2john, ...
  applications/         signal2john, telegram2john, ...
  lib/                  shared Perl modules copied from John
  manifest.json         generated provenance and SHA-256 manifest
```

## Populate the store

John the Ripper must be installed and `paths.john_bin` must point at its
binary. From the repository root:

```bash
hashvault convert --sync
```

This copies every helper used by the conversion gallery into the matching
category, copies shared Perl modules into `lib/`, and writes `manifest.json`.
Existing files are kept; use `--force` to refresh them:

```bash
hashvault convert --sync --force
```

The store is intentionally local. Helper binaries and scripts are not
committed to the repository and are ignored by git. The directory layout,
manifest format, and this document are tracked.

## Verify the store

```bash
hashvault convert --paths
hashvault doctor
hashvault convert --gallery
```

`--paths` shows the store, output, and checkpoint directories. `doctor`
reports how many profiles are stored and which are missing. `--gallery`
shows the converter path and whether it came from the store or directly from
John.

## Output and checkpoints

Converted hash lines are written where you ask:

```bash
hashvault convert archive.zip --hash-out conversions/archive.john
hashvault convert archive.zip --save
```

`--save` writes to the configured `paths.conversions_dir` (default
`conversions/`). Campaign checkpoints are written to
`paths.checkpoints_dir` (default `checkpoints/`). Both directories are
gitignored because they can contain sensitive material.
