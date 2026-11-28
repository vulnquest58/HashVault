# Corpus Provenance

HashVault uses several corpora for identification and cracking regression tests.
This document records where the data came from, how it is verified, and how to
use it safely.

## Bundled corpora

| Corpus | Path | Purpose |
| --- | --- | --- |
| hashcat examples | `data/corpus/hashcat_examples.json` | Broad format coverage |
| 0xdf real-world cases | `data/corpus/0xdf_cases.json` | Published HTB hash/password examples |
| Crypto vectors | `data/corpus/crypto_vectors.json` | Locally derived library vectors |
| CTF writeups | `data/corpus/ctf_writeups.json` | Local lab/CTF artifacts |
| Public CTF challenges | `data/corpus/ctf_public.json` | Published TryHackMe-style cases |
| Layered recipes | `data/corpus/layer_vectors.json` | Deterministic unwrap-chain tests |

## 0xdf cases

The 0xdf corpus is derived from the Hack The Box writeups published at
[0xdf.gitlab.io](https://0xdf.gitlab.io/). The manifest contains 20 cases: 18
with verified plaintexts and 2 identification-only cases where a plaintext was
not established.

Each record includes:

- a stable case id,
- the source URL,
- the username and hash material,
- the hashcat mode and format name,
- the expected plaintext where verified,
- provenance and verification notes.

The corpus is used by `tests/test_corpus.py` and by the demonstration files in
`examples/`. The examples are published test fixtures, not live credentials.

### Verify the corpus

```bash
python -m pytest -q tests/test_corpus.py
hashvault corpus validate
hashvault corpus validate --json
```

`hashvault corpus validate` checks schema versions, stable ids, duplicate ids
(within and across files), provenance/reference fields, multiline or empty
hash material, contradictory `usable_for_*` flags, and declared counts. It
fails on errors; `--strict` also treats warnings as failures. The validator does
not re-crack every case -- `tests/test_corpus.py` and `hashvault evaluate` do
that.

### Benchmark it

```bash
python scripts/benchmark_corpus.py --source 0xdf
python scripts/benchmark_corpus.py --source 0xdf --crack \
  --json reports/0xdf-corpus.json
```

### Use it in a campaign demo

```bash
hashvault campaign plan examples/0xdf-demo.txt
hashvault campaign run examples/0xdf-demo.txt \
  --known-file examples/0xdf-known.json \
  --max-candidates 50000
```

The demo intentionally includes exact-reuse behavior: one known plaintext is
shared by an SHA-256 case and an Apache `$apr1$` case.

## Verification policy

- Plaintexts must verify against their published hash before they are accepted
  into a corpus.
- Published answers that cannot be reproduced are dropped rather than guessed.
- Truncated or binary-only hashcat examples are skipped unless
  `--include-unusable` is passed.
- Corpus changes require a test update and a changelog entry.
- Do not add customer data, engagement material, potfiles, or session artifacts.

## Attribution

Corpus data remains subject to the terms of its original publication. The 0xdf
cases are attributed to 0xdf's writeups; hashcat examples remain subject to the
hashcat project's licensing and documentation. HashVault's own code and
documentation are MIT licensed.
