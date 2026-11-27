# Examples

These files are safe, published test fixtures for demonstrations and regression
checks. They are not live credentials.

## 0xdf corpus demo

`0xdf-demo.txt` contains a small selection of cases from
[0xdf's Hack The Box writeups](https://0xdf.gitlab.io/). The full, verified
manifest lives at `data/corpus/0xdf_cases.json`; provenance and verification
details are documented in [docs/CORPUS.md](../docs/CORPUS.md).

`0xdf-known.json` provides two known plaintexts for a campaign demonstration.

```bash
hashvault campaign plan examples/0xdf-demo.txt
hashvault campaign run examples/0xdf-demo.txt \
  --known-file examples/0xdf-known.json \
  --max-candidates 50000
```

The demo intentionally includes:

- two SHA-256 hashes,
- an Apache `$apr1$` hash that shares a plaintext with one SHA-256 case,
- a sha512crypt hash,
- a bcrypt hash.

Campaigns skip slow KDFs during mutation/wordlist stages unless
`--include-slow` is supplied.

## Adding examples

Use only published, non-sensitive fixtures. Add attribution and a test when a
fixture is meant to guard behavior. Do not commit real customer data, private
engagement material, potfiles, or session artifacts.
