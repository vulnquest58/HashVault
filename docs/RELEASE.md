# Release Process

HashVault uses semantic versioning. The current release line is `2.3.x`.

## Version locations

Update all of these together:

- `pyproject.toml` (`project.version`)
- `hashvault/__init__.py` (`__version__`)
- `README.md` version badge
- `CHANGELOG.md`
- `CITATION.cff`
- the Git tag and GitHub release title

## Pre-release checklist

Run from a clean checkout on the Debian build host:

```bash
git status --short
uv venv
uv pip install -e ".[dev,builtin]"
python -m pytest -q --cov=hashvault --cov-fail-under=70
python -m ruff check hashvault/campaign hashvault/core/evidence.py \
  hashvault/core/evidence_schema.py hashvault/core/corpus_validator.py \
  tests/test_campaign.py tests/test_evidence_schema.py \
  tests/test_corpus_validator.py
python -m compileall -q hashvault tests
```

Expected baseline for v2.3.0: `473 passed`.

Then verify the corpus and campaign smoke path:

```bash
python -m pytest -q tests/test_corpus.py tests/test_campaign.py
hashvault setup
hashvault doctor --json
hashvault campaign plan examples/0xdf-demo.txt
hashvault campaign run examples/0xdf-demo.txt \
  --known-file examples/0xdf-known.json --json
```

Check that no generated artifacts are staged:

```bash
git status --short
```

The release must not include `db/`, `sessions/`, potfiles, `.venv/`, caches,
or plaintext reports.

## Build artifacts

```bash
rm -rf dist/
uv build
python -m zipfile -l dist/hashvault-2.3.0-py3-none-any.whl | head
```

The source distribution is the canonical GitHub release artifact because it
contains the bundled `data/` and `docs/` trees. The wheel also bundles the
runtime `data/` and `config/` trees; smoke-test it from a clean virtual
environment and an empty working directory so installed-path regressions are
caught. Run `hashvault setup` there, then confirm `hashvault doctor --json`
reports `"ok": true`. Verify the sdist contains those paths before uploading:

```bash
tar -tf dist/hashvault-2.3.0.tar.gz | grep -E 'data/|docs/|examples/' | head
```

## Tag and publish

```bash
git tag -a v2.3.0 -m "HashVault v2.3.0"
git push origin main
git push origin v2.3.0
```

Create the GitHub release from the tag with:

- title: `HashVault v2.3.0`
- summary from `CHANGELOG.md`
- assets: source distribution and wheel
- notes: breaking changes, campaign engine, corpus provenance, test count,
  and upgrade guidance

If `git push` is unavailable, use the GitHub API with a scoped token and the
same tag/commit. Never commit the token or place it in shell history.

## Post-release verification

```bash
curl -sS https://api.github.com/repos/vulnquest58/HashVault \
  -H "Accept: application/vnd.github+json" | grep -E 'private|visibility|default_branch'
curl -sS https://api.github.com/repos/vulnquest58/HashVault/releases/latest \
  -H "Accept: application/vnd.github+json" | grep -E 'tag_name|name|published_at'
```

Confirm:

- repository visibility is public,
- `main` contains the release commit,
- the release tag points at that commit,
- CI is green,
- the release notes and assets are present.

## Rollback

If a release is defective:

1. Mark the GitHub release as a draft or delete it.
2. Delete the tag locally and remotely.
3. Publish a corrective patch release; do not rewrite `main` history.
4. Document the issue in `CHANGELOG.md` and `SECURITY.md` if it has a security
   impact.

## PyPI

PyPI publication is optional and should only happen after the wheel is verified
to include runtime data. The source distribution is the supported release
artifact for the GitHub-first distribution model.
