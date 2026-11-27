# Contributing to HashVault

Thanks for helping improve HashVault. This project is for authorized security
testing and research; contributions must respect that boundary.

## Ways to contribute

- Report a reproducible bug.
- Improve documentation, examples, or corpus provenance.
- Add a verifier test for a hash format.
- Add a well-scoped campaign or analysis test case.
- Propose a feature with a clear use case and threat model.
- Triage an existing issue or improve the roadmap.

Please open an issue before starting a large feature so the design can be
discussed first.

## Development setup

Requirements: Python 3.11 or newer and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/vulnquest58/HashVault.git
cd HashVault
uv venv
uv pip install -e ".[dev,builtin]"
hashvault setup
hashvault doctor
```

On Windows, activate the environment with `.venv\Scripts\activate`; on POSIX
systems use `source .venv/bin/activate`.

## Tests

```bash
python -m pytest -q
python -m pytest -q tests/test_campaign.py
python -m pytest -q tests/test_corpus.py
```

The baseline is 436 passing tests. New behavior needs a test that fails before
the change and passes after it. Use published, non-sensitive fixtures only.

## Style

- Python 3.11+ syntax.
- Keep new code formatted and lint-clean:

```bash
python -m ruff check hashvault/campaign tests/test_campaign.py
python -m ruff format hashvault/campaign tests/test_campaign.py
```

- Avoid new dependencies unless they are necessary and justified in the PR.
- Use `shell=False` for subprocesses and never interpolate untrusted input into
  shell strings.
- Do not log, print, or commit plaintext secrets, tokens, potfiles, or session
  artifacts.
- Prefer existing helpers and patterns over new abstractions.

The legacy codebase has a larger `ruff`/`mypy` backlog. Do not mix unrelated
mass-formatting with a focused change; the campaign package is the current
lint-clean reference.

## Corpus changes

- Use published sources and record attribution.
- Verify every accepted plaintext against its hash.
- Update `docs/CORPUS.md` when adding a corpus or changing provenance.
- Do not add customer data, live credentials, or engagement material.
- Keep 0xdf-derived fixtures in `examples/` and the manifest in
  `data/corpus/0xdf_cases.json`.

## Commit and pull request process

1. Fork the repository and create a focused branch.
2. Make the change and add tests/docs.
3. Run the relevant test and lint commands.
4. Open a pull request using the template.
5. Describe the motivation, behavior change, security impact, and verification.
6. Link the issue when one exists.

Write commit messages in the imperative mood, for example:

```text
Add campaign certificate verification tests
Fix SQLite sidecar ignore rules
Document 0xdf corpus provenance
```

Do not include generated databases, reports, or secrets. Do not force-push a
shared branch. Maintainers may squash or rebase for a clean history.

## Security issues

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md)
and use GitHub's private vulnerability reporting when available.

## Code of conduct

Participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Be
respectful, assume good faith, and keep discussions technical.
