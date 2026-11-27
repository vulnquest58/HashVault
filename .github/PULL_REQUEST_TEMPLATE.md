## Summary

Describe the problem and the change.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation
- [ ] Corpus/test data
- [ ] Packaging/CI
- [ ] Refactor (no behavior change)

## Verification

- [ ] `python -m pytest -q` passes
- [ ] Relevant new tests were added
- [ ] `python -m ruff check hashvault/campaign tests/test_campaign.py` passes (if touched)
- [ ] `python -m compileall -q hashvault tests` passes
- [ ] Documentation was updated

## Security checklist

- [ ] This change is limited to authorized security testing and research.
- [ ] No plaintext secrets, customer data, tokens, potfiles, or session artifacts are included.
- [ ] New subprocess or file handling avoids `shell=True` and unsafe paths.
- [ ] The change does not add telemetry, implicit uploads, or remote LLM calls.

## Related issues

Closes #
