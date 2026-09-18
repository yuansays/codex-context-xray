# Contributing

Thanks for helping keep Codex Context X-Ray accurate.

## Ground rules

1. Link behavior changes to current official Codex documentation.
2. Keep the scanner offline and static. Never execute content being inspected.
3. Use only fictional fixtures. Do not commit real home paths, tokens, logs,
   downloads, database files, or captured configuration.
4. Prefer `conditional` or `unobserved` over guessing.
5. Preserve stable JSON fields or document a schema-version change.

## Local checks

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
ruff check .
mypy src
pytest
python -m build
```

Tests that create a synthetic secret must use an unmistakably fake value such
as `fake_test_token_do_not_use`. Tests must assert the value is absent from all
serialized reports.

## Compatibility reports

A useful compatibility issue includes:

- the Codex version;
- operating system and Python version;
- the smallest fictional directory tree that reproduces the result;
- expected and observed source statuses.

Never attach your real `~/.codex` directory.
