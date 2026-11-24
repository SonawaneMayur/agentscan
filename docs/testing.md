# Testing

Every pull request and every push to `dev`, `test` and `main` runs the **full** suite, not only
the tests near the change, so nothing that already worked can silently break.

## What runs in CI

| Check | Command |
|---|---|
| Secret check over every file version in every commit | `uv run python scripts/check_secrets.py --history` |
| Lint and formatting | `uv run ruff check` and `uv run ruff format --check` |
| Scanner, CLI and branch-rule tests | `uv run pytest` |
| MCP config census pipeline tests | `uv run --group demo pytest research/mcp-config-census` |
| Branch name and promotion path (pull requests) | `python3 scripts/check_branch_name.py <head> <base>` |
| Release candidate installed from TestPyPI (`test` branch) | see [release-process.md](release-process.md) |

The scanner tests run on Python 3.10, 3.11, 3.12 and 3.13.

## Rules

- **Every bug fix adds a regression test** that fails before the fix and passes after it. Name
  it after the issue, for example `test_bug_15_placeholder_host_does_not_crash`, so the history
  of each failure stays visible.
- **New features come with tests** for both the problem they detect and the safe counterpart they
  must not flag.
- **Never weaken an existing assertion to make a change pass.** If behavior is meant to change,
  say so in the pull request and update the test deliberately.
- **Fake secrets in tests are built at runtime** (for example `"ghp_" + "a" * 36`), so the
  repository never contains secret-shaped text and the secret check stays meaningful.

## Running locally

```bash
uv sync
uv run pytest
uv run --group demo pytest research/mcp-config-census
uv run python scripts/check_secrets.py
```

Golden-output regression tests, a coverage gate and macOS and Windows runners are tracked in
issue #2.
