## What and why

<!-- What does this change, and which issue does it address? -->

Refs #

## Type

- [ ] feature
- [ ] bug fix
- [ ] docs
- [ ] chore / CI
- [ ] refactor
- [ ] tests
- [ ] promotion (dev → test, or test → main)

## Checklist

- [ ] Branch follows `<type>/<issue>_<short-description>` and targets `dev` (promotions: `dev` → `test` → `main`)
- [ ] Tests added or updated; a bug fix includes a regression test named after its issue
- [ ] `uv run pytest` and `uv run ruff check` pass locally
- [ ] `CHANGELOG.md` updated under `Unreleased` (for user-facing changes)
- [ ] No credentials, personal paths or research `data/` in the diff (the secret check passes)
- [ ] Docs updated if behavior or workflow changed

## How it was tested

<!-- Commands run, and what you checked by hand. -->
