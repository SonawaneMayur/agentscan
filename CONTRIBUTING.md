# Contributing to agentscan

Thanks for helping. The short version:

1. **Open or pick an issue** describing the change.
2. **Branch from `dev`:** `<type>/<issue>_<short-description>`, for example
   `feature/5_sarif-output` or `bug/15_placeholder-host-crash`.
3. **Set up and enable the secret-check hook:**
   ```bash
   uv sync
   git config core.hooksPath .githooks
   ```
4. **Make the change with tests.** Every bug fix adds a regression test.
5. **Open a pull request into `dev`** and fill in the template. CI must pass.

Maintainers then promote `dev` → `test` (TestPyPI release candidate) → `main` (PyPI release).

| Guide | Covers |
|---|---|
| [docs/branching.md](docs/branching.md) | Branches, naming, merge types, hotfixes |
| [docs/testing.md](docs/testing.md) | What CI runs and the testing rules |
| [docs/release-process.md](docs/release-process.md) | TestPyPI candidates and PyPI releases |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities privately |

Never commit credentials, `.env` files, databases or anything under `research/*/data/`. The
pre-commit hook and CI both block them.
