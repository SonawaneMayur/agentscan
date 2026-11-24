# Branching and promotion

agentscan uses three long-lived environment branches. Code only moves in one direction:

```
feature/… bug/… chore/… docs/… refactor/… test/…  →  dev  →  test  →  main
```

| Branch | Role | What happens on push |
|---|---|---|
| `dev` | Integration. Default branch; every work branch starts here and merges back here. | CI |
| `test` | Release candidate. Only receives `dev`. | CI, then a release candidate (`X.Y.ZrcN`) is published to **TestPyPI** and installed from there |
| `main` | Production. Only receives `test`. Release tags live here. | CI; a `vX.Y.Z` tag on `main` publishes to **PyPI** |

All three are protected by the `protect-environments` ruleset: they can't be deleted or force-pushed.

## Work branches

Every change starts from a GitHub issue and a branch created from the latest `dev`:

```
<type>/<issue>_<short-description>
```

| Type | Use for | Example |
|---|---|---|
| `feature/` | New capability | `feature/5_sarif-output` |
| `bug/` | Defect fix | `bug/15_placeholder-host-crash` |
| `chore/` | Tooling, CI, dependencies | `chore/3_actions-node24` |
| `docs/` | Documentation only | `docs/4_census-report` |
| `refactor/` | Restructuring without behavior change | `refactor/20_split-rules` |
| `test/` | Tests only | `test/2_regression-suite` |

- `<issue>` is the GitHub issue number.
- `<short-description>` is lowercase words joined by dashes.
- The `Branch rules` workflow ([scripts/check_branch_name.py](../scripts/check_branch_name.py)) rejects pull requests that break these rules, including promotions that skip a stage.

```bash
git checkout dev
git pull
git checkout -b feature/5_sarif-output
```

## Pull requests and merges

| Pull request | Merge with | After merging |
|---|---|---|
| work branch → `dev` | **Squash and merge** (one commit per issue) | Delete the work branch |
| `dev` → `test` | **Create a merge commit** | Keep `dev`. Never delete it. |
| `test` → `main` | **Create a merge commit** | Keep `test`. Never delete it. |

Promotions use merge commits, not squash, so the three branches share history and never drift
apart. Every pull request needs green CI before merging.

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/): `feat: …`,
`fix: …`, `docs: …`, `chore: …`, `test: …`, `refactor: …`. Reference the issue with `Refs #N`
on work branches; close it once the change reaches `main`.

## Hotfixes (emergencies only)

When production is broken and can't wait for the normal flow:

1. Open an issue, then branch from `main`: `hotfix/<issue>_<short-description>`.
2. Pull request into `main`, then release as usual (see [release-process.md](release-process.md)).
3. **The same day**, merge the same hotfix branch into `test` and `dev`, so the fix is never lost.

Everything else, however urgent it feels, goes through `dev`.
