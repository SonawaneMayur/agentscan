# Release process

Releases follow the promotion flow in [branching.md](branching.md). Nothing reaches PyPI without
first being installed and run from TestPyPI.

## 1. Prepare on a work branch

On the branch for the release's last change (or a `chore/<issue>_release-X.Y.Z` branch):

- bump `__version__` in [src/agentscan/__init__.py](../src/agentscan/__init__.py) (SemVer:
  breaking change → major, feature → minor, fix → patch)
- move the `Unreleased` entries in [CHANGELOG.md](../CHANGELOG.md) under the new version and date

Merge it into `dev` as usual.

## 2. Release candidate on `test`

Open a pull request `dev` → `test` and merge it with a merge commit. The
[Publish to TestPyPI](../.github/workflows/publish-test.yml) workflow then:

1. runs the tests
2. builds `X.Y.ZrcN`, where `N` is the workflow run number (the rc suffix is not committed)
3. refuses to publish if research data, notebooks or local files are in the package
4. publishes to [TestPyPI](https://test.pypi.org/project/agentscan-si/) through Trusted Publishing
5. installs that candidate from TestPyPI (dependencies from the real PyPI only) and checks that
   `agentscan --version`, `agentscan rules` and scans of `examples/` behave as expected

Try it yourself if you like:

```bash
uv venv rc
uv pip install --python rc "rich>=13.7"
uv pip install --python rc --no-deps --default-index https://test.pypi.org/simple/ "agentscan-si==X.Y.ZrcN"
rc/bin/agentscan scan
```

## 3. Release from `main`

Open a pull request `test` → `main`, merge it with a merge commit, then tag the merged commit:

```bash
git checkout main
git pull
git tag -a vX.Y.Z -m "agentscan X.Y.Z"
git push origin vX.Y.Z
```

The [Release](../.github/workflows/release.yml) workflow refuses tags whose commit isn't in
`main` or doesn't match `__version__`, runs the tests, checks the package contents and publishes
to [PyPI](https://pypi.org/project/agentscan-si/). Finally, create the GitHub release page from the
changelog entry and close the release's issues.

## One-time setup

| Where | Setting |
|---|---|
| pypi.org → project → Publishing | Trusted publisher: owner `SonawaneMayur`, repo `agentscan`, workflow `release.yml`, environment `pypi` |
| test.pypi.org → Account → Publishing | Pending trusted publisher: project `agentscan-si`, owner `SonawaneMayur`, repo `agentscan`, workflow `publish-test.yml`, environment `testpypi` |
| GitHub → Settings → Environments | `pypi` and `testpypi` (created automatically on first use) |
