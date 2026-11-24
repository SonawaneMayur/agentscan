import importlib.util
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "check_branch_name", Path(__file__).parents[1] / "scripts" / "check_branch_name.py"
)
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)


@pytest.mark.parametrize(
    ("head", "base"),
    [
        ("feature/14_sarif-output", "dev"),
        ("bug/15_placeholder-host-crash", "dev"),
        ("chore/1_branching-strategy", "dev"),
        ("docs/4_census-report", "dev"),
        ("refactor/20_split-rules", "dev"),
        ("test/2_regression-suite", "dev"),
        ("feature/7_x", "dev"),
        ("dev", "test"),
        ("test", "main"),
        ("hotfix/30_pypi-install-error", "main"),
        ("hotfix/30_pypi-install-error", "test"),
        ("hotfix/30_pypi-install-error", "dev"),
    ],
)
def test_allowed(head, base):
    assert check.problem(head, base) is None


@pytest.mark.parametrize(
    ("head", "base", "reason"),
    [
        ("my-change", "dev", "doesn't follow"),
        ("feature/sarif-output", "dev", "doesn't follow"),  # no issue number
        ("feature/14-sarif-output", "dev", "doesn't follow"),  # dash instead of underscore
        ("feature/14_SARIF-output", "dev", "doesn't follow"),  # uppercase
        ("feature/14_sarif_output", "dev", "doesn't follow"),  # underscores in description
        ("feature/0_x", "dev", "doesn't follow"),  # issue numbers start at 1
        ("fix/15_crash", "dev", "doesn't follow"),  # unknown type
        ("feature/14_sarif-output", "test", "only dev"),  # skipping dev
        ("feature/14_sarif-output", "main", "only test"),  # skipping dev and test
        ("dev", "main", "only test"),  # skipping test
        ("main", "dev", "doesn't follow"),
        ("hotfix/30_x", "release", "hotfix branches merge into"),
        ("feature/14_sarif-output", "release", "must target"),
    ],
)
def test_rejected(head, base, reason):
    assert reason in check.problem(head, base)


def test_cli_exit_codes(capsys):
    assert check.main(["feature/14_sarif-output", "dev"]) == 0
    assert check.main(["my-change", "dev"]) == 1
    assert "docs/branching.md" in capsys.readouterr().err
    assert check.main([]) == 2
