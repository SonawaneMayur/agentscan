"""Check a pull request's branch name and promotion path against docs/branching.md.

Usage: python scripts/check_branch_name.py <head-branch> <base-branch>
Exits 1 with an explanation when the pull request breaks the rules.
"""

from __future__ import annotations

import re
import sys

WORK_TYPES = ("feature", "bug", "chore", "docs", "refactor", "test")
# <type>/<issue number>_<short-description>, description in lowercase words joined by dashes
WORK_BRANCH = re.compile(rf"^({'|'.join(WORK_TYPES)})/[1-9][0-9]*_[a-z0-9]+(-[a-z0-9]+)*$")
HOTFIX_BRANCH = re.compile(r"^hotfix/[1-9][0-9]*_[a-z0-9]+(-[a-z0-9]+)*$")

EXAMPLE = "feature/14_sarif-output, bug/15_placeholder-host-crash"


def problem(head: str, base: str) -> str | None:
    """Return why head -> base is not allowed, or None when it is."""
    if HOTFIX_BRANCH.match(head):
        # Emergency path: hotfix into main, then back-merged into test and dev.
        return (
            None
            if base in ("main", "test", "dev")
            else f"hotfix branches merge into main, test or dev, not {base!r}"
        )
    if base == "dev":
        if WORK_BRANCH.match(head):
            return None
        return (
            f"branch {head!r} doesn't follow <type>/<issue>_<short-description> "
            f"(types: {', '.join(WORK_TYPES)}; e.g. {EXAMPLE})"
        )
    if base == "test":
        return (
            None if head == "dev" else f"only dev (or a hotfix) can merge into test, not {head!r}"
        )
    if base == "main":
        return (
            None if head == "test" else f"only test (or a hotfix) can merge into main, not {head!r}"
        )
    return f"pull requests must target dev, test or main, not {base!r}"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    head, base = argv
    reason = problem(head, base)
    if reason:
        print(f"Branch check failed: {reason}. See docs/branching.md.", file=sys.stderr)
        return 1
    print(f"Branch check passed: {head} -> {base}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
