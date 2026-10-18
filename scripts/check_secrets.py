"""Block commits that contain credentials or private research data.

Prints the file and the kind of problem, never the matched value.

Usage:
  uv run python scripts/check_secrets.py            all tracked and untracked, non-ignored files
  uv run python scripts/check_secrets.py --staged   staged changes only (used by the git hook)
  uv run python scripts/check_secrets.py --rev REV  every file in a commit, e.g. origin/main
  uv run python scripts/check_secrets.py --history  every file version in every commit and tag
"""

from __future__ import annotations

import re
import subprocess
import sys

from agentscan.rules.mcp import SECRET_PATTERNS

PATTERNS = [
    *SECRET_PATTERNS,
    ("GitHub fine-grained token", re.compile(r"github_pat_[A-Za-z0-9_]{50,}")),
    ("PyPI token", re.compile(r"pypi-[A-Za-z0-9_-]{50,}")),
    ("long bearer token", re.compile(r"Bearer\s+[A-Za-z0-9_\-.=]{30,}")),
]

# Paths that must never be committed, whatever their content.
BLOCKED_PATH = re.compile(
    r"(^|/)research/[^/]+/data/"
    r"|\.(db|sqlite3?|db-journal|pem|key|p12|pfx)$"
    r"|(^|/)\.env($|\.(?!example$))"
    r"|(^|/)(\.pypirc|\.netrc|id_rsa[^/]*|id_ed25519[^/]*)$"
)

# Deliberately fake values used in example configs and tests.
ALLOWED_FAKES = (
    "hunter2-prod-password",
    "hunter2-prod-pass",
    "demo-token-1234567890",
    "demo-jira-token-7c1e4b",
    "demo-key-5f2c9a71",
    "prod-token-8f2a61c9",
)


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout


def problems(path: str, text: str) -> list[str]:
    found = []
    for kind, pattern in PATTERNS:
        for match in pattern.finditer(text):
            start = text.rfind("\n", 0, match.start()) + 1
            end = text.find("\n", match.end())
            line = text[start : end if end != -1 else len(text)]
            if not any(fake in line for fake in ALLOWED_FAKES):
                line_no = text.count("\n", 0, match.start()) + 1
                found.append(f"{path}:{line_no}: possible {kind}")
    return found


def split_z(output: str) -> list[str]:
    return [part for part in output.split("\0") if part]


def history_items() -> list[tuple[str, str, str]]:
    """Every file version added or changed in any commit on any branch or tag."""
    items, seen = [], set()
    for commit in git("rev-list", "--all").split():
        parts = split_z(git("diff-tree", "--no-commit-id", "-r", "--root", "-z", commit))
        for meta, path in zip(parts[::2], parts[1::2], strict=True):
            _, _, _, blob, status = meta.split()
            if status != "D" and (blob, path) not in seen:
                seen.add((blob, path))
                items.append((f"commit {commit[:7]} {path}", path, blob))
    return items


def collect() -> tuple[str, list[tuple[str, str, str | None]]]:
    """Return a description and (label, path, git object or None for the working tree) items."""
    args = sys.argv[1:]
    if "--staged" in args:
        paths = split_z(git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"))
        return "staged files", [(p, p, f":{p}") for p in paths]
    if "--rev" in args:
        rev = args[args.index("--rev") + 1]
        paths = split_z(git("ls-tree", "-r", "--name-only", "-z", rev))
        return f"files in {rev}", [(f"{rev}:{p}", p, f"{rev}:{p}") for p in paths]
    if "--history" in args:
        commits = len(git("rev-list", "--all").split())
        return f"file versions across {commits} commits", history_items()
    paths = split_z(git("ls-files", "--cached", "--others", "--exclude-standard", "-z"))
    return "files", [(p, p, None) for p in paths]


def main() -> int:
    scope, items = collect()
    found = [
        f"{label}: this path must never be committed"
        for label, path, _ in items
        if BLOCKED_PATH.search(path)
    ]
    for label, path, obj in items:
        try:
            text = git("cat-file", "-p", obj) if obj else open(path, encoding="utf-8").read()
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        except subprocess.CalledProcessError:
            continue
        found += problems(label, text)

    if found:
        print("Secret check failed:\n  " + "\n  ".join(found), file=sys.stderr)
        print(
            "\nRemove the value (use an environment variable instead) and try again. If it is a "
            "deliberate fake, add it to ALLOWED_FAKES in scripts/check_secrets.py.",
            file=sys.stderr,
        )
        return 1
    print(f"Secret check passed ({len(items)} {scope}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
