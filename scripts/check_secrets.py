"""Block commits that contain credentials or private research data.

Prints the file and the kind of problem, never the matched value.

Usage:
  uv run python scripts/check_secrets.py            all tracked and untracked, non-ignored files
  uv run python scripts/check_secrets.py --staged   staged changes only (used by the git hook)
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


def main() -> int:
    staged = "--staged" in sys.argv
    if staged:
        paths = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split("\0")
    else:
        paths = git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split("\0")
    paths = [p for p in paths if p]

    found = [f"{p}: this path must never be committed" for p in paths if BLOCKED_PATH.search(p)]
    for path in paths:
        try:
            text = git("show", f":{path}") if staged else open(path, encoding="utf-8").read()
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        except subprocess.CalledProcessError:
            continue
        found += problems(path, text)

    if found:
        print("Secret check failed:\n  " + "\n  ".join(found), file=sys.stderr)
        print(
            "\nRemove the value (use an environment variable instead) and try again. If it is a "
            "deliberate fake, add it to ALLOWED_FAKES in scripts/check_secrets.py.",
            file=sys.stderr,
        )
        return 1
    print(f"Secret check passed ({len(paths)} files).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
