"""Shared census pipeline pieces: paths, SQLite schema and a rate-limited GitHub client."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"  # gitignored: working database, salt, disclosure list
RESULTS = ROOT / "results"  # committed: aggregated, pseudonymized tables only
FIGURES = ROOT / "figures"
DB_PATH = DATA / "census.db"
SALT_PATH = DATA / "salt.txt"

API = "https://api.github.com"
USER_AGENT = "agentscan-mcp-config-census (+https://github.com/SonawaneMayur/agentscan)"

SCHEMA = """
CREATE TABLE IF NOT EXISTS shards (
    query TEXT NOT NULL,
    size_lo INTEGER NOT NULL,
    size_hi INTEGER NOT NULL,
    state TEXT NOT NULL,              -- split | pending | done
    total_count INTEGER,
    next_page INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (query, size_lo, size_hi)
);
CREATE TABLE IF NOT EXISTS files (
    repo_full_name TEXT NOT NULL,
    path TEXT NOT NULL,
    blob_sha TEXT NOT NULL,
    client TEXT NOT NULL,
    repo_id INTEGER,
    owner_type TEXT,
    is_fork INTEGER,
    html_url TEXT,
    found_at TEXT NOT NULL,
    PRIMARY KEY (repo_full_name, path)
);
CREATE INDEX IF NOT EXISTS files_blob ON files (blob_sha);
CREATE TABLE IF NOT EXISTS blobs (
    sha TEXT PRIMARY KEY,
    status TEXT NOT NULL,             -- ok | parse_error | scan_error | fetch_error | too_large
    size INTEGER,
    n_servers INTEGER,
    error TEXT,
    scanned_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS servers (
    blob_sha TEXT NOT NULL,
    name TEXT NOT NULL,
    transport TEXT NOT NULL,          -- stdio | remote | unknown
    launcher TEXT,
    ecosystem TEXT,
    package TEXT,
    pinned INTEGER,
    url_scheme TEXT,
    url_local INTEGER,
    n_env INTEGER,
    n_headers INTEGER,
    docker_image_pinned INTEGER,
    broad_fs_path INTEGER,
    PRIMARY KEY (blob_sha, name)
);
CREATE TABLE IF NOT EXISTS findings (
    blob_sha TEXT NOT NULL,
    server_name TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,            -- already masked by agentscan
    secret_kind TEXT
);
CREATE INDEX IF NOT EXISTS findings_blob ON findings (blob_sha);
-- One row per MCP001 secret: where it was and how real it looks. The value itself is never
-- stored; there is deliberately no column that could hold it.
CREATE TABLE IF NOT EXISTS secret_quality (
    blob_sha TEXT NOT NULL,
    server_name TEXT NOT NULL,
    location TEXT NOT NULL,           -- env var | header | argument | URL query parameter
    var_name TEXT NOT NULL,
    secret_kind TEXT NOT NULL,
    quality TEXT NOT NULL             -- likely_real | placeholder | low_entropy | too_short
);
CREATE INDEX IF NOT EXISTS secret_quality_blob ON secret_quality (blob_sha);
CREATE TABLE IF NOT EXISTS secret_quality_done (blob_sha TEXT PRIMARY KEY, status TEXT NOT NULL);
"""


def connect() -> sqlite3.Connection:
    private_dir(DATA)
    db = sqlite3.connect(DB_PATH)
    private_file(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    return db


# --- local data protection -----------------------------------------------------------------
# data/ holds repo names and masked findings: readable by this user account only.


def private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def private_file(path: Path) -> None:
    if path.exists():
        os.chmod(path, 0o600)


# --- network safety ------------------------------------------------------------------------
# Only GitHub is ever contacted, only over https, and the token never leaves api.github.com.

ALLOWED_HOSTS = {"api.github.com", "raw.githubusercontent.com"}


def check_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"refusing to fetch non-GitHub URL: {url[:80]}")


class _GitHubOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            check_url(newurl)
        except ValueError:
            return None  # urllib then raises the 3xx as an HTTPError instead of following it
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).hostname != "api.github.com":
            new.remove_header("Authorization")
        return new


_OPENER = urllib.request.build_opener(_GitHubOnlyRedirects)


def open_url(request: urllib.request.Request, timeout: float = 30):
    check_url(request.full_url)
    return _OPENER.open(request, timeout=timeout)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def pseudonym(value: str) -> str:
    """Stable salted hash so published tables can't be joined back to repo names."""
    private_dir(DATA)
    if not SALT_PATH.exists():
        SALT_PATH.write_text(secrets.token_hex(16))
    private_file(SALT_PATH)
    salt = SALT_PATH.read_text().strip()
    return hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()[:12]


def token() -> str:
    value = os.environ.get("GITHUB_TOKEN", "").strip()
    if not value:
        sys.exit(
            "GITHUB_TOKEN is not set. Create a fine-grained token with public repository "
            "read-only access and run:  export GITHUB_TOKEN=<token>"
        )
    return value


class GitHub:
    """Minimal GitHub REST client that paces requests and waits out rate limits."""

    def __init__(self, token: str, min_interval: float) -> None:
        self.token = token
        self.min_interval = min_interval
        self._next_allowed = 0.0

    def get(self, path: str, params: dict | None = None) -> dict:
        url = f"{API}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        for attempt in range(8):
            delay = self._next_allowed - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            request = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": USER_AGENT,
                },
            )
            try:
                with open_url(request) as response:
                    self._next_allowed = time.monotonic() + self.min_interval
                    return json.load(response)
            except urllib.error.HTTPError as e:
                if e.code in (403, 429):
                    self._wait_for_limit(e.headers, attempt)
                    continue
                if e.code >= 500:
                    time.sleep(min(2**attempt, 60))
                    continue
                raise
            except (urllib.error.URLError, TimeoutError):
                time.sleep(min(2**attempt, 60))
        raise RuntimeError(f"giving up on {url} after repeated failures")

    def _wait_for_limit(self, headers, attempt: int) -> None:
        if retry_after := headers.get("Retry-After"):
            wait = int(retry_after) + 1
        elif headers.get("X-RateLimit-Remaining") == "0":
            wait = max(int(headers.get("X-RateLimit-Reset", "0")) - int(time.time()), 0) + 2
        else:  # secondary rate limit without guidance
            wait = min(60 * 2**attempt, 900)
        print(f"  rate limited, waiting {wait}s", flush=True)
        time.sleep(wait)
