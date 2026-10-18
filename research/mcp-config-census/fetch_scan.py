"""Step 2: fetch each unique file once, scan it in memory, and store only derived results.

Raw file contents are never written to disk. Findings are stored with agentscan's masking.

Files are downloaded from raw.githubusercontent.com at the exact commit the search returned
(no API rate limit) and verified against the search result's git blob hash. Failures fall back
to the git blobs API when GITHUB_TOKEN is set. Files are processed in blob-hash order, which is
effectively random, so a partial run is an unbiased sample of unique contents.

Usage: uv run python research/mcp-config-census/fetch_scan.py [--limit N]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from common import USER_AGENT, GitHub, connect, now, open_url
from features import secret_kind, server_features

from agentscan.config import ConfigError, parse_servers
from agentscan.rules import all_rules

MAX_BYTES = 1_000_000
WORKERS = 4
WORKER_INTERVAL = 0.5  # seconds between requests per worker: ~8 requests/second overall
BATCH = 200
RULES = all_rules()


def scan_text(db, sha: str, text: str, path: str) -> None:
    # Re-scanning replaces earlier results instead of duplicating them.
    db.execute("DELETE FROM servers WHERE blob_sha = ?", (sha,))
    db.execute("DELETE FROM findings WHERE blob_sha = ?", (sha,))
    # A leading slash lets agentscan detect the client from directories like .cursor/.
    try:
        servers = parse_servers(text, Path("/") / path)
    except ConfigError as e:
        record_blob(db, sha, "parse_error", len(text), None, str(e))
        return

    for server in servers:
        db.execute(
            "INSERT OR REPLACE INTO servers VALUES "
            "(:blob_sha, :name, :transport, :launcher, :ecosystem, :package, :pinned, "
            ":url_scheme, :url_local, :n_env, :n_headers, :docker_image_pinned, :broad_fs_path)",
            {"blob_sha": sha, "name": server.name, **server_features(server)},
        )
        for rule in RULES:
            for finding in rule.run(server):
                db.execute(
                    "INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        sha,
                        server.name,
                        finding.rule_id,
                        str(finding.severity),
                        finding.message,
                        secret_kind(finding.message) if finding.rule_id == "MCP001" else None,
                    ),
                )
    record_blob(db, sha, "ok", len(text), len(servers), None)


def record_blob(db, sha, status, size, n_servers, error) -> None:
    db.execute(
        "INSERT OR REPLACE INTO blobs VALUES (?, ?, ?, ?, ?, ?)",
        (sha, status, size, n_servers, error, now()),
    )
    db.commit()


def git_blob_sha(body: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(body) + body).hexdigest()


def raw_url(html_url: str) -> str:
    """github.com/o/r/blob/<commit>/path -> raw.githubusercontent.com/o/r/<commit>/path"""
    url = html_url.replace("https://github.com/", "https://raw.githubusercontent.com/", 1)
    # Search results can contain unencoded spaces; keep existing %-escapes as they are.
    return urllib.parse.quote(url.replace("/blob/", "/", 1), safe=":/%@+~!$&'()*,;=")


class RawFetcher:
    """Downloads raw files; all workers back off together when GitHub pushes back."""

    def __init__(self) -> None:
        self._pause_until = 0.0
        self._lock = threading.Lock()

    def fetch(self, url: str) -> bytes | None:
        for attempt in range(5):
            delay = self._pause_until - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            try:
                with open_url(request) as response:
                    body = response.read(MAX_BYTES + 1)
                time.sleep(WORKER_INTERVAL)
                return body
            except urllib.error.HTTPError as e:
                if e.code in (403, 429) or e.code >= 500:
                    wait = int(e.headers.get("Retry-After") or 30 * 2**attempt)
                    with self._lock:
                        self._pause_until = max(self._pause_until, time.monotonic() + wait)
                    print(f"  raw host returned {e.code}, pausing {wait}s", flush=True)
                    continue
                return None  # 404 and similar: file gone or renamed
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                time.sleep(2**attempt)
            except (ValueError, OSError) as e:  # malformed URL, broken connection, etc.
                print(f"  skipping {url}: {type(e).__name__}", flush=True)
                return None
        return None


def fetch_api(gh: GitHub, repo: str, sha: str) -> bytes | None:
    try:
        blob = gh.get(f"/repos/{repo}/git/blobs/{sha}")
    except (urllib.error.HTTPError, RuntimeError):
        return None
    if blob.get("encoding") != "base64":
        return None
    return base64.b64decode(blob["content"])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--limit", type=int, help="process at most N files (for a test run)")
    args = parser.parse_args()

    db = connect()
    api_token = os.environ.get("GITHUB_TOKEN", "").strip()
    gh = GitHub(api_token, min_interval=0.75) if api_token else None
    if gh is None:
        print("GITHUB_TOKEN not set: files that fail to download won't be retried via the API")

    # One file row per unique content, in blob-hash order (effectively random).
    pending = db.execute(
        """
        SELECT f.blob_sha, f.repo_full_name AS repo, f.path, f.html_url
        FROM files f
        WHERE f.rowid = (SELECT MIN(rowid) FROM files WHERE blob_sha = f.blob_sha)
          AND NOT EXISTS (SELECT 1 FROM blobs b WHERE b.sha = f.blob_sha)
        ORDER BY f.blob_sha
        """
    ).fetchall()
    if args.limit:
        pending = pending[: args.limit]
    print(f"{len(pending)} unique files to fetch", flush=True)

    fetcher = RawFetcher()
    started, done, fallbacks = time.monotonic(), 0, 0
    with ThreadPoolExecutor(WORKERS) as pool:
        for start in range(0, len(pending), BATCH):
            batch = pending[start : start + BATCH]
            bodies = pool.map(lambda row: fetcher.fetch(raw_url(row["html_url"])), batch)
            for row, body in zip(batch, bodies, strict=True):
                sha = row["blob_sha"]
                if body is not None and len(body) > MAX_BYTES:
                    record_blob(db, sha, "too_large", len(body), None, None)
                    continue
                if (body is None or git_blob_sha(body) != sha) and gh is not None:
                    body, fallbacks = fetch_api(gh, row["repo"], sha), fallbacks + 1
                if body is None or git_blob_sha(body) != sha:
                    record_blob(db, sha, "fetch_error", None, None, "download failed")
                    continue
                try:
                    scan_text(db, sha, body.decode("utf-8", errors="replace"), row["path"])
                except Exception as e:  # one odd file must not stop a long run
                    db.rollback()
                    record_blob(db, sha, "scan_error", len(body), None, f"{type(e).__name__}: {e}")
                    print(f"  scan error on {sha[:10]}: {type(e).__name__}: {e}", flush=True)
            done += len(batch)
            rate = done / (time.monotonic() - started) * 3600
            print(
                f"  {done}/{len(pending)}  ({rate:,.0f}/hour, {fallbacks} API fallbacks)",
                flush=True,
            )


if __name__ == "__main__":
    main()
