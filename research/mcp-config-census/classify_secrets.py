"""Step 2b: estimate how many MCP001 findings are real secrets rather than placeholders.

Re-downloads only the files that had MCP001 findings, re-runs agentscan's secret detection in
memory and stores a quality label per secret (see features.secret_quality). The secret values
are never written anywhere: the table has no column for them.

Usage: uv run python research/mcp-config-census/classify_secrets.py
"""

from __future__ import annotations

import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from common import connect
from features import secret_quality
from fetch_scan import (
    BATCH,
    MAX_BYTES,
    WORKERS,
    RawFetcher,
    git_blob_sha,
    raw_url,
    scan_text,
)

from agentscan.config import ConfigError, parse_servers
from agentscan.rules.mcp import find_secrets


def classify(db, sha: str, text: str, path: str) -> int:
    try:
        servers = parse_servers(text, Path("/") / path)
    except ConfigError:
        return 0
    rows = [
        (sha, server.name, hit.location, hit.name, hit.kind, secret_quality(hit.value))
        for server in servers
        for hit in find_secrets(server)
    ]
    db.executemany("INSERT INTO secret_quality VALUES (?, ?, ?, ?, ?, ?)", rows)
    return len(rows)


def main() -> None:
    db = connect()
    pending = db.execute(
        """
        SELECT f.blob_sha, f.path, f.html_url
        FROM files f
        WHERE f.rowid = (SELECT MIN(rowid) FROM files WHERE blob_sha = f.blob_sha)
          AND f.blob_sha IN (SELECT blob_sha FROM findings WHERE rule_id = 'MCP001')
          AND f.blob_sha NOT IN (SELECT blob_sha FROM secret_quality_done)
        ORDER BY f.blob_sha
        """
    ).fetchall()
    print(f"{len(pending)} files with MCP001 findings to classify", flush=True)

    fetcher, started, done = RawFetcher(), time.monotonic(), 0
    with ThreadPoolExecutor(WORKERS) as pool:
        for start in range(0, len(pending), BATCH):
            batch = pending[start : start + BATCH]
            bodies = pool.map(lambda row: fetcher.fetch(raw_url(row["html_url"])), batch)
            for row, body in zip(batch, bodies, strict=True):
                sha = row["blob_sha"]
                ok = body is not None and len(body) <= MAX_BYTES and git_blob_sha(body) == sha
                if ok:
                    text = body.decode("utf-8", errors="replace")
                    scan_text(db, sha, text, row["path"])  # refresh findings with current rules
                    db.execute("DELETE FROM secret_quality WHERE blob_sha = ?", (sha,))
                    classify(db, sha, text, row["path"])
                db.execute(
                    "INSERT OR REPLACE INTO secret_quality_done VALUES (?, ?)",
                    (sha, "ok" if ok else "fetch_error"),
                )
                db.commit()
            done += len(batch)
            rate = done / (time.monotonic() - started) * 3600
            print(f"  {done}/{len(pending)}  ({rate:,.0f}/hour)", flush=True)

    quality = Counter(r[0] for r in db.execute("SELECT quality FROM secret_quality"))
    print("secret quality:", dict(quality.most_common()), flush=True)


if __name__ == "__main__":
    main()
