"""Step 1: find public MCP config files with GitHub code search and record them in the database.

Code search returns at most 1,000 results per query, so each query is split by file size until
every range fits. Progress is stored per range, so an interrupted run resumes where it stopped.

Usage: uv run python research/mcp-config-census/collect.py [--only CLIENT]
"""

from __future__ import annotations

import argparse
import math

from common import GitHub, connect, now, token

# (client, search query). Keywords keep results to files that actually define servers.
TARGETS = [
    ("claude-code", "mcpServers filename:.mcp.json"),
    ("cursor", "mcpServers path:.cursor filename:mcp.json"),
    ("vscode", "servers path:.vscode filename:mcp.json"),
    ("claude-desktop", "mcpServers filename:claude_desktop_config.json"),
    ("windsurf", "mcpServers filename:mcp_config.json"),
]
MAX_SIZE = 384_000  # code search only indexes files smaller than 384 KB
RESULT_CAP = 1_000
PER_PAGE = 100


def search(gh: GitHub, query: str, lo: int, hi: int, page: int) -> dict:
    return gh.get(
        "/search/code", {"q": f"{query} size:{lo}..{hi}", "per_page": PER_PAGE, "page": page}
    )


def store_items(db, client: str, items: list[dict]) -> int:
    rows = [
        (
            item["repository"]["full_name"],
            item["path"],
            item["sha"],
            client,
            item["repository"]["id"],
            item["repository"]["owner"]["type"],
            int(item["repository"]["fork"]),
            item["html_url"],
            now(),
        )
        for item in items
        if not item["repository"].get("private")
    ]
    before = db.total_changes
    db.executemany("INSERT OR IGNORE INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
    db.commit()
    return db.total_changes - before


def plan(db, gh: GitHub, client: str, query: str) -> None:
    """Split [0, MAX_SIZE] into size ranges with at most RESULT_CAP results each."""
    stack = [(0, MAX_SIZE)]
    while stack:
        lo, hi = stack.pop()
        known = db.execute(
            "SELECT state FROM shards WHERE query = ? AND size_lo = ? AND size_hi = ?",
            (query, lo, hi),
        ).fetchone()
        if known and known["state"] == "split":
            mid = (lo + hi) // 2
            stack += [(mid + 1, hi), (lo, mid)]
            continue
        if known:
            continue

        first = search(gh, query, lo, hi, page=1)
        total = first["total_count"]
        if total > RESULT_CAP and hi > lo:
            db.execute("INSERT INTO shards VALUES (?, ?, ?, 'split', ?, 1)", (query, lo, hi, total))
            mid = (lo + hi) // 2
            stack += [(mid + 1, hi), (lo, mid)]
            print(f"  size {lo}..{hi}: {total} results, splitting", flush=True)
        else:
            # The probe already fetched page 1 of this leaf range, so keep it.
            new = store_items(db, client, first["items"])
            pages = math.ceil(min(total, RESULT_CAP) / PER_PAGE)
            state = "done" if pages <= 1 else "pending"
            db.execute(
                "INSERT INTO shards VALUES (?, ?, ?, ?, ?, 2)", (query, lo, hi, state, total)
            )
            print(f"  size {lo}..{hi}: {total} results (+{new} new files)", flush=True)
        db.commit()


def collect_pending(db, gh: GitHub, client: str, query: str) -> None:
    shards = db.execute(
        "SELECT * FROM shards WHERE query = ? AND state = 'pending' ORDER BY size_lo", (query,)
    ).fetchall()
    for shard in shards:
        pages = math.ceil(min(shard["total_count"], RESULT_CAP) / PER_PAGE)
        for page in range(shard["next_page"], pages + 1):
            result = search(gh, query, shard["size_lo"], shard["size_hi"], page)
            new = store_items(db, client, result["items"])
            db.execute(
                "UPDATE shards SET next_page = ? WHERE query = ? AND size_lo = ? AND size_hi = ?",
                (page + 1, query, shard["size_lo"], shard["size_hi"]),
            )
            db.commit()
            print(
                f"  size {shard['size_lo']}..{shard['size_hi']} page {page}/{pages} (+{new})",
                flush=True,
            )
            if not result["items"]:
                break
        db.execute(
            "UPDATE shards SET state = 'done' WHERE query = ? AND size_lo = ? AND size_hi = ?",
            (query, shard["size_lo"], shard["size_hi"]),
        )
        db.commit()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", choices=[c for c, _ in TARGETS], help="collect one client")
    args = parser.parse_args()

    db = connect()
    gh = GitHub(token(), min_interval=6.5)  # code search allows 10 requests per minute
    for client, query in TARGETS:
        if args.only and client != args.only:
            continue
        print(f"[{client}] {query}", flush=True)
        plan(db, gh, client, query)
        collect_pending(db, gh, client, query)

    total = db.execute("SELECT COUNT(*), COUNT(DISTINCT blob_sha) FROM files").fetchone()
    print(f"done: {total[0]} files, {total[1]} unique contents", flush=True)


if __name__ == "__main__":
    main()
