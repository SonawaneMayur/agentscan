"""Step 3: aggregate the working database into pseudonymized tables in results/ (safe to commit).

A file is analyzed when its contents parsed and define at least one server. Rule prevalence is
counted per file and per repo; server statistics are counted per unique file content so that
copied templates don't dominate.

Usage: uv run --group demo python research/mcp-config-census/export_results.py
"""

from __future__ import annotations

import json
import sys

import pandas as pd
from common import DATA, RESULTS, connect, private_file, pseudonym

from agentscan import __version__
from agentscan.rules import all_rules

MIN_REPOS_FOR_PACKAGE = 5  # only name packages used by at least this many repos
RULES = {r.id: r for r in all_rules()}


def pct(part, whole) -> float:
    return round(100 * part / whole, 1) if whole else 0.0


def main() -> None:
    db = connect()
    pending = db.execute(
        "SELECT COUNT(DISTINCT f.blob_sha) FROM files f "
        "LEFT JOIN blobs b ON b.sha = f.blob_sha WHERE b.sha IS NULL"
    ).fetchone()[0]
    scanned = db.execute("SELECT COUNT(*) FROM blobs WHERE status = 'ok'").fetchone()[0]
    if not scanned:
        sys.exit("Nothing to export yet: run collect.py and fetch_scan.py first.")
    if pending:
        print(f"warning: {pending} files not scanned yet; re-run fetch_scan.py for full results")
    RESULTS.mkdir(exist_ok=True)

    all_files = pd.read_sql("SELECT * FROM files", db)
    blob_status = pd.read_sql("SELECT status, COUNT(*) AS n FROM blobs GROUP BY status", db)
    files = pd.read_sql(
        """
        SELECT f.repo_full_name, f.blob_sha, f.client, f.owner_type, f.is_fork, b.n_servers
        FROM files f JOIN blobs b ON b.sha = f.blob_sha
        WHERE b.status = 'ok' AND b.n_servers > 0
        """,
        db,
    )
    servers = pd.read_sql("SELECT * FROM servers", db)
    servers = servers[servers.blob_sha.isin(files.blob_sha)]
    findings = pd.read_sql("SELECT blob_sha, rule_id, secret_kind FROM findings", db)
    findings = findings[findings.blob_sha.isin(files.blob_sha)]

    rule_ids = list(RULES)
    per_blob = (
        findings.groupby(["blob_sha", "rule_id"]).size().unstack(fill_value=0)
        .reindex(columns=rule_ids, fill_value=0)
    )  # fmt: skip
    files = files.join(per_blob, on="blob_sha")
    files[rule_ids] = files[rule_ids].fillna(0).astype(int)
    files["any_finding"] = files[rule_ids].sum(axis=1) > 0
    n_files, n_repos = len(files), files.repo_full_name.nunique()
    repos_with_any = files[files.any_finding].repo_full_name.nunique()

    summary = {
        "agentscan_version": __version__,
        "collected_files": len(all_files),
        "collected_unique_contents": int(all_files.blob_sha.nunique()),
        "fetch_status": dict(zip(blob_status.status, blob_status.n.astype(int), strict=True)),
        "analyzed_files": n_files,
        "analyzed_repos": int(n_repos),
        "analyzed_unique_contents": int(files.blob_sha.nunique()),
        "servers_in_unique_contents": len(servers),
        "pct_files_with_any_finding": pct(files.any_finding.sum(), n_files),
        "pct_repos_with_any_finding": pct(repos_with_any, n_repos),
        "collection_window_utc": [all_files.found_at.min(), all_files.found_at.max()],
    }
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    by_rule = pd.DataFrame(
        [
            {
                "rule_id": rule_id,
                "title": RULES[rule_id].title,
                "severity": str(RULES[rule_id].severity),
                "files_affected": int((files[rule_id] > 0).sum()),
                "pct_files": pct((files[rule_id] > 0).sum(), n_files),
                "repos_affected": int(files[files[rule_id] > 0].repo_full_name.nunique()),
                "pct_repos": pct(files[files[rule_id] > 0].repo_full_name.nunique(), n_repos),
            }
            for rule_id in rule_ids
        ]
    )
    by_rule.to_csv(RESULTS / "by_rule.csv", index=False)

    by_client = files.groupby("client").agg(
        files=("blob_sha", "size"),
        pct_any_finding=("any_finding", lambda s: pct(s.sum(), len(s))),
        **{f"pct_{r}": (r, lambda s: pct((s > 0).sum(), len(s))) for r in rule_ids},
    )
    by_client.sort_values("files", ascending=False).to_csv(RESULTS / "by_client.csv")

    secrets = findings[findings.rule_id == "MCP001"].merge(files[["blob_sha"]], on="blob_sha")
    secret_kinds = (
        secrets.groupby("secret_kind").blob_sha.nunique().rename("unique_contents")
        .sort_values(ascending=False)
    )  # fmt: skip
    secret_kinds.to_csv(RESULTS / "secret_kinds.csv")

    packaged = servers[servers.package.notna()]
    pinning = packaged.groupby(["ecosystem", "launcher"]).agg(
        servers=("pinned", "size"), pinned=("pinned", "sum")
    )
    pinning["pinned"] = pinning.pinned.astype(int)
    pinning["pct_pinned"] = [
        pct(p, s) for p, s in zip(pinning.pinned, pinning.servers, strict=True)
    ]
    pinning.to_csv(RESULTS / "pinning.csv")

    transport = servers.groupby("transport").size().rename("servers").to_frame()
    remote = servers[servers.transport == "remote"]
    transport.to_csv(RESULTS / "transport.csv")
    remote.assign(local=remote.url_local.map({1: "local", 0: "remote host"})).groupby(
        ["url_scheme", "local"]
    ).size().rename("servers").to_csv(RESULTS / "remote_schemes.csv")

    repo_packages = packaged.merge(files[["blob_sha", "repo_full_name"]], on="blob_sha")
    top_packages = repo_packages.groupby(["package", "ecosystem"]).agg(
        repos=("repo_full_name", "nunique")
    )
    package_pinning = packaged.groupby(["package", "ecosystem"]).pinned.agg(["size", "sum"])
    top_packages["pct_pinned"] = [
        pct(package_pinning.loc[i, "sum"], package_pinning.loc[i, "size"])
        for i in top_packages.index
    ]
    top_packages = top_packages[top_packages.repos >= MIN_REPOS_FOR_PACKAGE]
    top_packages.sort_values("repos", ascending=False).to_csv(RESULTS / "top_packages.csv")

    docker = servers[servers.docker_image_pinned.notna()]
    filesystem = servers[servers.broad_fs_path.notna()]
    extras = pd.DataFrame(
        [
            ("docker_servers", len(docker)),
            ("docker_images_pinned", int(docker.docker_image_pinned.sum())),
            ("filesystem_servers", len(filesystem)),
            ("filesystem_broad_path", int(filesystem.broad_fs_path.sum())),
            ("servers_with_env", int((servers.n_env > 0).sum())),
            ("servers_with_headers", int((servers.n_headers > 0).sum())),
        ],
        columns=["measure", "count"],
    )
    extras.to_csv(RESULTS / "extras.csv", index=False)

    per_file = files.n_servers.clip(upper=10).astype(int).value_counts().sort_index()
    per_file.index = ["10+" if n == 10 else str(n) for n in per_file.index]
    per_file.rename_axis("n_servers").rename("files").to_csv(RESULTS / "servers_per_file.csv")

    anonymized = files.assign(repo=files.repo_full_name.map(pseudonym))[
        ["repo", "client", "owner_type", "is_fork", "n_servers", *rule_ids, "any_finding"]
    ]
    anonymized.to_csv(RESULTS / "files_anonymized.csv", index=False)

    # Private, gitignored: where secrets were found, for notifying owners. Never published.
    disclosure = (
        findings[findings.rule_id == "MCP001"]
        .merge(pd.read_sql("SELECT repo_full_name, path, blob_sha, html_url FROM files", db))
        .drop_duplicates(["repo_full_name", "path", "secret_kind"])
    )
    disclosure.to_csv(DATA / "disclosure.csv", index=False)
    private_file(DATA / "disclosure.csv")

    print(json.dumps(summary, indent=2))
    print(by_rule.to_string(index=False))


if __name__ == "__main__":
    main()
