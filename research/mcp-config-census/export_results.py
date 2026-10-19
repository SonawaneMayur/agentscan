"""Step 3: aggregate the working database into pseudonymized tables in results/ (safe to commit).

Headline numbers cover real configs only: files named exactly like a client's config, outside
test/example/template folders (plugin configs included). Everything else is reported separately
in by_path_kind.csv. Rule prevalence is counted per file and per repo; server statistics per
unique file content, so copied templates don't dominate. Secrets are split into likely-real and
placeholder/test values when classify_secrets.py has run.

Usage: uv run --group demo python research/mcp-config-census/export_results.py
"""

from __future__ import annotations

import json
import re
import sys

import pandas as pd
from common import DATA, RESULTS, connect, private_file, pseudonym
from features import path_kind

from agentscan import __version__
from agentscan.rules import all_rules
from agentscan.rules.mcp import SECRET_PATTERNS

MIN_REPOS = 5  # only name packages and variable names seen in at least this many repos
PRIMARY_KINDS = ("config", "plugin")
RULES = {r.id: r for r in all_rules()}


# Anything matching these must never appear in a published table.
UNPUBLISHABLE = [
    *SECRET_PATTERNS,
    ("masked secret value", re.compile(r"…\(\d+ chars\)")),
    ("GitHub URL", re.compile(r"github\.com/")),
    ("repo file path", re.compile(r"[\w.-]+/[\w.-]+/\.(?:mcp|cursor|vscode)\b")),
]


def assert_publishable(directory) -> None:
    """Fail the export, deleting the offending file, if a results file could leak anything."""
    for path in sorted(directory.iterdir()):
        text = path.read_text(encoding="utf-8")
        leaks = [kind for kind, pattern in UNPUBLISHABLE if pattern.search(text)]
        if leaks:
            path.unlink()
            sys.exit(f"{path.name} contained {', '.join(leaks)}; deleted it. Fix the export.")


def pct(part, whole) -> float:
    return round(100 * part / whole, 1) if whole else 0.0


def rule_columns(files: pd.DataFrame, rule_ids: list[str]) -> dict:
    n = len(files)
    return {
        "files": n,
        "repos": int(files.repo_full_name.nunique()),
        "pct_any_finding": pct(files.any_finding.sum(), n),
        **{f"pct_{r}": pct((files[r] > 0).sum(), n) for r in rule_ids},
    }


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
    analyzed = pd.read_sql(
        """
        SELECT f.repo_full_name, f.path, f.blob_sha, f.client, f.owner_type, f.is_fork,
               b.n_servers
        FROM files f JOIN blobs b ON b.sha = f.blob_sha
        WHERE b.status = 'ok' AND b.n_servers > 0
        """,
        db,
    )
    analyzed["path_kind"] = [
        path_kind(c, p) for c, p in zip(analyzed.client, analyzed.path, strict=True)
    ]
    findings = pd.read_sql("SELECT blob_sha, rule_id, secret_kind FROM findings", db)
    quality = pd.read_sql("SELECT * FROM secret_quality", db)
    classified = pd.read_sql("SELECT blob_sha FROM secret_quality_done WHERE status = 'ok'", db)

    rule_ids = list(RULES)
    per_blob = (
        findings.groupby(["blob_sha", "rule_id"]).size().unstack(fill_value=0)
        .reindex(columns=rule_ids, fill_value=0)
    )  # fmt: skip
    analyzed = analyzed.join(per_blob, on="blob_sha")
    analyzed[rule_ids] = analyzed[rule_ids].fillna(0).astype(int)
    analyzed["any_finding"] = analyzed[rule_ids].sum(axis=1) > 0
    real_blobs = set(quality[quality.quality == "likely_real"].blob_sha)
    analyzed["likely_real_secret"] = analyzed.blob_sha.isin(real_blobs)

    # --- scope: real configs only ----------------------------------------------------------
    by_kind = pd.DataFrame(
        [{"path_kind": k, **rule_columns(g, rule_ids)} for k, g in analyzed.groupby("path_kind")]
    ).sort_values("files", ascending=False)
    by_kind.to_csv(RESULTS / "by_path_kind.csv", index=False)

    files = analyzed[analyzed.path_kind.isin(PRIMARY_KINDS)].copy()
    servers = pd.read_sql("SELECT * FROM servers", db)
    servers = servers[servers.blob_sha.isin(files.blob_sha)]
    findings = findings[findings.blob_sha.isin(files.blob_sha)]
    quality = quality[quality.blob_sha.isin(files.blob_sha)]
    n_files, n_repos = len(files), files.repo_full_name.nunique()

    def repos_where(mask) -> int:
        return int(files[mask].repo_full_name.nunique())

    secrets_classified = bool(len(classified))
    summary = {
        "agentscan_version": __version__,
        "scope": "files named exactly like a client config, outside test/example folders",
        "collected_files": len(all_files),
        "collected_unique_contents": int(all_files.blob_sha.nunique()),
        "fetch_status": dict(zip(blob_status.status, blob_status.n.astype(int), strict=True)),
        "files_with_servers": len(analyzed),
        "excluded_files_by_kind": {
            k: int(n)
            for k, n in analyzed.path_kind.value_counts().items()
            if k not in PRIMARY_KINDS
        },  # fmt: skip
        "analyzed_files": n_files,
        "analyzed_repos": int(n_repos),
        "analyzed_unique_contents": int(files.blob_sha.nunique()),
        "servers_in_unique_contents": len(servers),
        "pct_files_with_any_finding": pct(files.any_finding.sum(), n_files),
        "pct_repos_with_any_finding": pct(repos_where(files.any_finding), n_repos),
        "repos_with_any_secret_finding": repos_where(files.MCP001 > 0),
        "secrets_classified": secrets_classified,
        "repos_with_likely_real_secret": repos_where(files.likely_real_secret),
        "pct_repos_with_likely_real_secret": pct(repos_where(files.likely_real_secret), n_repos),
        "collection_window_utc": [all_files.found_at.min(), all_files.found_at.max()],
    }
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")

    by_rule = pd.DataFrame(
        [
            {
                "rule_id": r,
                "title": RULES[r].title,
                "severity": str(RULES[r].severity),
                "files_affected": int((files[r] > 0).sum()),
                "pct_files": pct((files[r] > 0).sum(), n_files),
                "repos_affected": repos_where(files[r] > 0),
                "pct_repos": pct(repos_where(files[r] > 0), n_repos),
            }
            for r in rule_ids
        ]
    )
    by_rule.to_csv(RESULTS / "by_rule.csv", index=False)

    by_client = pd.DataFrame(
        [{"client": c, **rule_columns(g, rule_ids)} for c, g in files.groupby("client")]
    ).sort_values("files", ascending=False)
    by_client.to_csv(RESULTS / "by_client.csv", index=False)

    # --- secrets ---------------------------------------------------------------------------
    if secrets_classified:
        secret_quality = (
            quality.groupby(["secret_kind", "quality"]).blob_sha.nunique().unstack(fill_value=0)
        )
        secret_quality["total"] = secret_quality.sum(axis=1)
        secret_quality.sort_values("total", ascending=False).to_csv(RESULTS / "secret_quality.csv")
        real = quality[quality.quality == "likely_real"].merge(
            files[["blob_sha", "repo_full_name"]], on="blob_sha"
        )
        names = real.groupby(["location", "var_name"]).repo_full_name.nunique().rename("repos")
        names[names >= MIN_REPOS].sort_values(ascending=False).to_csv(
            RESULTS / "leaked_variable_names.csv"
        )

    # --- servers and packages --------------------------------------------------------------
    packaged = servers[servers.package.notna()]
    pinning = packaged.groupby(["ecosystem", "launcher"]).agg(
        servers=("pinned", "size"), pinned=("pinned", "sum")
    )
    pinning["pinned"] = pinning.pinned.astype(int)
    pinning["pct_pinned"] = [
        pct(p, s) for p, s in zip(pinning.pinned, pinning.servers, strict=True)
    ]
    pinning.to_csv(RESULTS / "pinning.csv")

    servers.groupby("transport").size().rename("servers").to_csv(RESULTS / "transport.csv")
    remote = servers[servers.transport == "remote"]
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
    top_packages = top_packages[top_packages.repos >= MIN_REPOS]
    top_packages.sort_values("repos", ascending=False).to_csv(RESULTS / "top_packages.csv")

    docker = servers[servers.docker_image_pinned.notna()]
    filesystem = servers[servers.broad_fs_path.notna()]
    pd.DataFrame(
        [
            ("docker_servers", len(docker)),
            ("docker_images_pinned", int(docker.docker_image_pinned.sum())),
            ("filesystem_servers", len(filesystem)),
            ("filesystem_broad_path", int(filesystem.broad_fs_path.sum())),
            ("servers_with_env", int((servers.n_env > 0).sum())),
            ("servers_with_headers", int((servers.n_headers > 0).sum())),
        ],
        columns=["measure", "count"],
    ).to_csv(RESULTS / "extras.csv", index=False)

    per_file = files.n_servers.clip(upper=10).astype(int).value_counts().sort_index()
    per_file.index = ["10+" if n == 10 else str(n) for n in per_file.index]
    per_file.rename_axis("n_servers").rename("files").to_csv(RESULTS / "servers_per_file.csv")

    anonymized = analyzed.assign(repo=analyzed.repo_full_name.map(pseudonym))[
        ["repo", "client", "path_kind", "owner_type", "is_fork", "n_servers", *rule_ids,
         "likely_real_secret", "any_finding"]
    ]  # fmt: skip
    anonymized.to_csv(RESULTS / "files_anonymized.csv", index=False)

    # Private, gitignored: likely-real secrets, for notifying owners. Never published.
    disclosure = (
        pd.read_sql("SELECT * FROM secret_quality WHERE quality = 'likely_real'", db)
        .merge(pd.read_sql("SELECT repo_full_name, path, blob_sha, html_url FROM files", db))
        .drop(columns=["quality"])
        .drop_duplicates(["repo_full_name", "path", "location", "var_name"])
    )
    disclosure.to_csv(DATA / "disclosure.csv", index=False)
    private_file(DATA / "disclosure.csv")

    assert_publishable(RESULTS)
    print(json.dumps(summary, indent=2))
    print(by_rule.to_string(index=False))
    print(by_kind.to_string(index=False))


if __name__ == "__main__":
    main()
