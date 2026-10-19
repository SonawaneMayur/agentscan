# MCP config census

How do people configure MCP servers in public repositories, and how often do those configs
contain the risks [agentscan](../../README.md) detects? This folder holds the pipeline, the
aggregated results and the analysis.

## Method

1. **Collect** ([collect.py](collect.py)): GitHub code search for MCP config files committed to
   public repositories: `.mcp.json` (Claude Code), `.cursor/mcp.json`, `.vscode/mcp.json`,
   `claude_desktop_config.json` and Windsurf's `mcp_config.json`. Search returns at most 1,000
   results per query, so each query is split by file size until every range fits.
2. **Fetch and scan** ([fetch_scan.py](fetch_scan.py)): each unique file content is fetched once,
   parsed and scanned with agentscan **in memory**. Only derived data is stored: server
   attributes (transport, package, pinning) and agentscan's already-masked findings.
3. **Export** ([export_results.py](export_results.py)): aggregates into [results/](results/).
   A file counts as analyzed when it parses and defines at least one server. Rule prevalence is
   reported per file and per repo; server statistics per unique file content, so copied templates
   don't dominate.

**Limitations:** code search only covers default branches, files under 384 KB and repositories
GitHub has indexed. Forks are mostly excluded. Committed configs are not the same as configs in
use on developer machines; user-level configs (for example `~/.cursor/mcp.json`) are rarely
committed. MCP001 also counts literal values for variables named like credentials, which
includes some test and placeholder values; MCP001 numbers are an upper bound.

## Ethics

- **No raw file contents are stored.** Files are scanned in memory; secrets never reach disk.
- **Published tables are aggregated or pseudonymized** (salted hash of the repo name). Package
  names are only listed when used by at least 5 repositories.
- **No repository is named** in the results or the write-up.
- **Found credentials are never tested or used.**
- **Disclosure:** GitHub secret scanning already alerts providers about well-known token formats
  in public repositories. Other likely-live credentials go to a private, gitignored list
  (`data/disclosure.csv`) so owners can be notified privately, never through public issues.

## Run it

Needs a GitHub token for the search API: a **fine-grained personal access token** with
*Public repositories (read-only)* access, no added permissions, and a short expiry (7 days).

Enter it so it is never shown on screen or saved to shell history:

```bash
unset HISTFILE
read -s "GITHUB_TOKEN?Paste token: "
export GITHUB_TOKEN
```

(In bash, use `read -s -p "Paste token: " GITHUB_TOKEN`.) Then run:

```bash
cd ~/projects/agentscan
uv run python research/mcp-config-census/collect.py
caffeinate -i uv run python research/mcp-config-census/fetch_scan.py
uv run --group demo python research/mcp-config-census/export_results.py
```

- `collect.py` takes 1-3 hours (code search allows 10 requests a minute).
- `fetch_scan.py` downloads raw files at about 20,000 per hour. `caffeinate -i` (macOS) keeps
  the machine awake.
- Delete the token on GitHub when the census is finished.

## Safety of running the pipeline

The pipeline handles files written by strangers, so it is built to treat them as untrusted data:

- **Nothing downloaded is executed.** Files are only parsed as JSON and matched with regular
  expressions; agentscan's parser is linear-time and rejects pathologically nested input.
- **Only GitHub is contacted, only over https:** `api.github.com` and
  `raw.githubusercontent.com`. Any other URL, including `file://`, is refused, as is a redirect
  to another host.
- **The token is only sent to `api.github.com`** and is stripped from any redirect elsewhere.
  Raw downloads never carry it.
- **Downloads are capped at 1 MB** and verified against the git blob hash from the search.
- **`data/` is readable by your user account only** (`700`/`600`) and is gitignored, as is
  `results/` until the final tables have been reviewed. A pre-commit hook
  ([scripts/check_secrets.py](../../scripts/check_secrets.py)) also refuses to commit anything
  under `data/`, database files or credentials.

All steps are resumable: re-running skips work already done. The working database lives in
`data/census.db` (gitignored).

Tests: `uv run --group demo pytest research/mcp-config-census`
