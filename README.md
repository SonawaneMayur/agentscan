# agentscan

Security scanner for AI agents. It finds risky MCP server setups in Claude, Cursor, VS Code
and Windsurf configs before they leak a credential or run a malicious package.

```console
$ agentscan scan examples/vulnerable
 HIGH  MCP001  Hardcoded secret in MCP config
  server   postgres (examples/vulnerable/.mcp.json)
  issue    env var 'DATABASE_PASSWORD' contains a hardcoded credential (hunt…(21 chars))
  fix      Reference an environment variable (e.g. "${GITHUB_TOKEN}") ...
...
✗ Scanned 7 MCP server(s) in 3 config file(s): 6 high, 4 medium
```

**See it in action:** [notebooks/agentscan-demo.ipynb](notebooks/agentscan-demo.ipynb) walks through a
scan of a multi-client setup, what each rule catches, charts of the findings, and the fixed configs.

## Install

```bash
uv tool install git+https://github.com/SonawaneMayur/agentscan   # PyPI release coming soon
```

## Usage

```bash
agentscan scan                    # current directory + your user-level client configs
agentscan scan path/to/project    # only configs inside that directory
agentscan scan --format json      # machine-readable output
agentscan scan --fail-on medium   # exit 1 on medium or worse (default: high), for CI
agentscan rules                   # list rules
```

Config files it reads:

| Client | Locations |
|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude.json`, `.mcp.json` |
| Cursor | `~/.cursor/mcp.json`, `.cursor/mcp.json` |
| VS Code | `.vscode/mcp.json`, `.vscode/settings.json`, user `mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

## Rules

| ID | Severity | Finds |
|---|---|---|
| MCP001 | high | API keys, tokens and passwords written directly in `env`, `headers`, arguments or URLs |
| MCP002 | medium | `npx`/`uvx`/`pipx` packages without an exact version, so every client restart runs the latest release |
| MCP003 | high | Remote servers reached over plain `http://` or `ws://` |

## Roadmap

- [x] MCP config scanning (secrets, unpinned packages, insecure transport)
- [ ] SARIF output and a GitHub Action
- [ ] Tool-description pinning to detect "rug pull" changes
- [ ] Live scan: connect to MCP servers and check tool descriptions for prompt injection
- [ ] Agent code analysis (LangChain, CrewAI, OpenAI/Anthropic SDKs)
- [ ] Findings mapped to OWASP LLM Top 10 and OWASP Agentic AI threats

## Development

```bash
uv sync               # create .venv with dev dependencies
uv run pytest         # tests
uv run ruff check     # lint
uv run agentscan scan examples/vulnerable

# re-run the demo notebook and save its outputs
uv run --group demo jupyter nbconvert --to notebook --execute --inplace notebooks/agentscan-demo.ipynb
```

Adding a rule: write a generator in `src/agentscan/rules/` that takes an `MCPServer`, yields one
message per problem, and register it with the `@rule(...)` decorator. Add tests in `tests/`.

## License

MIT
