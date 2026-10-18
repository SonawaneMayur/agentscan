# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-10-18

### Fixed

- Scanning no longer crashes on server URLs with a bracketed placeholder host, such as
  `http://[SERVER_IP]:8080/mcp`. MCP003 now reports these when they use plain `http://`, and
  MCP001 still checks their query parameters. Found by running agentscan over public configs.
- A deeply nested JSON file is now reported as an invalid config instead of crashing the scan,
  so a planted file can't break a CI job.
- Comment and trailing-comma handling is now linear-time, so a crafted config can't stall the
  scanner.

## [0.1.0] - 2026-10-17

First release, published on PyPI as `agentscan-si`.

### Added

- `agentscan scan` discovers and scans MCP configs for Claude Desktop, Claude Code, Cursor,
  VS Code and Windsurf, including VS Code's JSON-with-comments files and per-project servers
  in `~/.claude.json`.
- Rules:
  - **MCP001** hardcoded secrets in `env`, `headers`, arguments and URLs, with masked output
  - **MCP002** `npx` / `uvx` / `pipx` packages not pinned to an exact version
  - **MCP003** remote servers reached over plain `http://` or `ws://`
- Text and JSON output, and `--fail-on` exit codes for CI.
- `agentscan rules` lists the available rules.
- Demo notebook and before/after example configs.

[Unreleased]: https://github.com/SonawaneMayur/agentscan/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/SonawaneMayur/agentscan/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/SonawaneMayur/agentscan/releases/tag/v0.1.0
