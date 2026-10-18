"""Parse MCP client config files (Claude, Cursor, VS Code, Windsurf) into MCPServer entries."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from agentscan.models import MCPServer


class ConfigError(Exception):
    pass


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, leaving string contents untouched.

    VS Code's mcp.json and settings.json are JSONC, which json.loads rejects.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
        elif c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        elif c in "}]":
            # Drop a trailing comma before the closing bracket. Comments are never copied to
            # `out`, so only whitespace can sit in between; this keeps the pass linear even on
            # hostile input such as thousands of commas followed by a huge comment.
            j = len(out) - 1
            while j >= 0 and out[j].isspace():
                j -= 1
            if j >= 0 and out[j] == ",":
                del out[j]
            out.append(c)
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def detect_client(path: Path) -> str:
    name = path.name.lower()
    posix = path.as_posix().lower()
    if name == "claude_desktop_config.json":
        return "claude-desktop"
    if name in (".claude.json", ".mcp.json"):
        return "claude-code"
    if "/.cursor/" in posix:
        return "cursor"
    if "windsurf" in posix:
        return "windsurf"
    if "/.vscode/" in posix or "/code/user/" in posix:
        return "vscode"
    return "unknown"


def load_servers(path: Path) -> list[MCPServer]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"cannot read file: {e.strerror}") from e
    return parse_servers(text, path)


def parse_servers(text: str, path: Path) -> list[MCPServer]:
    """Parse config text; `path` identifies the client and is recorded as each server's source."""
    try:
        data = json.loads(strip_jsonc(text))
    except json.JSONDecodeError as e:
        raise ConfigError(f"invalid JSON at line {e.lineno}: {e.msg}") from e
    except RecursionError:
        raise ConfigError("JSON is nested too deeply to be a config file") from None
    if not isinstance(data, dict):
        raise ConfigError("top-level value is not an object")

    client = detect_client(path)
    servers = []
    for scope, block in _server_blocks(data):
        for name, entry in block.items():
            if isinstance(entry, dict):
                full_name = f"{scope}:{name}" if scope else name
                servers.append(_parse_server(full_name, entry, path, client))
    return servers


def _server_blocks(data: dict) -> Iterator[tuple[str, dict]]:
    """Yield (scope, {name: server}) for every place a client stores MCP servers."""
    for key in ("mcpServers", "servers"):  # Claude/Cursor/Windsurf, VS Code mcp.json
        if isinstance(data.get(key), dict):
            yield "", data[key]
    mcp = data.get("mcp")  # VS Code settings.json
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        yield "", mcp["servers"]
    projects = data.get("projects")  # ~/.claude.json keeps per-project servers
    if isinstance(projects, dict):
        for project, cfg in projects.items():
            if isinstance(cfg, dict) and isinstance(cfg.get("mcpServers"), dict):
                yield project, cfg["mcpServers"]


def _parse_server(name: str, entry: dict, source: Path, client: str) -> MCPServer:
    raw_args = entry.get("args")
    args = (
        [str(a) for a in raw_args if isinstance(a, (str, int, float))]
        if isinstance(raw_args, list)
        else []
    )
    url = entry.get("url") or entry.get("serverUrl") or entry.get("httpUrl")
    return MCPServer(
        name=name,
        source=source,
        client=client,
        command=entry["command"] if isinstance(entry.get("command"), str) else None,
        args=args,
        env=_string_map(entry.get("env")),
        url=url if isinstance(url, str) else None,
        headers=_string_map(entry.get("headers")),
    )


def _string_map(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items() if isinstance(v, (str, int, float))}
