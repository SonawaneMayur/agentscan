import json
import time
from pathlib import Path

import pytest

from agentscan.config import (
    ConfigError,
    detect_client,
    load_servers,
    parse_servers,
    strip_jsonc,
)
from agentscan.discovery import discover


def test_strip_jsonc_removes_comments_and_trailing_commas():
    text = """{
      // line comment
      "url": "http://example.com/a//b", /* block */
      "list": [1, 2,],
      "s": "has , } inside",
    }"""
    assert json.loads(strip_jsonc(text)) == {
        "url": "http://example.com/a//b",
        "list": [1, 2],
        "s": "has , } inside",
    }


def test_strip_jsonc_drops_comma_before_comment_and_bracket():
    assert json.loads(strip_jsonc('{"a": [1, 2, /* c */\n // d\n ], }')) == {"a": [1, 2]}


def test_strip_jsonc_stays_fast_on_hostile_input():
    # Quadratic handling of commas-then-comment would take minutes on this.
    hostile = "[" + "," * 200_000 + "/*" + "x" * 200_000 + "*/ ]"
    started = time.monotonic()
    strip_jsonc(hostile)
    assert time.monotonic() - started < 2


def test_deeply_nested_json_is_a_config_error_not_a_crash(tmp_path: Path):
    path = tmp_path / ".mcp.json"
    path.write_text("[" * 100_000 + "]" * 100_000)
    with pytest.raises(ConfigError):
        load_servers(path)


def test_load_claude_desktop_config(write_config):
    path = write_config(
        "claude_desktop_config.json",
        {
            "mcpServers": {
                "fs": {"command": "npx", "args": ["-y", "pkg"], "env": {"A": "1"}},
            }
        },
    )
    [server] = load_servers(path)
    assert server.name == "fs"
    assert server.client == "claude-desktop"
    assert server.command == "npx"
    assert server.args == ["-y", "pkg"]
    assert server.env == {"A": "1"}


def test_load_vscode_jsonc_with_remote_server(tmp_path: Path):
    path = tmp_path / ".vscode" / "mcp.json"
    path.parent.mkdir()
    path.write_text(
        '{\n  // remote\n  "servers": {"api": {"type": "http", "url": "https://x.dev/mcp",'
        ' "headers": {"Authorization": "Bearer ${input:token}"}},},\n}'
    )
    [server] = load_servers(path)
    assert server.client == "vscode"
    assert server.url == "https://x.dev/mcp"
    assert server.headers["Authorization"] == "Bearer ${input:token}"


def test_load_claude_code_per_project_servers(write_config):
    path = write_config(
        ".claude.json",
        {
            "mcpServers": {"global": {"command": "a"}},
            "projects": {"/work/app": {"mcpServers": {"local": {"command": "b"}}}},
        },
    )
    names = {s.name for s in load_servers(path)}
    assert names == {"global", "/work/app:local"}


def test_parse_servers_from_text_uses_path_for_client():
    [server] = parse_servers('{"mcpServers": {"a": {"command": "x"}}}', Path("/r/.cursor/mcp.json"))
    assert server.client == "cursor"
    assert server.source == Path("/r/.cursor/mcp.json")


def test_invalid_json_raises_config_error(tmp_path: Path):
    path = tmp_path / ".mcp.json"
    path.write_text("{not json")
    with pytest.raises(ConfigError, match="invalid JSON"):
        load_servers(path)


@pytest.mark.parametrize(
    ("path", "client"),
    [
        ("/x/.cursor/mcp.json", "cursor"),
        ("/x/.codeium/windsurf/mcp_config.json", "windsurf"),
        ("/x/.mcp.json", "claude-code"),
        ("/x/other.json", "unknown"),
    ],
)
def test_detect_client(path, client):
    assert detect_client(Path(path)) == client


def test_discover_finds_project_configs_and_skips_node_modules(write_config, tmp_path: Path):
    wanted = write_config("app/.cursor/mcp.json", {})
    write_config("node_modules/pkg/.mcp.json", {})
    assert discover([tmp_path], include_global=False) == [wanted]
