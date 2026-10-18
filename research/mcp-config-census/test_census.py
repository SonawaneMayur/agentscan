import json
import sqlite3
import urllib.request
from pathlib import Path

import pytest
from common import SCHEMA, _GitHubOnlyRedirects, check_url
from features import docker_image, docker_image_pinned, package_name, secret_kind, server_features
from fetch_scan import raw_url, scan_text

from agentscan.models import MCPServer


def server(**kwargs) -> MCPServer:
    return MCPServer(name="s", source=Path("/x.json"), client="test", **kwargs)


@pytest.mark.parametrize(
    ("ecosystem", "spec", "name"),
    [
        ("npm", "@modelcontextprotocol/server-filesystem@2025.8.21", "@modelcontextprotocol/server-filesystem"),  # noqa: E501
        ("npm", "@playwright/mcp", "@playwright/mcp"),
        ("npm", "Some-Server@latest", "some-server"),
        ("pypi", "mcp-server-git==0.6.2", "mcp-server-git"),
        ("pypi", "mcp-atlassian[extra]>=1.0", "mcp-atlassian"),
        ("pypi", "ruff@0.6.0", "ruff"),
    ],
)  # fmt: skip
def test_package_name(ecosystem, spec, name):
    assert package_name(ecosystem, spec) == name


def test_docker_image_skips_flag_values():
    args = ["run", "-i", "--rm", "-e", "TOKEN", "-v", "/a:/b", "ghcr.io/org/server:1.2"]
    assert docker_image(args) == "ghcr.io/org/server:1.2"


@pytest.mark.parametrize(
    ("image", "pinned"),
    [
        ("ghcr.io/org/server:1.2", True),
        ("org/server@sha256:abc", True),
        ("org/server", False),
        ("org/server:latest", False),
        ("localhost:5000/server", False),
    ],
)
def test_docker_image_pinned(image, pinned):
    assert docker_image_pinned(image) is pinned


def test_secret_kind_from_messages():
    assert secret_kind("env var 'X' contains a hardcoded GitHub token (ghp_…(40 chars))") == (
        "GitHub token"
    )
    assert secret_kind("argument --key=**** contains a hardcoded credential") == "credential"


def test_features_for_unpinned_filesystem_server_with_home_dir():
    features = server_features(
        server(command="npx", args=["-y", "@modelcontextprotocol/server-filesystem", "~"])
    )
    assert features["transport"] == "stdio"
    assert features["package"] == "@modelcontextprotocol/server-filesystem"
    assert features["pinned"] == 0
    assert features["broad_fs_path"] == 1


def test_features_for_remote_server():
    features = server_features(server(url="http://127.0.0.1:3000/mcp"))
    assert features["transport"] == "remote"
    assert features["url_scheme"] == "http"
    assert features["url_local"] == 1
    assert features["package"] is None


def test_scan_text_stores_servers_and_masked_findings():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    config = {
        "mcpServers": {
            "db": {
                "command": "uvx",
                "args": ["pg-mcp"],
                "env": {"DB_PASSWORD": "hunter2-prod-pass"},
            }
        }
    }
    scan_text(db, "sha1", json.dumps(config), ".cursor/mcp.json")

    assert db.execute("SELECT status, n_servers FROM blobs").fetchone()[:] == ("ok", 1)
    assert db.execute("SELECT package, pinned FROM servers").fetchone()[:] == ("pg-mcp", 0)
    rows = db.execute(
        "SELECT rule_id, message, secret_kind FROM findings ORDER BY rule_id"
    ).fetchall()
    assert [r["rule_id"] for r in rows] == ["MCP001", "MCP002"]
    assert "hunter2-prod-pass" not in rows[0]["message"]
    assert rows[0]["secret_kind"] == "credential"


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://raw.githubusercontent.com/o/r/abc/x.json",
        "https://example.com/x.json",
        "https://raw.githubusercontent.com.evil.example/x.json",
    ],
)
def test_only_https_github_urls_are_fetched(url):
    with pytest.raises(ValueError, match="refusing"):
        check_url(url)


def test_github_urls_are_allowed():
    check_url("https://api.github.com/search/code?q=x")
    check_url("https://raw.githubusercontent.com/o/r/abc/.mcp.json")


def test_redirect_off_github_is_refused_and_token_never_forwarded():
    handler = _GitHubOnlyRedirects()
    request = urllib.request.Request(
        "https://api.github.com/repos/o/r", headers={"Authorization": "Bearer t"}
    )
    assert handler.redirect_request(request, None, 302, "", {}, "https://evil.example/") is None
    moved = handler.redirect_request(
        request, None, 302, "", {}, "https://raw.githubusercontent.com/o/r/x"
    )
    assert not moved.has_header("Authorization")
    same_host = handler.redirect_request(
        request, None, 301, "", {}, "https://api.github.com/repositories/1"
    )
    assert same_host.has_header("Authorization")


def test_raw_url_encodes_spaces_and_keeps_escapes():
    url = "https://github.com/o/r/blob/abc123/Library/Application Support/Claude/c%2Bd.json"
    assert raw_url(url) == (
        "https://raw.githubusercontent.com/o/r/abc123/Library/Application%20Support/Claude/c%2Bd.json"
    )


def test_rescanning_does_not_duplicate_findings():
    db = sqlite3.connect(":memory:")
    db.executescript(SCHEMA)
    config = json.dumps({"mcpServers": {"x": {"command": "npx", "args": ["some-server"]}}})
    scan_text(db, "sha3", config, ".mcp.json")
    scan_text(db, "sha3", config, ".mcp.json")
    assert db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1


def test_scan_text_records_parse_errors():
    db = sqlite3.connect(":memory:")
    db.executescript(SCHEMA)
    scan_text(db, "sha2", "{broken", ".mcp.json")
    assert db.execute("SELECT status FROM blobs").fetchone()[0] == "parse_error"
