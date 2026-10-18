from pathlib import Path

import pytest

from agentscan.models import MCPServer
from agentscan.rules import all_rules
from agentscan.rules.mcp import package_spec

# Secret-shaped test values are assembled at runtime so the repo never contains a literal
# that secret scanners (including GitHub push protection) would flag.
GITHUB_TOKEN = "ghp_" + "a1B2" * 9
ANTHROPIC_KEY = "sk-ant-" + "api03" + "x" * 30

RULES = {r.id: r for r in all_rules()}


def server(**kwargs) -> MCPServer:
    return MCPServer(name="test", source=Path("test.json"), client="test", **kwargs)


def messages(rule_id: str, srv: MCPServer) -> list[str]:
    return [f.message for f in RULES[rule_id].run(srv)]


# --- MCP001 --------------------------------------------------------------------------------


def test_secret_in_env_is_reported_and_masked():
    [msg] = messages("MCP001", server(env={"GITHUB_TOKEN": GITHUB_TOKEN}))
    assert "GitHub token" in msg
    assert GITHUB_TOKEN not in msg


def test_known_secret_format_found_under_any_env_name():
    assert messages("MCP001", server(env={"CONFIG": ANTHROPIC_KEY}))


@pytest.mark.parametrize(
    "value", ["${GITHUB_TOKEN}", "$GITHUB_TOKEN", "<your-token>", "your_token_here", "short"]
)
def test_env_references_and_placeholders_are_not_secrets(value):
    assert messages("MCP001", server(env={"GITHUB_TOKEN": value})) == []


def test_literal_bearer_header_is_reported():
    srv = server(headers={"Authorization": "Bearer abcdefghijklmnop"})
    assert messages("MCP001", srv)


def test_bearer_header_with_input_reference_is_ok():
    srv = server(headers={"Authorization": "Bearer ${input:api-token}"})
    assert messages("MCP001", srv) == []


def test_secret_in_argument_is_reported():
    [msg] = messages("MCP001", server(command="node", args=[f"--api-key={ANTHROPIC_KEY}"]))
    assert msg.startswith("argument --api-key=")
    assert ANTHROPIC_KEY not in msg


def test_secret_in_url_query_is_reported():
    assert messages("MCP001", server(url="https://x.dev/mcp?api_key=abcd1234efgh5678"))


# --- MCP002 --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]),
        ("npx", ["-y", "some-server@latest"]),
        ("npx", ["@scope/server@^1.2.0"]),
        ("/usr/local/bin/npx", ["server"]),
        ("pnpm", ["dlx", "server"]),
        ("uvx", ["mcp-server-git"]),
        ("uvx", ["--python", "3.12", "mcp-server-fetch"]),
        ("uv", ["tool", "run", "mcp-server-time"]),
        ("pipx", ["run", "mcp-server-time"]),
    ],
)
def test_unpinned_packages_are_reported(command, args):
    assert messages("MCP002", server(command=command, args=args))


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/tmp"]),
        ("npx", ["server@1.4.0"]),
        ("uvx", ["mcp-server-git==0.6.2"]),
        ("uvx", ["--from", "mcp-server-git==0.6.2", "mcp-server-git"]),
        ("uvx", ["ruff@0.6.0"]),
        ("npx", ["./local-server"]),
        ("uvx", ["git+https://github.com/org/repo"]),
        ("node", ["server.js"]),
        ("docker", ["run", "-i", "image"]),
    ],
)
def test_pinned_or_non_registry_packages_are_ok(command, args):
    assert messages("MCP002", server(command=command, args=args)) == []


def test_package_spec_skips_flag_values():
    srv = server(command="uvx", args=["--python", "3.12", "--with", "extra", "mcp-server-fetch"])
    assert package_spec(srv) == ("pypi", "mcp-server-fetch")


# --- MCP003 --------------------------------------------------------------------------------


def test_plain_http_remote_server_is_reported():
    [msg] = messages("MCP003", server(url="http://mcp.example.com/sse"))
    assert "mcp.example.com" in msg


def test_plain_http_with_auth_header_mentions_credentials():
    srv = server(url="http://mcp.example.com/sse", headers={"Authorization": "${input:t}"})
    [msg] = messages("MCP003", srv)
    assert "credentials" in msg


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example.com/sse",
        "http://localhost:8080/mcp",
        "http://127.0.0.1:3000/mcp",
        "http://[::1]:3000/mcp",
    ],
)
def test_https_and_localhost_are_ok(url):
    assert messages("MCP003", server(url=url)) == []


# --- malformed input -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://[SERVER_IP]:8080/mcp",
        "http://[::1:8080/mcp",
        "http://user@[not-an-ip]/mcp?api_key=abcd1234efgh5678",
        "not a url",
        "",
    ],
)
def test_malformed_urls_never_crash_any_rule(url):
    for rule in RULES.values():
        rule.run(server(url=url))


def test_placeholder_host_over_http_is_still_reported():
    [msg] = messages("MCP003", server(url="http://[SERVER_IP]:8080/mcp"))
    assert "server_ip" in msg


def test_secret_in_query_of_malformed_url_is_reported():
    assert messages("MCP001", server(url="http://[HOST]/mcp?api_key=abcd1234efgh5678"))
