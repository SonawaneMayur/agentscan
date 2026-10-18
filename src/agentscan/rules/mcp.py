"""Rules that inspect MCP server entries in client config files."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from agentscan.models import MCPServer, Severity
from agentscan.rules import rule

# --- MCP001: hardcoded secrets -------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
SENSITIVE_NAME = re.compile(
    r"TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH", re.I
)
SENSITIVE_FLAG = re.compile(
    r"^(--?[\w-]*(?:token|secret|password|api[-_]?key|access[-_]?key)[\w-]*)=(.+)$", re.I
)
PLACEHOLDER = re.compile(r"^(?:<.*>|your[-_ ].*|x{3,}|\*+|changeme|\.\.\.)$", re.I)


def _known_secret(value: str) -> str | None:
    for kind, pattern in SECRET_PATTERNS:
        if pattern.search(value):
            return kind
    return None


def _is_literal(value: str) -> bool:
    """False for env var references and placeholders, which are the safe way to pass secrets."""
    value = value.strip()
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    if "${" in value or re.fullmatch(r"\$[A-Za-z_]\w*", value) or PLACEHOLDER.match(value):
        return False
    return len(value) >= 8


def _secret_kind(name: str, value: str) -> str | None:
    if kind := _known_secret(value):
        return kind
    if SENSITIVE_NAME.search(name) and _is_literal(value):
        return "credential"
    return None


def _mask(value: str) -> str:
    value = value.strip()
    if value.lower().startswith("bearer "):
        return "Bearer " + _mask(value[7:])
    return f"{value[:4]}…({len(value)} chars)" if len(value) > 8 else "****"


@rule(
    id="MCP001",
    title="Hardcoded secret in MCP config",
    severity=Severity.HIGH,
    description=(
        "API keys and tokens written directly into a config file end up in backups, dotfile "
        "repos and screenshots, and are readable by every process running as the user."
    ),
    remediation=(
        'Reference an environment variable (e.g. "${GITHUB_TOKEN}") or use the client\'s '
        "secret input/keychain support, then rotate the exposed credential."
    ),
)
def hardcoded_secret(server: MCPServer) -> Iterator[str]:
    for where, items in (("env var", server.env), ("header", server.headers)):
        for name, value in items.items():
            if kind := _secret_kind(name, value):
                yield f"{where} {name!r} contains a hardcoded {kind} ({_mask(value)})"

    for arg in server.args:
        flag = SENSITIVE_FLAG.match(arg)
        if kind := _known_secret(arg):
            shown = f"{flag.group(1)}={_mask(flag.group(2))}" if flag else _mask(arg)
            yield f"argument {shown} contains a hardcoded {kind}"
        elif flag and _is_literal(flag.group(2)):
            yield f"argument {flag.group(1)}={_mask(flag.group(2))} contains a hardcoded credential"

    if server.url:
        for name, value in parse_qsl(url_query(server.url)):
            if kind := _secret_kind(name, value):
                yield f"URL query parameter {name!r} contains a hardcoded {kind} ({_mask(value)})"


# --- MCP002: unpinned packages -------------------------------------------------------------

# (flags that name the package, flags that take a value) for each package runner ecosystem
_RUNNER_FLAGS = {
    "npm": ({"-p", "--package"}, {"-c", "--call", "--registry", "--cache", "--userconfig"}),
    "pypi": (
        {"--from", "--spec"},
        {
            "-p",
            "--python",
            "-w",
            "--with",
            "--with-editable",
            "--with-requirements",
            "--index",
            "--index-url",
            "--default-index",
            "--extra-index-url",
            "-c",
            "--constraints",
            "--pip-args",
        },
    ),
}
_EXACT_NPM_VERSION = re.compile(r"v?\d+\.\d+\.\d+(?:[-+][\w.+-]*)?")
_EXACT_PYPI_VERSION = re.compile(r"(?:==|@)\s*v?\d[\w.+!-]*\s*$")


def package_spec(server: MCPServer) -> tuple[str, str] | None:
    """Return (ecosystem, package spec) when the server is launched through a package runner."""
    if not server.command:
        return None
    cmd = Path(server.command).name.lower().removesuffix(".exe").removesuffix(".cmd")
    args = server.args
    if cmd in ("npx", "bunx"):
        ecosystem, rest = "npm", args
    elif cmd in ("pnpm", "yarn") and args[:1] == ["dlx"]:
        ecosystem, rest = "npm", args[1:]
    elif cmd == "uvx":
        ecosystem, rest = "pypi", args
    elif cmd == "uv" and args[:2] == ["tool", "run"]:
        ecosystem, rest = "pypi", args[2:]
    elif cmd == "pipx" and args[:1] == ["run"]:
        ecosystem, rest = "pypi", args[1:]
    else:
        return None

    package_flags, value_flags = _RUNNER_FLAGS[ecosystem]
    i = 0
    while i < len(rest):
        arg = rest[i]
        flag, has_value, value = arg.partition("=")
        if flag in package_flags:
            if has_value:
                return ecosystem, value
            return (ecosystem, rest[i + 1]) if i + 1 < len(rest) else None
        if arg.startswith("-"):
            i += 2 if flag in value_flags and not has_value else 1
            continue
        return ecosystem, arg
    return None


def is_pinned(ecosystem: str, spec: str) -> bool | None:
    """True/False for registry packages; None for local paths, URLs and git sources."""
    if spec.startswith((".", "/", "~")) or "://" in spec or spec.startswith("git+"):
        return None
    if ecosystem == "npm":
        if ":" in spec:  # github:, npm: aliases, file:
            return None
        _, _, version = spec[1:].partition("@") if spec.startswith("@") else spec.partition("@")
        return bool(_EXACT_NPM_VERSION.fullmatch(version))
    return bool(_EXACT_PYPI_VERSION.search(spec))


@rule(
    id="MCP002",
    title="MCP server package is not pinned",
    severity=Severity.MEDIUM,
    description=(
        "npx/uvx fetch the newest release every time the client starts. A compromised or "
        "malicious update of the package runs immediately with the user's privileges."
    ),
    remediation=(
        'Pin an exact version, e.g. "@modelcontextprotocol/server-filesystem@2025.8.21" '
        'or "mcp-server-git==0.6.2", and review changes before upgrading.'
    ),
)
def unpinned_package(server: MCPServer) -> Iterator[str]:
    found = package_spec(server)
    if found is None:
        return
    ecosystem, spec = found
    if is_pinned(ecosystem, spec) is False:
        yield f"{ecosystem} package {spec!r} is not pinned to an exact version"


# --- MCP003: insecure remote transport -----------------------------------------------------

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
_URL_PARTS = re.compile(r"^\s*([A-Za-z][A-Za-z0-9+.-]*)://(?:[^@/?#]*@)?(\[[^\]/?#]*\]?|[^:/?#]*)")


def url_scheme_and_host(url: str) -> tuple[str, str]:
    """Lower-cased (scheme, host); never raises.

    Configs often hold placeholders like http://[SERVER_IP]:8080, which urllib rejects because
    a bracketed host must be an IPv6 address. Fall back to a plain pattern match for those.
    """
    try:
        parts = urlsplit(url.strip())
        return parts.scheme.lower(), (parts.hostname or "").lower()
    except ValueError:
        match = _URL_PARTS.match(url)
        if not match:
            return "", ""
        return match.group(1).lower(), match.group(2).strip("[]").lower()


def url_query(url: str) -> str:
    return url.partition("?")[2].partition("#")[0]


def is_local_host(host: str) -> bool:
    return host in _LOCAL_HOSTS or host.startswith("127.") or host.endswith(".localhost")


@rule(
    id="MCP003",
    title="Remote MCP server over unencrypted connection",
    severity=Severity.HIGH,
    description=(
        "Plain http/ws lets anyone on the network read tool calls and results, steal auth "
        "headers, or inject malicious tool descriptions and responses."
    ),
    remediation="Use an https:// (or wss://) endpoint for any server that is not on localhost.",
)
def insecure_transport(server: MCPServer) -> Iterator[str]:
    if not server.url:
        return
    scheme, host = url_scheme_and_host(server.url)
    if scheme not in ("http", "ws") or is_local_host(host):
        return
    message = f"server at {host} is reached over unencrypted {scheme}://"
    if any(SENSITIVE_NAME.search(name) for name in server.headers):
        message += " and sends credentials in its headers"
    yield message
