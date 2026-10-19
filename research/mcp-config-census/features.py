"""Per-server attributes measured by the census, beyond agentscan's rule findings."""

from __future__ import annotations

import math
import re
from pathlib import Path

from agentscan.models import MCPServer
from agentscan.rules.mcp import is_local_host, is_pinned, package_spec, url_scheme_and_host

# docker run flags that take a value, so the value isn't mistaken for the image name
_DOCKER_VALUE_FLAGS = {
    "-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "--network", "--net",
    "-p", "--publish", "-w", "--workdir", "-u", "--user", "--entrypoint", "-l", "--label",
    "--platform", "--pull", "-m", "--memory", "--cpus", "--add-host", "--cap-add",
    "--cap-drop", "--security-opt", "--device", "-h", "--hostname", "--restart", "--tmpfs",
    "--ulimit", "--dns", "--log-driver", "--log-opt",
}  # fmt: skip

# Filesystem-server roots that expose a whole disk or home directory.
_BROAD_PATH = re.compile(
    r"^(?:/|~/?|\$\{?HOME\}?/?|/Users/[^/]+/?|/home/[^/]+/?|/root/?"
    r"|[A-Za-z]:[\\/]?|[A-Za-z]:[\\/]Users[\\/][^\\/]+[\\/]?)$"
)

_SECRET_KIND = re.compile(r"hardcoded (.+?)(?: \(|$)")

# Words and shapes that mark a value as a placeholder or test value rather than a real secret.
_PLACEHOLDER = re.compile(
    r"x{3,}|\*{3,}|\.{3}|[<>{}]|your|example|placeholder|dummy|fake|test|sample|change_?me"
    r"|replace|insert|here|todo|redacted|demo|mock|null|none|undefined|1234|abcd|0000",
    re.I,
)
_KNOWN_PREFIX = re.compile(
    r"^(?:sk-(?:ant-(?:api\d+-)?|proj-|svcacct-)?|gh[pousr]_|github_pat_|xox[abprs]-|AKIA|ASIA"
    r"|AIza|[rs]k_live_)"
)


EXPECTED_FILENAME = {
    "claude-code": ".mcp.json",
    "cursor": "mcp.json",
    "vscode": "mcp.json",
    "claude-desktop": "claude_desktop_config.json",
    "windsurf": "mcp_config.json",
}
_EXAMPLE_DIR = re.compile(
    r"^(?:tests?|__tests__|testdata|test[-_]data|fixtures?|__fixtures__|examples?|samples?"
    r"|demos?|benchmarks?|templates?|mocks?|__mocks__|docs?|e2e|specs?)$"
    r"|^(?:test|example|sample|fixture|demo|template|mock)[-_]",
    re.I,
)


def path_kind(client: str, path: str) -> str:
    """config | plugin | test_or_example | other_name (e.g. .mcp.json.example, mcp.json.bak)."""
    parts = path.split("/")
    if parts[-1] != EXPECTED_FILENAME.get(client):
        return "other_name"
    dirs = [d.lower() for d in parts[:-1]]
    if any(_EXAMPLE_DIR.match(d) for d in dirs):
        return "test_or_example"
    if any(d in ("plugins", "plugin", ".claude-plugin") for d in dirs):
        return "plugin"
    return "config"


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {c: text.count(c) for c in set(text)}
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def secret_quality(value: str) -> str:
    """Classify a found secret without keeping it: likely_real, placeholder, low_entropy or
    too_short. Used to separate real leaks from documentation and test values."""
    value = value.strip()
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    if _PLACEHOLDER.search(value):
        return "placeholder"
    core = _KNOWN_PREFIX.sub("", value)
    if len(core) < 12:
        return "too_short"
    if len(set(core)) < 8 or shannon_entropy(core) < 3.0:
        return "low_entropy"
    return "likely_real"


def launcher_name(command: str | None) -> str | None:
    if not command:
        return None
    return Path(command.replace("\\", "/")).name.lower().removesuffix(".exe").removesuffix(".cmd")


def package_name(ecosystem: str, spec: str) -> str:
    """Strip version and extras: '@scope/pkg@1.2.3' -> '@scope/pkg', 'pkg[x]==1.0' -> 'pkg'."""
    if ecosystem == "npm":
        if spec.startswith("@"):
            scope, _, rest = spec[1:].partition("/")
            return f"@{scope}/{rest.partition('@')[0]}".lower()
        return spec.partition("@")[0].lower()
    return re.split(r"[=<>!~@\[ ;]", spec, maxsplit=1)[0].lower()


def docker_image(args: list[str]) -> str | None:
    if not args or args[0] != "run":
        return None
    i = 1
    while i < len(args):
        arg = args[i]
        if arg.startswith("-"):
            flag, has_value, _ = arg.partition("=")
            i += 2 if flag in _DOCKER_VALUE_FLAGS and not has_value else 1
            continue
        return arg
    return None


def docker_image_pinned(image: str) -> bool:
    if "@sha256:" in image:
        return True
    last = image.rsplit("/", 1)[-1]
    return ":" in last and last.split(":", 1)[1] != "latest"


def secret_kind(message: str) -> str | None:
    match = _SECRET_KIND.search(message)
    return match.group(1) if match else None


def server_features(server: MCPServer) -> dict:
    launcher = launcher_name(server.command)
    transport = "remote" if server.url else ("stdio" if server.command else "unknown")

    ecosystem = package = pinned = None
    if spec := package_spec(server):
        ecosystem, raw = spec
        result = is_pinned(ecosystem, raw)
        if result is not None:  # skip local paths and git URLs
            package, pinned = package_name(ecosystem, raw), int(result)

    url_scheme = url_local = None
    if server.url:
        scheme, host = url_scheme_and_host(server.url)
        url_scheme, url_local = scheme or None, int(is_local_host(host))

    image_pinned = None
    if launcher == "docker" and (image := docker_image(server.args)):
        image_pinned = int(docker_image_pinned(image))

    broad = None
    if package and "filesystem" in package:
        broad = int(any(_BROAD_PATH.match(arg.strip()) for arg in server.args))

    return {
        "transport": transport,
        "launcher": launcher,
        "ecosystem": ecosystem if package else None,
        "package": package,
        "pinned": pinned,
        "url_scheme": url_scheme,
        "url_local": url_local,
        "n_env": len(server.env),
        "n_headers": len(server.headers),
        "docker_image_pinned": image_pinned,
        "broad_fs_path": broad,
    }
