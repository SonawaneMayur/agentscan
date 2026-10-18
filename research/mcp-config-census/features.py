"""Per-server attributes measured by the census, beyond agentscan's rule findings."""

from __future__ import annotations

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
