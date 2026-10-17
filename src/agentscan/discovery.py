"""Find MCP config files on disk."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build"}

# Config files a project can check in, relative to any directory.
PROJECT_CONFIGS = (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".vscode/settings.json")


def global_config_paths(home: Path | None = None) -> list[Path]:
    """User-level MCP configs for common clients that exist on this machine."""
    home = home or Path.home()
    candidates = [
        home / "Library/Application Support/Claude/claude_desktop_config.json",
        home / ".config/Claude/claude_desktop_config.json",
        home / "AppData/Roaming/Claude/claude_desktop_config.json",
        home / ".claude.json",
        home / ".cursor/mcp.json",
        home / ".codeium/windsurf/mcp_config.json",
        home / "Library/Application Support/Code/User/mcp.json",
        home / ".config/Code/User/mcp.json",
    ]
    return [p for p in candidates if p.is_file()]


def find_project_configs(root: Path) -> list[Path]:
    found = []
    for dirpath, dirnames, _ in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        base = Path(dirpath)
        found.extend(base / rel for rel in PROJECT_CONFIGS if (base / rel).is_file())
    return found


def discover(paths: Iterable[Path], include_global: bool) -> list[Path]:
    """Expand directories into config files, dropping duplicates."""
    candidates = global_config_paths() if include_global else []
    for path in paths:
        candidates.extend(find_project_configs(path) if path.is_dir() else [path])

    seen: set[Path] = set()
    unique = []
    for path in candidates:
        key = path.resolve()
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique
