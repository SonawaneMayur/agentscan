from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from rich import box
from rich.console import Console
from rich.table import Table

from agentscan import __version__
from agentscan.discovery import discover
from agentscan.models import Severity
from agentscan.reporters import render_json, render_text
from agentscan.rules import all_rules
from agentscan.scanner import scan


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentscan", description="Security scanner for AI agents and MCP configurations."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="scan MCP config files for security issues")
    scan_cmd.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="config files or project directories (default: current directory plus "
        "user-level configs for Claude, Cursor, VS Code and Windsurf)",
    )
    scan_cmd.add_argument(
        "--no-global",
        action="store_true",
        help="when no paths are given, skip user-level client configs",
    )
    scan_cmd.add_argument("-f", "--format", choices=("text", "json"), default="text")
    scan_cmd.add_argument(
        "--fail-on",
        type=_severity,
        default=Severity.HIGH,
        metavar="SEVERITY",
        help="exit 1 if any finding is at or above this severity (default: high)",
    )

    sub.add_parser("rules", help="list available rules")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    console = Console(highlight=False)

    if args.command == "rules":
        table = Table(box=box.SIMPLE_HEAD)
        table.add_column("ID")
        table.add_column("Severity")
        table.add_column("Title")
        for r in all_rules():
            table.add_row(r.id, str(r.severity), r.title)
        console.print(table)
        return 0

    missing = [p for p in args.paths if not p.exists()]
    if missing:
        for path in missing:
            print(f"agentscan: no such file or directory: {path}", file=sys.stderr)
        return 2

    include_global = not args.paths and not args.no_global
    files = discover(args.paths or [Path.cwd()], include_global=include_global)
    result = scan(files)

    if args.format == "json":
        print(render_json(result))
    else:
        render_text(result, console)

    worst = result.max_severity()
    return 1 if worst is not None and worst >= args.fail_on else 0
