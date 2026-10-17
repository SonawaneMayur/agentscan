from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from agentscan import __version__
from agentscan.models import Severity
from agentscan.scanner import ScanResult

_STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold white on dark_orange3",
    Severity.MEDIUM: "black on yellow",
    Severity.LOW: "black on cyan",
    Severity.INFO: "black on grey70",
}


def display_path(path: Path) -> str:
    resolved = path.resolve()
    for base, prefix in ((Path.cwd(), ""), (Path.home(), "~/")):
        try:
            return prefix + str(resolved.relative_to(base))
        except ValueError:
            continue
    return str(path)


def render_text(result: ScanResult, console: Console) -> None:
    for path, error in result.errors:
        console.print(f"[red]error[/] {escape(display_path(path))}: {escape(error)}")
    if not result.config_files:
        console.print("[yellow]No MCP config files found.[/]")
        return

    for f in result.findings:
        console.print(
            Text(f" {str(f.severity).upper()} ", style=_STYLES[f.severity]),
            Text(f"{f.rule_id}  {f.title}", style="bold"),
        )
        # A grid keeps wrapped text aligned under its value column instead of the left edge.
        details = Table.grid(padding=(0, 3))
        details.add_column(no_wrap=True)
        details.add_column()
        details.add_row("server", f"{escape(f.server)} [dim]({escape(display_path(f.source))})[/]")
        details.add_row("issue", escape(f.message))
        details.add_row("[dim]fix[/]", f"[dim]{escape(f.remediation)}[/]")
        console.print(Padding(details, (0, 0, 1, 2)))

    scanned = (
        f"Scanned {len(result.servers)} MCP server(s) in {len(result.config_files)} config file(s)"
    )
    if not result.findings:
        console.print(f"[green]✓[/] {scanned}: no issues found")
        return
    counts = Counter(f.severity for f in result.findings)
    summary = ", ".join(f"{counts[s]} {s}" for s in sorted(counts, reverse=True))
    console.print(f"[bold]✗[/] {scanned}: {summary}")


def render_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "tool": "agentscan",
            "version": __version__,
            "config_files": [str(p) for p in result.config_files],
            "servers_scanned": len(result.servers),
            "findings": [f.to_dict() for f in result.findings],
            "errors": [{"file": str(p), "error": e} for p, e in result.errors],
        },
        indent=2,
    )
