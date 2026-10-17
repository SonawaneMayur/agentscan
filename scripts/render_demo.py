"""Render the README terminal screenshot to docs/demo.svg.

Usage (from the repo root): uv run python scripts/render_demo.py
"""

import io
from pathlib import Path

from rich.console import Console

from agentscan.discovery import discover
from agentscan.reporters import render_text
from agentscan.scanner import scan

EXAMPLE = Path("examples/vulnerable")
OUTPUT = Path("docs/demo.svg")


def main() -> None:
    console = Console(
        record=True, width=104, file=io.StringIO(), force_terminal=True, highlight=False
    )
    console.print(f"[dim]$[/] agentscan scan {EXAMPLE}")
    console.print()
    render_text(scan(discover([EXAMPLE], include_global=False)), console)
    OUTPUT.parent.mkdir(exist_ok=True)
    console.save_svg(str(OUTPUT), title="agentscan")
    print(f"wrote {OUTPUT}")


if __name__ == "__main__":
    main()
