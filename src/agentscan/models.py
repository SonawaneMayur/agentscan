from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError:
            choices = ", ".join(str(s) for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from {choices})") from None


@dataclass
class MCPServer:
    """One MCP server entry parsed from a client config file."""

    name: str
    source: Path
    client: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    message: str
    server: str
    source: Path
    remediation: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": str(self.severity),
            "message": self.message,
            "server": self.server,
            "source": str(self.source),
            "remediation": self.remediation,
        }
