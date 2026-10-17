from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from agentscan.config import ConfigError, load_servers
from agentscan.models import Finding, MCPServer, Severity
from agentscan.rules import Rule, all_rules


@dataclass
class ScanResult:
    config_files: list[Path] = field(default_factory=list)
    servers: list[MCPServer] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[tuple[Path, str]] = field(default_factory=list)

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)


def scan(config_files: Iterable[Path], rules: list[Rule] | None = None) -> ScanResult:
    rules = all_rules() if rules is None else rules
    result = ScanResult(config_files=list(config_files))
    for path in result.config_files:
        try:
            servers = load_servers(path)
        except ConfigError as e:
            result.errors.append((path, str(e)))
            continue
        result.servers.extend(servers)
        for server in servers:
            for r in rules:
                result.findings.extend(r.run(server))
    result.findings.sort(key=lambda f: (-f.severity, str(f.source), f.server, f.rule_id))
    return result
