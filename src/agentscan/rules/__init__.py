"""Rule registry. Each rule is a generator that yields one message per problem it finds."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from agentscan.models import Finding, MCPServer, Severity

Check = Callable[[MCPServer], Iterator[str]]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    check: Check

    def run(self, server: MCPServer) -> list[Finding]:
        return [
            Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                message=message,
                server=server.name,
                source=server.source,
                remediation=self.remediation,
            )
            for message in self.check(server)
        ]


_REGISTRY: dict[str, Rule] = {}


def rule(
    *, id: str, title: str, severity: Severity, description: str, remediation: str
) -> Callable[[Check], Check]:
    def register(check: Check) -> Check:
        if id in _REGISTRY:
            raise ValueError(f"duplicate rule id {id}")
        _REGISTRY[id] = Rule(id, title, severity, description, remediation, check)
        return check

    return register


def all_rules() -> list[Rule]:
    from agentscan.rules import mcp  # noqa: F401  (importing registers the rules)

    return sorted(_REGISTRY.values(), key=lambda r: r.id)
