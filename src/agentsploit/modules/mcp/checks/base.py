"""Base class for MCP scanner checks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from typing import ClassVar

from agentsploit.core.finding import Finding, Severity
from agentsploit.modules.mcp.client import MCPInventory


@dataclass
class CheckResult:
    """Lightweight intermediate that a check yields; the scanner turns it into a Finding."""

    severity: Severity
    title: str
    description: str
    remediation: str
    target_item: str
    evidence_extra: dict[str, object] | None = None


class Check(ABC):
    """A single rule executed against an MCPInventory."""

    NAME: ClassVar[str]
    DEFAULT_SEVERITY: ClassVar[Severity] = Severity.MEDIUM
    REFERENCES: ClassVar[list[str]] = []

    @abstractmethod
    def run(self, inventory: MCPInventory) -> Iterator[CheckResult]:
        """Yield zero or more CheckResults for the inventory."""
        ...

    def to_finding(self, result: CheckResult, target_uri: str) -> Finding:
        from agentsploit.core.finding import Evidence

        evidence = Evidence(extra=result.evidence_extra or {})
        evidence.extra["target_item"] = result.target_item
        return Finding(
            module="mcp/scanner",
            check=self.NAME,
            target=target_uri,
            severity=result.severity,
            title=result.title,
            description=result.description,
            remediation=result.remediation,
            references=self.REFERENCES,
            evidence=evidence,
            tags=["mcp", self.NAME],
        )
