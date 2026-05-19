"""Base classes for MCP scanner checks.

Two kinds of checks:
  - Check: synchronous, operates on the already-fetched MCPInventory.
           Transport-agnostic - applies to stdio, HTTP, or SSE targets.
  - Probe: asynchronous, opens its own connection to the target.
           Used for HTTP/SSE-only concerns (CORS, auth bypass, headers).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from typing import ClassVar

from agentsploit.core.finding import Finding, Severity
from agentsploit.core.target import Target, TargetType
from agentsploit.modules.mcp.auth import Credentials
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


class _BaseCheck(ABC):
    """Shared metadata + Finding construction for Check and Probe."""

    NAME: ClassVar[str]
    DEFAULT_SEVERITY: ClassVar[Severity] = Severity.MEDIUM
    REFERENCES: ClassVar[list[str]] = []

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


class Check(_BaseCheck):
    """A synchronous rule executed against an already-fetched MCPInventory."""

    @abstractmethod
    def run(self, inventory: MCPInventory) -> Iterator[CheckResult]:
        """Yield zero or more CheckResults for the inventory."""
        ...


class Probe(_BaseCheck):
    """An async check that fans out its own requests to the live target.

    Used for HTTP/SSE-only concerns: CORS, unauth probes, response headers.
    Subclasses set `APPLIES_TO` to a tuple of TargetType values it supports.
    """

    APPLIES_TO: ClassVar[tuple[TargetType, ...]] = ()

    def applies_to(self, target: Target) -> bool:
        return target.type in self.APPLIES_TO

    # Note: this is intentionally NOT `async def`. Subclasses implement it as
    # an async generator (`async def` + `yield`), which type-checkers handle
    # correctly when the abstract signature returns AsyncIterator directly.
    @abstractmethod
    def run(self, target: Target, credentials: Credentials) -> AsyncIterator[CheckResult]:
        """Yield zero or more CheckResults from live probing."""
        ...
