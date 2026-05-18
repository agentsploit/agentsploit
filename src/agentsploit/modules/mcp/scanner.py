"""MCP Scanner — connects to an MCP server, enumerates it, runs checks."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import ClassVar

from agentsploit.core.finding import Finding, Severity
from agentsploit.core.module import Category, Module, ModuleMeta
from agentsploit.core.session import Session
from agentsploit.core.target import Target, TargetType
from agentsploit.modules.mcp.checks import ALL_CHECKS
from agentsploit.modules.mcp.client import MCPClientError, inventory
from agentsploit.utils.logging import get_logger

log = get_logger(__name__)


class MCPScanner(Module):
    META: ClassVar[ModuleMeta] = ModuleMeta(
        name="mcp/scanner",
        category=Category.SCANNER,
        description=(
            "Enumerate an MCP server's tools, resources, and prompts; "
            "run all registered checks against the inventory."
        ),
        references=[
            "https://modelcontextprotocol.io/specification",
            "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
        ],
        supported_targets=[TargetType.MCP_STDIO, TargetType.MCP_HTTP, TargetType.MCP_SSE],
        tags=["mcp", "scanner"],
    )

    def __init__(self, check_filter: list[str] | None = None) -> None:
        self.check_filter = set(check_filter) if check_filter else None

    async def run(self, target: Target, session: Session) -> AsyncIterator[Finding]:
        log.info("mcp.scan.start", target=target.uri)

        try:
            inv = await inventory(target)
        except MCPClientError as e:
            yield Finding(
                module=self.META.name,
                check="mcp/transport",
                target=target.uri,
                severity=Severity.INFO,
                title="Failed to enumerate MCP server",
                description=str(e),
                remediation="Verify the target URI and that the server is reachable.",
                tags=["mcp", "transport-error"],
            )
            return

        log.info(
            "mcp.scan.enumerated",
            tools=len(inv.tools),
            resources=len(inv.resources),
            prompts=len(inv.prompts),
        )

        yield Finding(
            module=self.META.name,
            check="mcp/inventory",
            target=target.uri,
            severity=Severity.INFO,
            title=f"Enumerated MCP server ({len(inv.tools)} tools, {len(inv.resources)} resources, {len(inv.prompts)} prompts)",
            description=(
                f"Discovered {len(inv.tools)} tools, {len(inv.resources)} resources, "
                f"and {len(inv.prompts)} prompts on the target MCP server."
            ),
            remediation="Informational — review the inventory and confirm it matches the expected surface.",
            tags=["mcp", "inventory"],
        )

        for check_cls in ALL_CHECKS:
            check = check_cls()
            if self.check_filter and check.NAME not in self.check_filter:
                continue
            log.debug("mcp.check.run", check=check.NAME)
            for result in check.run(inv):
                yield check.to_finding(result, target.uri)

        log.info("mcp.scan.done", target=target.uri)
