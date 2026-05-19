"""MCP Scanner - connects to an MCP server, enumerates it, runs checks + probes."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import ClassVar

from agentsploit.core.finding import Finding, Severity
from agentsploit.core.module import Category, Module, ModuleMeta
from agentsploit.core.session import Session
from agentsploit.core.target import Target, TargetType
from agentsploit.modules.mcp.auth import Credentials
from agentsploit.modules.mcp.checks import ALL_CHECKS, ALL_PROBES
from agentsploit.modules.mcp.client import MCPClientError, inventory
from agentsploit.utils.logging import get_logger

log = get_logger(__name__)


class MCPScanner(Module):
    META: ClassVar[ModuleMeta] = ModuleMeta(
        name="mcp/scanner",
        category=Category.SCANNER,
        description=(
            "Enumerate an MCP server's tools, resources, and prompts; "
            "run inventory checks and (for HTTP/SSE targets) HTTP probes."
        ),
        references=[
            "https://modelcontextprotocol.io/specification",
            "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
        ],
        supported_targets=[TargetType.MCP_STDIO, TargetType.MCP_HTTP, TargetType.MCP_SSE],
        tags=["mcp", "scanner"],
    )

    def __init__(
        self,
        check_filter: list[str] | None = None,
        credentials: Credentials | None = None,
    ) -> None:
        self.check_filter = set(check_filter) if check_filter else None
        self.credentials = credentials or Credentials()

    async def run(self, target: Target, session: Session) -> AsyncIterator[Finding]:
        from agentsploit.modules.mcp.client import MCPInventory

        log.info("mcp.scan.start", target=target.uri)

        # ----- Enumerate via the appropriate MCP transport ---------------------
        inv: MCPInventory | None = None
        try:
            inv = await inventory(target, self.credentials)
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
            # We can still run HTTP probes even if MCP enumeration failed -
            # for example, the server might require auth that we lack, but
            # be open on HTTP-level controls. Continue to probes.

        if inv is not None:
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
                title=(
                    f"Enumerated MCP server ({len(inv.tools)} tools, "
                    f"{len(inv.resources)} resources, {len(inv.prompts)} prompts)"
                ),
                description=(
                    f"Discovered {len(inv.tools)} tools, {len(inv.resources)} resources, "
                    f"and {len(inv.prompts)} prompts on the target MCP server."
                ),
                remediation=(
                    "Informational - review the inventory and confirm it matches "
                    "the expected surface."
                ),
                tags=["mcp", "inventory"],
            )

            # ----- Sync inventory checks ---------------------------------------
            for check_cls in ALL_CHECKS:
                check = check_cls()
                if self.check_filter and check.NAME not in self.check_filter:
                    continue
                log.debug("mcp.check.run", check=check.NAME)
                for result in check.run(inv):
                    yield check.to_finding(result, target.uri)

        # ----- Async HTTP probes (skipped for stdio) ---------------------------
        for probe_cls in ALL_PROBES:
            probe = probe_cls()
            if self.check_filter and probe.NAME not in self.check_filter:
                continue
            if not probe.applies_to(target):
                continue
            log.debug("mcp.probe.run", probe=probe.NAME)
            async for result in probe.run(target, self.credentials):
                yield probe.to_finding(result, target.uri)

        log.info("mcp.scan.done", target=target.uri)
