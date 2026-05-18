"""End-to-end test: scan the bundled vulnerable MCP server fixture.

This is the canonical proof that AgentSploit detects what it claims to detect.
"""

from __future__ import annotations

import pytest

from agentsploit.core import Session, Target
from agentsploit.modules.mcp.scanner import MCPScanner

pytestmark = pytest.mark.integration


async def test_scanner_against_vulnerable_fixture(
    session: Session, vulnerable_fixture_uri: str
) -> None:
    target = Target.parse(vulnerable_fixture_uri)
    scanner = MCPScanner()

    async for finding in scanner.run(target, session):
        session.add(finding)

    checks_fired = {f.check for f in session.findings}

    # The fixture exposes one of each vulnerability class — every check should fire.
    assert "tool_poisoning" in checks_fired, "expected tool_poisoning on read_secret_file"
    assert "tool_shadowing" in checks_fired, "expected tool_shadowing on read_file"
    assert "prompt_disclosure" in checks_fired, "expected prompt_disclosure on AWS key"
    assert "unsafe_tool_args" in checks_fired, "expected unsafe_tool_args on run_command.command"

    # safe_add should NOT generate findings, but should appear in inventory
    inventory_findings = [f for f in session.findings if f.check == "mcp/inventory"]
    assert len(inventory_findings) == 1
    assert "4 tools" in inventory_findings[0].title
