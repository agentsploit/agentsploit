"""Benign-fixture smoke test - proves the scanner doesn't false-positive.

Every other integration test asserts that AgentSploit *finds* issues in
intentionally-vulnerable fixtures. This one asserts the opposite: against
a well-engineered MCP server, the only thing the scanner should produce
is an INFO inventory finding. Anything else is a false positive worth fixing.
"""

from __future__ import annotations

from pathlib import Path as FsPath

import pytest

from agentsploit.core import Session, Target
from agentsploit.modules.mcp.scanner import MCPScanner

pytestmark = pytest.mark.integration


@pytest.fixture()
def benign_fixture_uri() -> str:
    p = FsPath(__file__).parent.parent / "fixtures" / "benign_mcp" / "server.py"
    return f"stdio://{p}"


async def test_benign_fixture_produces_only_info_findings(
    session: Session, benign_fixture_uri: str
) -> None:
    """Tight bar: only the inventory finding should appear, at INFO severity."""
    target = Target.parse(benign_fixture_uri)
    scanner = MCPScanner()

    async for f in scanner.run(target, session):
        session.add(f)

    non_info = [f for f in session.findings if f.severity.label != "info"]
    assert not non_info, (
        f"benign fixture produced non-INFO findings (false positives): "
        f"{[(f.severity.label, f.check, f.title) for f in non_info]}"
    )

    inventory = [f for f in session.findings if f.check == "mcp/inventory"]
    assert len(inventory) == 1
    assert (
        "3 tools" in inventory[0].title
    )  # acme_add_numbers, acme_format_date, acme_lookup_status_code


async def test_benign_fixture_inventory_finds_three_tools(
    session: Session, benign_fixture_uri: str
) -> None:
    """The inventory should enumerate exactly the 3 benign tools we registered."""
    target = Target.parse(benign_fixture_uri)
    scanner = MCPScanner()
    async for f in scanner.run(target, session):
        session.add(f)

    inventory = next(f for f in session.findings if f.check == "mcp/inventory")
    # Title encodes counts: "3 tools, 0 resources, 0 prompts"
    assert "3 tools" in inventory.title
    assert "0 resources" in inventory.title
    assert "0 prompts" in inventory.title
