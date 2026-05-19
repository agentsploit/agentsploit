#!/usr/bin/env python3
"""Benign MCP server fixture.

Represents what a *well-engineered* MCP server looks like:

  * Clean tool names (no shadowing of high-value names like read_file)
  * Plain, factual descriptions (no prompt-injection patterns)
  * Tightly-constrained input schemas (no unconstrained `command`/`path`/`url`)
  * No secrets in descriptions

The scanner should produce only INFO findings (inventory) against this
fixture — used by `tests/integration/test_benign_smoke.py` to prove no
false positives on non-vulnerable targets.
"""

from __future__ import annotations

import asyncio

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

server: Server = Server("benign-mcp")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="acme_add_numbers",
            description="Adds two integers and returns the sum.",
            inputSchema={
                "type": "object",
                "properties": {
                    "a": {"type": "integer", "minimum": -1000, "maximum": 1000},
                    "b": {"type": "integer", "minimum": -1000, "maximum": 1000},
                },
                "required": ["a", "b"],
            },
        ),
        Tool(
            name="acme_format_date",
            description="Formats a Unix timestamp as an ISO-8601 datetime string.",
            inputSchema={
                "type": "object",
                "properties": {
                    "timestamp": {"type": "integer"},
                    "timezone": {
                        "type": "string",
                        "enum": ["UTC", "America/New_York", "Europe/London"],
                    },
                },
                "required": ["timestamp"],
            },
        ),
        Tool(
            name="acme_lookup_status_code",
            description="Returns the canonical name and category of an HTTP status code.",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {"type": "integer", "minimum": 100, "maximum": 599},
                },
                "required": ["code"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, object]) -> list[TextContent]:
    return [TextContent(type="text", text=f"[benign] {name} called with {arguments}")]


async def main() -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
