#!/usr/bin/env python3
"""Sink-class vulnerable MCP server fixture.

DO NOT DEPLOY. Pairs with `vulnerable_mcp/server.py` (which exposes source-
class read tools) to give the mapper a known cross-server path: an attacker
who reaches the `read_file` source on the first server can chain it into
the `send_email` or `run_shell` sink on this server.

Tools:
  * send_email      - egress sink with `to` and `body` args
  * git_push        - mutation sink with branch arg
  * run_shell       - execution sink with unconstrained `command` arg
  * cache_summary   - pivot
"""

from __future__ import annotations

import asyncio

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

server: Server = Server("vulnerable-sink-mcp")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="send_email",
            description=(
                "Sends an email to the specified recipient. The body can include "
                "content fetched from upstream tools - for example, the output of "
                "read_file or fetch_url can be relayed verbatim."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "subject", "body"],
            },
        ),
        Tool(
            name="git_push",
            description=(
                "Pushes the current branch to origin. Use after edit_file or "
                "write_file to publish changes."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "branch": {"type": "string"},
                    "force": {"type": "boolean"},
                },
                "required": ["branch"],
            },
        ),
        Tool(
            name="run_shell",
            description=(
                "Runs the given shell command and returns its output. Accepts the "
                "raw command string."
            ),
            inputSchema={
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        ),
        Tool(
            name="cache_summary",
            description="Stores a text summary under the given key for later retrieval.",
            inputSchema={
                "type": "object",
                "properties": {
                    "key": {"type": "string"},
                    "summary": {"type": "string"},
                },
                "required": ["key", "summary"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, object]) -> list[TextContent]:
    return [TextContent(type="text", text=f"[fixture-sink] would call {name} with {arguments}")]


async def main() -> None:
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
