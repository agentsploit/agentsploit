"""Thin async MCP client wrapper for stdio and HTTP transports."""

from __future__ import annotations

import shlex
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agentsploit.core.target import Target, TargetType


@dataclass
class MCPInventory:
    """The discovered tools/resources/prompts of an MCP server."""

    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    server_info: dict[str, Any] = field(default_factory=dict)


class MCPClientError(RuntimeError):
    """Raised when the underlying MCP transport fails to connect or speak."""


@asynccontextmanager
async def _stdio_session(target: Target) -> AsyncIterator[ClientSession]:
    """Open an MCP session over stdio.

    URI format: stdio://<command-with-args>
        e.g. stdio://./tests/fixtures/vulnerable_mcp/server.py
             stdio://python -m my_mcp_server
    """
    raw = target.uri[len("stdio://") :]
    parts = shlex.split(raw)
    if not parts:
        raise MCPClientError(f"Empty stdio command in URI: {target.uri!r}")

    # If the command looks like a python file, run it under python
    if parts[0].endswith(".py") or "/" in parts[0]:
        command = "python"
        args = parts
    else:
        command = parts[0]
        args = parts[1:]

    params = StdioServerParameters(command=command, args=args, env=None)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


@asynccontextmanager
async def _http_session(target: Target) -> AsyncIterator[ClientSession]:
    """Placeholder for HTTP MCP transport.

    The official MCP Python SDK is iterating on HTTP transports — until that
    API stabilizes in this project, HTTP scans fall back to a raw probe in
    checks that need it.
    """
    raise MCPClientError(
        "HTTP MCP transport will land in v0.2. Use stdio:// for now, or pipe through `mcp-bridge`."
    )
    yield  # pragma: no cover


@asynccontextmanager
async def open_session(target: Target) -> AsyncIterator[ClientSession]:
    if target.type == TargetType.MCP_STDIO:
        async with _stdio_session(target) as s:
            yield s
        return
    if target.type in (TargetType.MCP_HTTP, TargetType.MCP_SSE):
        async with _http_session(target) as s:
            yield s
        return
    raise MCPClientError(f"Unsupported target type for MCP: {target.type}")


async def inventory(target: Target) -> MCPInventory:
    """Connect to the target and enumerate tools, resources, prompts."""
    inv = MCPInventory()
    try:
        async with open_session(target) as session:
            try:
                tools_resp = await session.list_tools()
                inv.tools = [t.model_dump() for t in tools_resp.tools]
            except Exception:
                pass
            try:
                res_resp = await session.list_resources()
                inv.resources = [r.model_dump() for r in res_resp.resources]
            except Exception:
                pass
            try:
                pr_resp = await session.list_prompts()
                inv.prompts = [p.model_dump() for p in pr_resp.prompts]
            except Exception:
                pass
    except Exception as e:
        raise MCPClientError(f"Failed to enumerate MCP server: {e}") from e

    inv.server_info = {"uri": target.uri, "scheme": urlparse(target.uri).scheme}
    return inv
