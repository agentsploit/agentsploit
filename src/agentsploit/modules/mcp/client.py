"""Async MCP client wrapper supporting stdio, HTTP (Streamable), and SSE transports."""

from __future__ import annotations

import shlex
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from agentsploit.core.target import Target, TargetType
from agentsploit.modules.mcp.auth import Credentials


@dataclass
class MCPInventory:
    """The discovered tools/resources/prompts of an MCP server."""

    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    server_info: dict[str, Any] = field(default_factory=dict)


class MCPClientError(RuntimeError):
    """Raised when the underlying MCP transport fails to connect or speak."""


# --------------------------------------------------------------------- URI helpers


def http_url_from_target(target: Target) -> str:
    """Strip the `mcp+` / `sse://` prefixes; return a plain http(s)://… URL.

    Public so HTTP-only checks (CORS, headers, auth-bypass) can probe the
    underlying URL with raw httpx without going through MCP.
    """
    uri = target.uri
    if uri.startswith("mcp+http://"):
        return "http://" + uri[len("mcp+http://") :]
    if uri.startswith("mcp+https://"):
        return "https://" + uri[len("mcp+https://") :]
    if uri.startswith("mcp+sse://"):
        return "http://" + uri[len("mcp+sse://") :]
    if uri.startswith("sse://"):
        return "http://" + uri[len("sse://") :]
    return uri


# --------------------------------------------------------------------- transports


@asynccontextmanager
async def _stdio_session(target: Target) -> AsyncIterator[ClientSession]:
    """Open an MCP session over stdio.

    URI format: stdio://<command-with-args>
        e.g. stdio://./tests/fixtures/vulnerable_mcp/server.py
             stdio://python -m my_mcp_server
    """
    raw = target.uri[len("stdio://") :]
    # If there's no whitespace, treat the whole tail as one argument so that
    # Windows paths with backslashes (`stdio://C:\\mcp\\server.py`) survive.
    # `shlex.split(posix=True)` would otherwise eat the backslashes as escapes.
    if any(c.isspace() for c in raw):
        parts = shlex.split(raw)
    else:
        parts = [raw]
    if not parts:
        raise MCPClientError(f"Empty stdio command in URI: {target.uri!r}")

    # Detect "this is a path to a Python script, not a bare command" so we know
    # to launch it via `python <script>`. Accept both POSIX (`/`) and Windows
    # (`\`) separators so `stdio://C:\\path\\server.py` works on Windows.
    first = parts[0]
    looks_like_path = (
        first.endswith(".py") or "/" in first or "\\" in first or first.startswith(".")
    )
    if looks_like_path:
        command = "python"
        args = parts
    else:
        command = first
        args = parts[1:]

    params = StdioServerParameters(command=command, args=args, env=None)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


@asynccontextmanager
async def _http_session(target: Target, credentials: Credentials) -> AsyncIterator[ClientSession]:
    """Open an MCP session over Streamable HTTP.

    URI format:
        http://host:port[/path]
        https://host:port[/path]
        mcp+http://host:port[/path]
        mcp+https://host:port[/path]
    """
    url = http_url_from_target(target)
    http_client = httpx.AsyncClient(
        headers=credentials.merged_headers(),
        timeout=credentials.timeout_seconds,
        verify=credentials.verify_tls,
    )
    try:
        async with streamable_http_client(url=url, http_client=http_client) as (
            read,
            write,
            _get_session_id,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session
    finally:
        await http_client.aclose()


@asynccontextmanager
async def _sse_session(target: Target, credentials: Credentials) -> AsyncIterator[ClientSession]:
    """Open an MCP session over Server-Sent Events.

    URI format:
        sse://host:port/path
        mcp+sse://host:port/path
    """
    url = http_url_from_target(target)
    async with sse_client(
        url=url,
        headers=credentials.merged_headers(),
        timeout=credentials.timeout_seconds,
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


@asynccontextmanager
async def open_session(
    target: Target, credentials: Credentials | None = None
) -> AsyncIterator[ClientSession]:
    """Open an MCP session for any supported transport."""
    creds = credentials or Credentials()

    if target.type == TargetType.MCP_STDIO:
        async with _stdio_session(target) as s:
            yield s
        return
    if target.type == TargetType.MCP_HTTP:
        async with _http_session(target, creds) as s:
            yield s
        return
    if target.type == TargetType.MCP_SSE:
        async with _sse_session(target, creds) as s:
            yield s
        return
    raise MCPClientError(f"Unsupported target type for MCP: {target.type}")


# --------------------------------------------------------------------- inventory


async def inventory(target: Target, credentials: Credentials | None = None) -> MCPInventory:
    """Connect to the target and enumerate tools, resources, prompts."""
    inv = MCPInventory()
    try:
        async with open_session(target, credentials) as session:
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
