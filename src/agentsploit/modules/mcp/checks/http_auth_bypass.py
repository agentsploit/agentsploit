"""Unauthenticated access probe.

Sends an MCP `initialize` + `tools/list` JSON-RPC pair to the target with NO
authentication headers. If the server returns a successful response, every
MCP capability is reachable without credentials.

This probe is conservative: it only flags when the unauthenticated request
clearly succeeded (HTTP 200 with a JSON-RPC `result` or SSE stream). 4xx and
401/403 responses are correct behaviour and are not flagged.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import ClassVar

import httpx

from agentsploit.core.finding import Severity
from agentsploit.core.target import Target, TargetType
from agentsploit.modules.mcp.auth import Credentials
from agentsploit.modules.mcp.checks.base import CheckResult, Probe
from agentsploit.modules.mcp.client import http_url_from_target

_INITIALIZE_RPC = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "agentsploit-probe", "version": "0.2.0"},
    },
}


class HTTPAuthBypassProbe(Probe):
    NAME: ClassVar[str] = "http_auth_bypass"
    DEFAULT_SEVERITY: ClassVar[Severity] = Severity.HIGH
    APPLIES_TO: ClassVar[tuple[TargetType, ...]] = (
        TargetType.MCP_HTTP,
        TargetType.MCP_SSE,
    )
    REFERENCES: ClassVar[list[str]] = [
        "https://modelcontextprotocol.io/specification/draft/basic/authorization",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/llm08-excessive-agency",
    ]

    async def run(self, target: Target, credentials: Credentials) -> AsyncIterator[CheckResult]:
        # Only probe if the operator actually supplied credentials. If they
        # didn't, an unauthenticated success isn't informative - we have no
        # baseline to compare against.
        if not credentials.bearer_token and "Authorization" not in credentials.headers:
            return

        url = http_url_from_target(target)
        probe_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": "agentsploit-probe/0.2.0",
        }

        try:
            async with httpx.AsyncClient(
                verify=credentials.verify_tls,
                timeout=credentials.timeout_seconds,
                follow_redirects=False,
            ) as client:
                resp = await client.post(
                    url,
                    headers=probe_headers,
                    content=json.dumps(_INITIALIZE_RPC),
                )
        except httpx.HTTPError:
            return

        if resp.status_code in (401, 403):
            return  # correct: auth required

        if resp.status_code != 200:
            return  # ambiguous - don't flag

        # 200 + a JSON-RPC result means unauthenticated init succeeded
        content_type = resp.headers.get("content-type", "").lower()
        body_text = resp.text[:2000]

        success = False
        if "application/json" in content_type:
            try:
                data = resp.json()
                if isinstance(data, dict) and "result" in data:
                    success = True
            except json.JSONDecodeError:
                pass
        elif "text/event-stream" in content_type:
            # SSE stream - a "data:" line with result text indicates success
            success = '"result"' in body_text

        if not success:
            return

        yield CheckResult(
            severity=Severity.CRITICAL,
            title="MCP server accepts unauthenticated `initialize`",
            description=(
                "The target accepted a JSON-RPC `initialize` request with no "
                "credentials and returned a successful result. Every MCP method "
                "(`tools/list`, `tools/call`, `resources/read`) is therefore "
                "reachable by any unauthenticated client that can reach the "
                "server's network."
            ),
            remediation=(
                "Require authentication for every MCP method. The MCP "
                "authorization spec defines OAuth 2.1 + bearer tokens. Refuse "
                "any JSON-RPC method when the Authorization header is missing "
                "or invalid, returning 401 with a `WWW-Authenticate` challenge."
            ),
            target_item="auth:unauthenticated-initialize",
            evidence_extra={
                "status_code": resp.status_code,
                "content_type": content_type,
                "body_excerpt": body_text[:400],
            },
        )
