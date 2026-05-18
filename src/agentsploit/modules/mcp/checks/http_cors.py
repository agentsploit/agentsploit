"""CORS misconfiguration probe.

MCP servers should NOT serve cross-origin requests from arbitrary web origins
— a browser running a malicious page could otherwise make an MCP user's
session perform tool calls without their knowledge. This probe sends a
preflight from an attacker-controlled origin and inspects the CORS headers.

Severity guidance:
  - `Access-Control-Allow-Origin: *` with credentials → CRITICAL
  - `Access-Control-Allow-Origin` reflects the Origin verbatim → HIGH
  - `Access-Control-Allow-Origin: *` without credentials → MEDIUM
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import ClassVar

import httpx

from agentsploit.core.finding import Severity
from agentsploit.core.target import Target, TargetType
from agentsploit.modules.mcp.auth import Credentials
from agentsploit.modules.mcp.checks.base import CheckResult, Probe
from agentsploit.modules.mcp.client import http_url_from_target

_PROBE_ORIGIN = "https://evil.example.com"


class HTTPCORSProbe(Probe):
    NAME: ClassVar[str] = "http_cors"
    DEFAULT_SEVERITY: ClassVar[Severity] = Severity.HIGH
    APPLIES_TO: ClassVar[tuple[TargetType, ...]] = (
        TargetType.MCP_HTTP,
        TargetType.MCP_SSE,
    )
    REFERENCES: ClassVar[list[str]] = [
        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/07-Test_Cross_Origin_Resource_Sharing",
    ]

    async def run(self, target: Target, credentials: Credentials) -> AsyncIterator[CheckResult]:
        url = http_url_from_target(target)
        probe_headers = {
            **credentials.merged_headers(),
            "Origin": _PROBE_ORIGIN,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type, authorization",
        }

        try:
            async with httpx.AsyncClient(
                verify=credentials.verify_tls,
                timeout=credentials.timeout_seconds,
                follow_redirects=False,
            ) as client:
                resp = await client.options(url, headers=probe_headers)
        except httpx.HTTPError:
            return

        allow_origin = resp.headers.get("access-control-allow-origin")
        allow_credentials = (
            resp.headers.get("access-control-allow-credentials", "").lower() == "true"
        )

        if not allow_origin:
            return

        if allow_origin == "*" and allow_credentials:
            yield CheckResult(
                severity=Severity.CRITICAL,
                title="CORS allows wildcard origin AND credentials",
                description=(
                    "The server returned `Access-Control-Allow-Origin: *` together "
                    "with `Access-Control-Allow-Credentials: true`. This combination "
                    "is forbidden by the CORS specification and, when accepted by a "
                    "browser, allows arbitrary cross-origin sites to perform "
                    "authenticated requests against this MCP endpoint."
                ),
                remediation=(
                    "Never return a wildcard ACAO with credentials. Set an explicit "
                    "allowlist of origins, or disable CORS for the MCP endpoint and "
                    "require server-to-server callers."
                ),
                target_item="cors:wildcard-with-credentials",
                evidence_extra={"allow_origin": allow_origin, "allow_credentials": True},
            )
            return

        if allow_origin == _PROBE_ORIGIN:
            yield CheckResult(
                severity=Severity.HIGH,
                title="CORS reflects arbitrary origin",
                description=(
                    f"The server reflected the attacker-controlled origin "
                    f"{_PROBE_ORIGIN!r} back as `Access-Control-Allow-Origin`. "
                    f"Combined with credentials, this is equivalent to disabling "
                    f"same-origin policy for authenticated callers."
                ),
                remediation=(
                    "Validate the Origin header against a static allowlist before "
                    "echoing it back. Never reflect arbitrary origins."
                ),
                target_item="cors:origin-reflection",
                evidence_extra={
                    "probe_origin": _PROBE_ORIGIN,
                    "allow_origin": allow_origin,
                    "allow_credentials": allow_credentials,
                },
            )
            return

        if allow_origin == "*":
            yield CheckResult(
                severity=Severity.MEDIUM,
                title="CORS allows wildcard origin",
                description=(
                    "The server returns `Access-Control-Allow-Origin: *`. Without "
                    "credentials this is normally safe, but for an MCP server it "
                    "still permits unauthenticated cross-origin reads. Combined "
                    "with any future change that adds credentials, this becomes "
                    "exploitable."
                ),
                remediation=("Set an explicit origin allowlist for the MCP endpoint."),
                target_item="cors:wildcard",
                evidence_extra={"allow_origin": "*"},
            )
