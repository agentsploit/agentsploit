"""HTTP response-header information disclosure probe.

Flags MCP HTTP/SSE servers that leak software version, framework, or stack
information via response headers. These do not directly compromise the server
but materially assist an attacker in finding known-vulnerable versions.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import ClassVar

import httpx

from agentsploit.core.finding import Severity
from agentsploit.core.target import Target, TargetType
from agentsploit.modules.mcp.auth import Credentials
from agentsploit.modules.mcp.checks.base import CheckResult, Probe
from agentsploit.modules.mcp.client import http_url_from_target

_LEAKY_HEADERS: dict[str, str] = {
    "server": "web server software",
    "x-powered-by": "application framework",
    "x-aspnet-version": "ASP.NET version",
    "x-aspnetmvc-version": "ASP.NET MVC version",
    "x-runtime": "runtime version",
    "x-version": "application version",
    "x-generator": "site generator",
}

# Versioned Server headers like "uvicorn/0.30.1" or "nginx/1.25.3"
_VERSION_PATTERN = re.compile(r"[\w.-]+/\d+(?:\.\d+)+")


class HTTPInfoDisclosureProbe(Probe):
    NAME: ClassVar[str] = "http_info_disclosure"
    DEFAULT_SEVERITY: ClassVar[Severity] = Severity.LOW
    APPLIES_TO: ClassVar[tuple[TargetType, ...]] = (
        TargetType.MCP_HTTP,
        TargetType.MCP_SSE,
    )
    REFERENCES: ClassVar[list[str]] = [
        "https://owasp.org/www-project-secure-headers/",
    ]

    async def run(self, target: Target, credentials: Credentials) -> AsyncIterator[CheckResult]:
        url = http_url_from_target(target)

        try:
            async with httpx.AsyncClient(
                verify=credentials.verify_tls,
                timeout=credentials.timeout_seconds,
                follow_redirects=False,
            ) as client:
                resp = await client.get(url, headers=credentials.merged_headers())
        except httpx.HTTPError:
            return

        for header_name, label in _LEAKY_HEADERS.items():
            value = resp.headers.get(header_name)
            if not value:
                continue

            has_version = bool(_VERSION_PATTERN.search(value))
            severity = Severity.LOW if has_version else Severity.INFO

            yield CheckResult(
                severity=severity,
                title=f"Response header {header_name!r} discloses {label}",
                description=(
                    f"The server responded with the header {header_name}: {value!r}. "
                    f"This discloses {label} and assists targeted vulnerability "
                    f"research against the server."
                ),
                remediation=(
                    f"Strip the {header_name!r} header at the reverse proxy or "
                    f"application layer. Most frameworks support disabling these "
                    f"headers in production configuration."
                ),
                target_item=f"http-header:{header_name}",
                evidence_extra={"header": header_name, "value": value},
            )
