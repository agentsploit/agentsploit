"""TLS-required probe.

Flags MCP HTTP/SSE servers reachable over plain HTTP when they should be
HTTPS-only. Plain HTTP is acceptable for localhost / loopback testing but
never for anything else - MCP traffic includes tool descriptions (which may
contain prompt content) and tool-call results (which may contain sensitive
data).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import ClassVar
from urllib.parse import urlparse

from agentsploit.core.finding import Severity
from agentsploit.core.target import Target, TargetType
from agentsploit.modules.mcp.auth import Credentials
from agentsploit.modules.mcp.checks.base import CheckResult, Probe
from agentsploit.modules.mcp.client import http_url_from_target

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}  # noqa: S104  # noqa: S104 (loopback list, not a bind)


class HTTPTLSRequiredProbe(Probe):
    NAME: ClassVar[str] = "http_tls_required"
    DEFAULT_SEVERITY: ClassVar[Severity] = Severity.HIGH
    APPLIES_TO: ClassVar[tuple[TargetType, ...]] = (
        TargetType.MCP_HTTP,
        TargetType.MCP_SSE,
    )
    REFERENCES: ClassVar[list[str]] = [
        "https://datatracker.ietf.org/doc/html/rfc9110",
    ]

    async def run(self, target: Target, credentials: Credentials) -> AsyncIterator[CheckResult]:
        url = http_url_from_target(target)
        parsed = urlparse(url)

        if parsed.scheme == "https":
            return
        if parsed.hostname and parsed.hostname.lower() in _LOOPBACK_HOSTS:
            return

        yield CheckResult(
            severity=Severity.HIGH,
            title="MCP server reachable over plain HTTP",
            description=(
                f"The target {target.uri!r} is served over plain HTTP, not HTTPS, "
                f"and the host is not localhost. All MCP traffic - including tool "
                f"descriptions, tool-call arguments, and tool-call results - is "
                f"transmitted in cleartext. Any on-path attacker can read or modify "
                f"agent interactions."
            ),
            remediation=(
                "Serve MCP exclusively over HTTPS. Use a valid CA-signed certificate "
                "(Let's Encrypt or your internal PKI). Disable plain-HTTP listeners "
                "entirely; do not 301 from HTTP to HTTPS, refuse the connection."
            ),
            target_item=f"http:{parsed.hostname}:{parsed.port or 80}",
            evidence_extra={"scheme": parsed.scheme, "host": parsed.hostname or ""},
        )
