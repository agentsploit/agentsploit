"""Unit tests for the HTTP probes.

Probes that need a live HTTP target are tested end-to-end against the
vulnerable HTTP fixture in the integration suite. These unit tests cover the
narrower logic: URI scheme handling, applies_to filtering, etc.
"""

from __future__ import annotations

import pytest

from agentsploit.core.target import Target, TargetType
from agentsploit.modules.mcp.auth import Credentials
from agentsploit.modules.mcp.checks.http_auth_bypass import HTTPAuthBypassProbe
from agentsploit.modules.mcp.checks.http_cors import HTTPCORSProbe
from agentsploit.modules.mcp.checks.http_info_disclosure import HTTPInfoDisclosureProbe
from agentsploit.modules.mcp.checks.http_tls_required import HTTPTLSRequiredProbe
from agentsploit.modules.mcp.client import http_url_from_target


@pytest.mark.parametrize(
    "uri,expected",
    [
        ("http://api.example.com:8080", "http://api.example.com:8080"),
        ("https://api.example.com", "https://api.example.com"),
        ("mcp+http://api.example.com/mcp", "http://api.example.com/mcp"),
        ("mcp+https://api.example.com/mcp", "https://api.example.com/mcp"),
        ("sse://stream.example.com/events", "http://stream.example.com/events"),
        ("mcp+sse://stream.example.com/sse", "http://stream.example.com/sse"),
    ],
)
def test_http_url_normalisation(uri: str, expected: str) -> None:
    target = Target.parse(uri)
    assert http_url_from_target(target) == expected


def test_probes_only_apply_to_http_targets() -> None:
    stdio = Target(uri="stdio://./server.py", type=TargetType.MCP_STDIO)
    http = Target(uri="http://localhost:8000", type=TargetType.MCP_HTTP)
    for probe_cls in (
        HTTPTLSRequiredProbe,
        HTTPInfoDisclosureProbe,
        HTTPCORSProbe,
        HTTPAuthBypassProbe,
    ):
        probe = probe_cls()
        assert probe.applies_to(http)
        assert not probe.applies_to(stdio)


async def test_tls_required_skips_localhost() -> None:
    probe = HTTPTLSRequiredProbe()
    target = Target.parse("http://localhost:8000")
    results = [r async for r in probe.run(target, Credentials())]
    assert results == []


async def test_tls_required_skips_loopback_ip() -> None:
    probe = HTTPTLSRequiredProbe()
    target = Target.parse("http://127.0.0.1:8000")
    results = [r async for r in probe.run(target, Credentials())]
    assert results == []


async def test_tls_required_flags_remote_plain_http() -> None:
    probe = HTTPTLSRequiredProbe()
    target = Target.parse("http://api.example.com")
    results = [r async for r in probe.run(target, Credentials())]
    assert len(results) == 1
    assert "plain HTTP" in results[0].title


async def test_tls_required_skips_https() -> None:
    probe = HTTPTLSRequiredProbe()
    target = Target.parse("https://api.example.com")
    results = [r async for r in probe.run(target, Credentials())]
    assert results == []


async def test_auth_bypass_skipped_without_supplied_credentials() -> None:
    """No baseline → can't tell if 'no auth' is correct or broken. We skip."""
    probe = HTTPAuthBypassProbe()
    target = Target.parse("http://api.example.com:8080")
    results = [r async for r in probe.run(target, Credentials())]
    assert results == []
