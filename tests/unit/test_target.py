"""Target URI parsing tests."""

from __future__ import annotations

import pytest

from agentsploit.core import Target, TargetType


@pytest.mark.parametrize(
    "uri,expected",
    [
        ("stdio://./server.py", TargetType.MCP_STDIO),
        ("http://localhost:8080", TargetType.MCP_HTTP),
        ("https://mcp.example.com", TargetType.MCP_HTTP),
        ("mcp+http://example.com", TargetType.MCP_HTTP),
        ("sse://example.com/events", TargetType.MCP_SSE),
        ("agent+http://agent.example.com", TargetType.AGENT_HTTP),
    ],
)
def test_target_type_inference(uri: str, expected: TargetType) -> None:
    assert TargetType.from_uri(uri) == expected


def test_target_parse_sets_type() -> None:
    t = Target.parse("stdio://./server.py")
    assert t.type == TargetType.MCP_STDIO
    assert t.uri == "stdio://./server.py"


def test_unknown_scheme_raises() -> None:
    with pytest.raises(ValueError, match="Unrecognized target URI scheme"):
        TargetType.from_uri("gopher://example.com")
