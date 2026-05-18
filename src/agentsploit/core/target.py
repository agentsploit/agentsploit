"""Target model — what we're attacking, with URI parsing."""

from __future__ import annotations

from enum import StrEnum
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


class TargetType(StrEnum):
    """Supported target types. New transports add a value here."""

    MCP_STDIO = "mcp_stdio"
    MCP_HTTP = "mcp_http"
    MCP_SSE = "mcp_sse"
    AGENT_HTTP = "agent_http"
    AGENT_ANTHROPIC = "agent_anthropic"
    AGENT_OPENAI = "agent_openai"
    AGENT_MOCK = "agent_mock"

    @classmethod
    def from_uri(cls, uri: str) -> TargetType:
        """Infer the target type from a URI scheme."""
        scheme = urlparse(uri).scheme.lower()
        match scheme:
            case "stdio":
                return cls.MCP_STDIO
            case "mcp+http" | "mcp+https":
                return cls.MCP_HTTP
            case "mcp+sse" | "sse":
                return cls.MCP_SSE
            case "agent+http" | "agent+https":
                return cls.AGENT_HTTP
            case "agent+anthropic":
                return cls.AGENT_ANTHROPIC
            case "agent+openai":
                return cls.AGENT_OPENAI
            case "agent+mock":
                return cls.AGENT_MOCK
            case "http" | "https":
                # Default plain http/https to MCP HTTP for convenience
                return cls.MCP_HTTP
            case _:
                raise ValueError(f"Unrecognized target URI scheme: {scheme!r}")


class Target(BaseModel):
    """A target to be scanned. URI semantics depend on the type."""

    uri: str
    type: TargetType
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("uri")
    @classmethod
    def _strip_uri(cls, v: str) -> str:
        return v.strip()

    @classmethod
    def parse(cls, uri: str, **metadata: Any) -> Target:
        """Build a Target by inferring the type from the URI."""
        return cls(uri=uri, type=TargetType.from_uri(uri), metadata=metadata)

    def __str__(self) -> str:
        return self.uri
