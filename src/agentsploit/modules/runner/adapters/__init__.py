"""Agent runtime adapters. Each adapter implements AgentAdapter for one provider."""

from agentsploit.modules.runner.adapters.base import AgentAdapter
from agentsploit.modules.runner.adapters.mock import MockAgentAdapter


def get_adapter(provider: str) -> AgentAdapter:
    """Resolve a provider name to a concrete adapter instance."""
    if provider == "anthropic":
        from agentsploit.modules.runner.adapters.anthropic import AnthropicAdapter

        return AnthropicAdapter()
    if provider == "openai":
        from agentsploit.modules.runner.adapters.openai import OpenAIAdapter

        return OpenAIAdapter()
    if provider == "http":
        from agentsploit.modules.runner.adapters.http import GenericHTTPAdapter

        return GenericHTTPAdapter()
    if provider == "mock":
        return MockAgentAdapter()
    raise ValueError(
        f"No adapter for provider {provider!r}. Supported: anthropic, openai, http, mock."
    )


__all__ = ["AgentAdapter", "MockAgentAdapter", "get_adapter"]
