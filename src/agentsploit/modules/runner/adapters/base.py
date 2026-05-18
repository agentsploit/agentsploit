"""AgentAdapter — protocol that every provider-specific adapter implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentsploit.modules.runner.config import RunnerConfig
    from agentsploit.modules.runner.trace import RunTrace


class AgentAdapter(ABC):
    """Drive a single agent conversation that delivers the payload.

    Contract:
      - The adapter receives the runner config and the payload string
      - It is responsible for offering the config's `mock_tools` to the agent
      - When the agent calls a tool with `returns_payload=True`, the adapter
        must return `payload` as that tool's output
      - Other mock tools return their `static_response`
      - The adapter loops up to `config.max_turns` assistant turns or until
        the agent stops calling tools, whichever comes first
      - It returns a fully-populated RunTrace
      - Errors are captured in `trace.error`, not raised
    """

    @abstractmethod
    async def run(self, config: RunnerConfig, payload: str) -> RunTrace:
        """Execute one agent conversation and return the trace."""
        ...
