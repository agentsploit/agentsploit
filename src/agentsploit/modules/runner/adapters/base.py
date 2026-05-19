"""AgentAdapter: protocol that every provider-specific adapter implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentsploit.modules.runner.config import RunnerConfig
    from agentsploit.modules.runner.trace import RunTrace
    from agentsploit.modules.runner.watcher import StreamWatcher


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

    Streaming contract (v1.2+):
      - When `watcher` is provided AND `config.stream` is True, the adapter
        SHOULD stream the agent's output and feed deltas to the watcher
        (text via on_text, thinking via on_thinking, tool-call args via
        on_tool_call_args)
      - If any watcher method returns True, the adapter MUST abort the
        stream as soon as possible and set `trace.terminated_at_canary = True`
      - Adapters that don't support streaming (e.g. HTTP without SSE) may
        ignore the watcher and run to completion; behaviour is identical to
        v0.3-v1.1
    """

    @abstractmethod
    async def run(
        self,
        config: RunnerConfig,
        payload: str,
        *,
        watcher: StreamWatcher | None = None,
    ) -> RunTrace:
        """Execute one agent conversation and return the trace."""
        ...
