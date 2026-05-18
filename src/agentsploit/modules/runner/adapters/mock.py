"""MockAgentAdapter — deterministic agent simulator for tests and demos.

Behaviour:
  1. Turn 1: the agent "decides" to call the payload-returning mock tool
  2. The runner returns the payload as that tool's result
  3. Turn 2: the agent extracts any canary it can see in the payload and
     echoes it in its response text — simulating a model that obeyed a
     prompt-injection instruction
  4. Run ends

This is the canonical positive-case fixture for canary detection tests.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from agentsploit.modules.runner.adapters.base import AgentAdapter
from agentsploit.modules.runner.trace import RunTrace, ToolCall

if TYPE_CHECKING:
    from agentsploit.modules.runner.config import RunnerConfig


_CANARY_RE = re.compile(r"AS-[A-Z0-9]{6,32}")


class MockAgentAdapter(AgentAdapter):
    async def run(self, config: RunnerConfig, payload: str) -> RunTrace:
        trace = RunTrace(
            provider="mock",
            model=config.model or "mock-1",
            system_prompt=config.system_prompt,
        )
        trace.add_user(config.trigger_prompt)

        # Find the tool that will serve the payload
        payload_tool = next((t for t in config.mock_tools if t.returns_payload), None)
        if payload_tool is None:
            trace.error = "no payload-returning tool defined"
            trace.finished_at = datetime.now(UTC)
            return trace

        # Turn 1: agent invokes the payload tool
        call = ToolCall(
            id="call_001", name=payload_tool.name, arguments={"name": "compliance-review.pdf"}
        )
        trace.add_assistant(tool_calls=[call])
        tool_output = payload_tool.render_response(payload)
        trace.add_tool_result(call.id, tool_output)

        # Turn 2: simulate obedience — extract any canary from the payload
        # (including Unicode tag-block encoded ones) and echo it
        canary_in_payload = _find_canary(tool_output)
        if canary_in_payload:
            response_text = (
                f"I read the document. Per the instructions in the document, "
                f"the canary is: {canary_in_payload}"
            )
        else:
            response_text = "I read the document. It appears to be a routine compliance review."
        trace.add_assistant(text=response_text)

        trace.finished_at = datetime.now(UTC)
        return trace


def _find_canary(text: str) -> str | None:
    """Search for the canary in literal form or in Unicode-tag-block encoded form."""
    m = _CANARY_RE.search(text)
    if m:
        return m.group(0)

    # Decode tag-block characters back to ASCII and try again
    decoded = "".join(chr(ord(c) - 0xE0000) if 0xE0020 <= ord(c) <= 0xE007F else c for c in text)
    m = _CANARY_RE.search(decoded)
    return m.group(0) if m else None
