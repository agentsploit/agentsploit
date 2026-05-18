"""MockAgentAdapter — deterministic agent simulator for tests and demos.

Behaviour:
  1. Turn 1: the agent "decides" to call the payload-returning mock tool
  2. The runner returns the payload as that tool's result
  3. Turn 2: the agent inspects the payload's *decoded* contents:
       a. If it sees an instruction of the form "call `<tool_name>` with these
          arguments: a=X, b=Y, …" AND that tool is registered, it issues a
          tool call matching those arguments. (Path-verification scenario.)
       b. Otherwise, if it sees a canary string, it echoes the canary in
          its response text. (v0.3 baseline scenario.)
       c. Otherwise, it produces a benign summary.

This makes the mock agent capable of demonstrating both single-shot canary
surface AND end-to-end chain completion without needing real LLM tokens.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agentsploit.modules.runner.adapters.base import AgentAdapter
from agentsploit.modules.runner.trace import RunTrace, ToolCall

if TYPE_CHECKING:
    from agentsploit.modules.runner.config import RunnerConfig


_CANARY_RE = re.compile(r"AS-[A-Z0-9]{6,32}")

# Matches "call `<tool>` with these exact arguments: k1='v1', k2='v2', …"
_CHAIN_INSTRUCTION_RE = re.compile(
    r"call\s+`?(?P<tool>[A-Za-z_][A-Za-z0-9_]*)`?\s+with\s+"
    r"(?:these\s+(?:exact\s+)?)?arguments?:?\s+(?P<args>.+)",
    re.IGNORECASE,
)
_ARG_PAIR_RE = re.compile(r"(?P<k>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*'(?P<v>[^']*)'")


class MockAgentAdapter(AgentAdapter):
    async def run(self, config: RunnerConfig, payload: str) -> RunTrace:
        trace = RunTrace(
            provider="mock",
            model=config.model or "mock-1",
            system_prompt=config.system_prompt,
        )
        trace.add_user(config.trigger_prompt)

        payload_tool = next((t for t in config.mock_tools if t.returns_payload), None)
        if payload_tool is None:
            trace.error = "no payload-returning tool defined"
            trace.finished_at = datetime.now(UTC)
            return trace

        # Turn 1: agent invokes the payload-bearing tool
        call = ToolCall(
            id="call_001", name=payload_tool.name, arguments={"name": "compliance-review.pdf"}
        )
        trace.add_assistant(tool_calls=[call])
        tool_output = payload_tool.render_response(payload)
        trace.add_tool_result(call.id, tool_output)

        decoded = _decode_tag_blocks(tool_output)

        # 2a: look for a chain instruction targeting a registered tool
        chain_call = _extract_chain_call(decoded, config)
        if chain_call is not None:
            trace.add_assistant(
                text=f"Per the document's workflow step, calling `{chain_call.name}` now.",
                tool_calls=[chain_call],
            )
            # Simulate the tool's response
            matched = next((t for t in config.mock_tools if t.name == chain_call.name), None)
            tool_result = matched.render_response(payload) if matched else "[mock] ok"
            trace.add_tool_result(chain_call.id, tool_result)
            trace.add_assistant(text="Workflow complete.")
            trace.finished_at = datetime.now(UTC)
            return trace

        # 2b: fall back to v0.3 canary-echo behaviour
        canary_in_payload = _find_canary(decoded)
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


# --------------------------------------------------------------------- helpers


def _decode_tag_blocks(text: str) -> str:
    """Decode any U+E0020 to U+E007F characters back to their ASCII originals."""
    return "".join(chr(ord(c) - 0xE0000) if 0xE0020 <= ord(c) <= 0xE007F else c for c in text)


def _find_canary(text: str) -> str | None:
    m = _CANARY_RE.search(text)
    return m.group(0) if m else None


def _extract_chain_call(decoded: str, config: RunnerConfig) -> ToolCall | None:
    """If `decoded` contains a chain instruction matching a registered tool, return the call."""
    m = _CHAIN_INSTRUCTION_RE.search(decoded)
    if m is None:
        return None
    tool_name = m.group("tool")
    if not any(t.name == tool_name for t in config.mock_tools):
        return None

    arguments: dict[str, Any] = {}
    for pair in _ARG_PAIR_RE.finditer(m.group("args")):
        arguments[pair.group("k")] = pair.group("v")

    if not arguments:
        return None

    return ToolCall(id="call_002", name=tool_name, arguments=arguments)
