"""MockAgentAdapter: deterministic agent simulator for tests and demos.

Behaviour:
  1. Turn 1: the agent "decides" to call the payload-returning mock tool
  2. The runner returns the payload as that tool's result
  3. Turn 2: the agent inspects the payload's *decoded* contents:
       a. If it sees an instruction of the form "call `<tool_name>` with these
          arguments: a=X, b=Y, ..." AND that tool is registered, it issues a
          tool call matching those arguments. (Path-verification scenario.)
       b. Otherwise, if it sees a canary string, it echoes the canary in
          its response text. (v0.3 baseline scenario.)
       c. Otherwise, it produces a benign summary.

v1.2 adds streaming simulation: when a `StreamWatcher` is provided, the
mock chunks its text + tool-call-args output and feeds each chunk through
the watcher. If the watcher returns True the run aborts and the trace's
`terminated_at_canary` flag is set.

This makes the mock a faithful test fixture for both single-shot canary
surface AND end-to-end streaming termination without burning real LLM tokens.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agentsploit.modules.runner.adapters.base import AgentAdapter
from agentsploit.modules.runner.trace import RunTrace, ToolCall

if TYPE_CHECKING:
    from agentsploit.modules.runner.config import RunnerConfig
    from agentsploit.modules.runner.watcher import StreamWatcher


_CANARY_RE = re.compile(r"AS-[A-Z0-9]{6,32}")

# Matches "call `<tool>` with these exact arguments: k1='v1', k2='v2', ..."
_CHAIN_INSTRUCTION_RE = re.compile(
    r"call\s+`?(?P<tool>[A-Za-z_][A-Za-z0-9_]*)`?\s+with\s+"
    r"(?:these\s+(?:exact\s+)?)?arguments?:?\s+(?P<args>.+)",
    re.IGNORECASE,
)
_ARG_PAIR_RE = re.compile(r"(?P<k>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*'(?P<v>[^']*)'")


# Chunk size for simulated streaming. Small enough that a watcher fires
# mid-string for realistic tokenisation behaviour.
_STREAM_CHUNK = 16


class MockAgentAdapter(AgentAdapter):
    async def run(
        self,
        config: RunnerConfig,
        payload: str,
        *,
        watcher: StreamWatcher | None = None,
    ) -> RunTrace:
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

        # Turn 1: agent invokes the payload-bearing tool with realistic args
        call_args = (
            dict(payload_tool.default_args)
            if payload_tool.default_args is not None
            else _default_args_for(payload_tool.input_schema)
        )
        call = ToolCall(id="call_001", name=payload_tool.name, arguments=call_args)
        trace.add_assistant(tool_calls=[call])
        tool_output = payload_tool.render_response(payload, call_args)
        trace.add_tool_result(call.id, tool_output)

        decoded = _decode_tag_blocks(tool_output)

        # 2a: look for a chain instruction targeting a registered tool
        chain_call = _extract_chain_call(decoded, config)
        if chain_call is not None:
            preamble = f"Per the document's workflow step, calling `{chain_call.name}` now."

            # Stream the assistant's preamble text through the watcher
            if watcher is not None and config.stream:
                for chunk in _chunk(preamble, _STREAM_CHUNK):
                    if watcher.feed_text(chunk):
                        # Watcher aborted mid-text; record partial assistant turn
                        partial = _accumulate_prefix(preamble, chunk)
                        trace.add_assistant(text=partial)
                        trace.terminated_at_canary = True
                        trace.finished_at = datetime.now(UTC)
                        return trace

            # Stream the tool-call args (as JSON deltas) through the watcher
            args_json = json.dumps(chain_call.arguments)
            if watcher is not None and config.stream:
                for chunk in _chunk(args_json, _STREAM_CHUNK):
                    if watcher.feed_tool_call_args(chain_call.name, chunk):
                        # Watcher aborted mid-tool-call: emit the assistant
                        # turn with the partial call recorded but DO NOT
                        # produce the tool result. The agent never actually
                        # invoked the sink.
                        trace.add_assistant(text=preamble, tool_calls=[chain_call])
                        trace.terminated_at_canary = True
                        trace.finished_at = datetime.now(UTC)
                        return trace

            # No watcher aborted: continue with the full chain call
            trace.add_assistant(text=preamble, tool_calls=[chain_call])
            matched = next((t for t in config.mock_tools if t.name == chain_call.name), None)
            tool_result = (
                matched.render_response(payload, chain_call.arguments) if matched else "[mock] ok"
            )
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

        # Stream the response through the watcher
        if watcher is not None and config.stream:
            accumulated = ""
            for chunk in _chunk(response_text, _STREAM_CHUNK):
                accumulated += chunk
                if watcher.feed_text(chunk):
                    trace.add_assistant(text=accumulated)
                    trace.terminated_at_canary = True
                    trace.finished_at = datetime.now(UTC)
                    return trace

        trace.add_assistant(text=response_text)
        trace.finished_at = datetime.now(UTC)
        return trace


# --------------------------------------------------------------------- helpers


def _chunk(text: str, size: int) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)] or [""]


def _accumulate_prefix(full: str, last_chunk: str) -> str:
    """Return the substring of `full` that ends with `last_chunk`."""
    idx = full.find(last_chunk)
    if idx < 0:
        return last_chunk
    return full[: idx + len(last_chunk)]


def _default_args_for(schema: dict[str, Any]) -> dict[str, str]:
    """Build a plausible default arg-dict for a tool's input schema.

    Used by the mock adapter when synthesising the agent's first tool call
    (which we hardcode rather than letting the agent decide). Picks the first
    required string arg and fills it with 'compliance-review.pdf'.
    """
    if not isinstance(schema, dict):
        return {"name": "compliance-review.pdf"}
    props = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(props, dict):
        return {"name": "compliance-review.pdf"}
    candidates: list[str] = list(required) if isinstance(required, list) else []
    for k in props:
        if k not in candidates:
            candidates.append(k)
    for k in candidates:
        spec = props.get(k, {})
        if isinstance(spec, dict) and spec.get("type") == "string":
            return {k: "compliance-review.pdf"}
    return {"name": "compliance-review.pdf"}


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
