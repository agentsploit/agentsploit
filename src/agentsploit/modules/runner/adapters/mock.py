"""MockAgentAdapter: deterministic agent simulator for tests and demos.

Behaviour:
  1. If `config.prepopulated_history` contains a chain instruction (v1.4),
     the agent obeys it directly on the trigger turn. Models thread
     poisoning, where the malicious instruction is in the agent's own
     conversation history rather than fetched from a tool.
  2. Otherwise, falls through to the v0.3 pattern:
       a. Turn 1: invoke the payload-bearing mock tool
       b. The runner returns the payload as the tool's result
       c. Turn 2: if the decoded result contains a chain instruction
          targeting a registered tool, issue that call. (Path verification,
          memory poisoning, RAG poisoning.)
       d. Otherwise, if the result contains a canary, echo it in text.
       e. Otherwise, produce a benign summary.

v1.2 streaming applies to both pathways: when a watcher is provided, the
mock chunks its output and the watcher can abort mid-stream.
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
_CHAIN_INSTRUCTION_RE = re.compile(
    r"call\s+`?(?P<tool>[A-Za-z_][A-Za-z0-9_]*)`?\s+with\s+"
    r"(?:these\s+(?:exact\s+)?)?arguments?:?\s+(?P<args>.+)",
    re.IGNORECASE,
)
_ARG_PAIR_RE = re.compile(r"(?P<k>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*'(?P<v>[^']*)'")

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

        history_text = _flatten_history(config.prepopulated_history)
        history_chain = (
            _extract_chain_call(_decode_tag_blocks(history_text), config) if history_text else None
        )

        # v1.4 thread-poisoning path: the chain instruction is in the prior
        # conversation history. Agent obeys it on the trigger turn without
        # needing a payload-returning tool.
        if history_chain is not None:
            return await self._emit_chain_call(trace, history_chain, payload, config, watcher)

        payload_tool = next((t for t in config.mock_tools if t.returns_payload), None)
        if payload_tool is None:
            # No payload tool and no history-based chain instruction: just
            # respond benignly and return.
            trace.add_assistant(text="No actionable input. Idle.")
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
        chain_call = _extract_chain_call(decoded, config)

        if chain_call is not None:
            return await self._emit_chain_call(trace, chain_call, payload, config, watcher)

        # Fallback: canary-echo behaviour (v0.3 baseline)
        canary_in_payload = _find_canary(decoded)
        if canary_in_payload:
            response_text = (
                f"I read the document. Per the instructions in the document, "
                f"the canary is: {canary_in_payload}"
            )
        else:
            response_text = "I read the document. It appears to be a routine compliance review."

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

    async def _emit_chain_call(
        self,
        trace: RunTrace,
        chain_call: ToolCall,
        payload: str,
        config: RunnerConfig,
        watcher: StreamWatcher | None,
    ) -> RunTrace:
        """Issue a chain-call (and optionally stream it through the watcher)."""
        preamble = f"Per the prior workflow step, calling `{chain_call.name}` now."

        if watcher is not None and config.stream:
            for chunk in _chunk(preamble, _STREAM_CHUNK):
                if watcher.feed_text(chunk):
                    partial = _accumulate_prefix(preamble, chunk)
                    trace.add_assistant(text=partial)
                    trace.terminated_at_canary = True
                    trace.finished_at = datetime.now(UTC)
                    return trace

            args_json = json.dumps(chain_call.arguments)
            for chunk in _chunk(args_json, _STREAM_CHUNK):
                if watcher.feed_tool_call_args(chain_call.name, chunk):
                    trace.add_assistant(text=preamble, tool_calls=[chain_call])
                    trace.terminated_at_canary = True
                    trace.finished_at = datetime.now(UTC)
                    return trace

        trace.add_assistant(text=preamble, tool_calls=[chain_call])
        matched = next((t for t in config.mock_tools if t.name == chain_call.name), None)
        tool_result = (
            matched.render_response(payload, chain_call.arguments) if matched else "[mock] ok"
        )
        trace.add_tool_result(chain_call.id, tool_result)
        trace.add_assistant(text="Workflow complete.")
        trace.finished_at = datetime.now(UTC)
        return trace


# --------------------------------------------------------------------- helpers


def _flatten_history(history: list[dict[str, Any]]) -> str:
    """Concatenate the textual content of every history entry."""
    parts: list[str] = []
    for entry in history:
        content = entry.get("content")
        if isinstance(content, str):
            parts.append(content)
    return "\n".join(parts)


def _chunk(text: str, size: int) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)] or [""]


def _accumulate_prefix(full: str, last_chunk: str) -> str:
    idx = full.find(last_chunk)
    if idx < 0:
        return last_chunk
    return full[: idx + len(last_chunk)]


def _default_args_for(schema: dict[str, Any]) -> dict[str, str]:
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
    return "".join(chr(ord(c) - 0xE0000) if 0xE0020 <= ord(c) <= 0xE007F else c for c in text)


def _find_canary(text: str) -> str | None:
    m = _CANARY_RE.search(text)
    return m.group(0) if m else None


def _extract_chain_call(decoded: str, config: RunnerConfig) -> ToolCall | None:
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
