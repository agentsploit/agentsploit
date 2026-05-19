"""AnthropicAdapter: drives Claude with native tool use, with optional streaming."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agentsploit.modules.runner.adapters.base import AgentAdapter
from agentsploit.modules.runner.trace import RunTrace, ToolCall

if TYPE_CHECKING:
    from agentsploit.modules.runner.config import RunnerConfig
    from agentsploit.modules.runner.watcher import StreamWatcher


class AnthropicAdapter(AgentAdapter):
    """Drive Anthropic's Messages API with tool use until the agent stops.

    v1.2: when a `watcher` is provided and `config.stream` is True, use
    `client.messages.stream(...)`. The streaming SDK exposes incremental
    events for text deltas, thinking deltas, and tool-use input deltas;
    we feed each to the watcher and abort if it returns True.
    """

    async def run(
        self,
        config: RunnerConfig,
        payload: str,
        *,
        watcher: StreamWatcher | None = None,
    ) -> RunTrace:
        trace = RunTrace(
            provider="anthropic",
            model=config.model,
            system_prompt=config.system_prompt,
        )
        trace.add_user(config.trigger_prompt)

        try:
            api_key = config.resolve_api_key()
        except ValueError as e:
            trace.error = str(e)
            trace.finished_at = datetime.now(UTC)
            return trace

        try:
            from anthropic import AsyncAnthropic
        except ImportError as e:  # pragma: no cover
            trace.error = f"anthropic SDK not installed: {e}"
            trace.finished_at = datetime.now(UTC)
            return trace

        client = AsyncAnthropic(api_key=api_key, timeout=config.timeout_seconds)

        tools_payload: list[dict[str, Any]] = [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema}
            for t in config.mock_tools
        ]
        # v1.4: prepend prior conversation history if supplied. The thread
        # poisoner uses this to resume a poisoned conversation thread.
        # Anthropic doesn't accept `system` role inside `messages`; strip them
        # (the system_prompt field carries that role).
        api_messages: list[dict[str, Any]] = [
            m for m in config.prepopulated_history if m.get("role") != "system"
        ]
        api_messages.append({"role": "user", "content": config.trigger_prompt})
        payload_tool_name = next((t.name for t in config.mock_tools if t.returns_payload), None)

        use_stream = bool(watcher is not None and config.stream)

        for _ in range(config.max_turns):
            try:
                if use_stream:
                    assert watcher is not None  # narrowed by `use_stream` guard
                    aborted, response = await self._stream_one_turn(
                        client, config, api_messages, tools_payload, watcher
                    )
                else:
                    response = await client.messages.create(
                        model=config.model,
                        max_tokens=4096,
                        system=config.system_prompt if config.system_prompt else "",
                        messages=api_messages,  # type: ignore[arg-type]
                        tools=tools_payload,  # type: ignore[arg-type]
                    )
                    aborted = False
            except Exception as e:
                trace.error = f"Anthropic API error: {e}"
                trace.finished_at = datetime.now(UTC)
                return trace

            text_parts: list[str] = []
            thinking_parts: list[str] = []
            tool_calls: list[ToolCall] = []
            assistant_blocks: list[dict[str, Any]] = []
            tool_result_blocks: list[dict[str, Any]] = []

            for block in response.content:
                block_dict = block.model_dump() if hasattr(block, "model_dump") else dict(block)
                btype = block_dict.get("type")
                assistant_blocks.append(block_dict)

                if btype == "text":
                    text_parts.append(block_dict.get("text", ""))
                elif btype == "thinking":
                    thinking_parts.append(block_dict.get("thinking", ""))
                elif btype == "tool_use":
                    tc = ToolCall(
                        id=block_dict.get("id", "unknown"),
                        name=block_dict.get("name", ""),
                        arguments=block_dict.get("input", {}) or {},
                    )
                    tool_calls.append(tc)

                    # When the run aborted on a tool-call args canary, DO NOT
                    # invoke the matched tool: the whole point of streaming
                    # safety is to stop before the sink actually fires.
                    if aborted:
                        continue

                    matched = next((t for t in config.mock_tools if t.name == tc.name), None)
                    tool_output = (
                        matched.render_response(payload, tc.arguments)
                        if matched
                        else f"[runner] tool {tc.name!r} not registered"
                    )
                    trace.add_tool_result(tc.id, tool_output)
                    tool_result_blocks.append(
                        {"type": "tool_result", "tool_use_id": tc.id, "content": tool_output}
                    )

            trace.add_assistant(
                text="\n".join(text_parts),
                thinking="\n".join(thinking_parts),
                tool_calls=tool_calls,
            )

            if aborted:
                trace.terminated_at_canary = True
                trace.finished_at = datetime.now(UTC)
                return trace

            stop_reason = getattr(response, "stop_reason", None)
            if not tool_calls or stop_reason == "end_turn":
                break

            api_messages.append({"role": "assistant", "content": assistant_blocks})
            api_messages.append({"role": "user", "content": tool_result_blocks})

            if payload_tool_name and not any(tc.name == payload_tool_name for tc in tool_calls):
                continue

        trace.finished_at = datetime.now(UTC)
        return trace

    # ---------------------------------------------------------------- streaming

    async def _stream_one_turn(
        self,
        client: Any,
        config: RunnerConfig,
        api_messages: list[dict[str, Any]],
        tools_payload: list[dict[str, Any]],
        watcher: StreamWatcher,
    ) -> tuple[bool, Any]:
        """Stream one turn through the watcher. Returns (aborted, response).

        `response` is a synthetic object with `.content` and `.stop_reason`
        attributes shaped like the non-streaming response, so the caller's
        block-handling code is unchanged.
        """
        aborted = False
        # Map tool-use index -> (id, name, accumulated_input_json)
        tool_blocks: dict[int, dict[str, str]] = {}

        async with client.messages.stream(
            model=config.model,
            max_tokens=4096,
            system=config.system_prompt if config.system_prompt else "",
            messages=api_messages,
            tools=tools_payload,
        ) as stream:
            async for event in stream:
                etype = getattr(event, "type", None)

                if etype == "content_block_start":
                    block = getattr(event, "content_block", None)
                    if getattr(block, "type", None) == "tool_use":
                        idx = getattr(event, "index", 0)
                        tool_blocks[idx] = {
                            "id": getattr(block, "id", "unknown"),
                            "name": getattr(block, "name", ""),
                            "input_json": "",
                        }

                elif etype == "content_block_delta":
                    delta = getattr(event, "delta", None)
                    dtype = getattr(delta, "type", None)
                    if dtype == "text_delta":
                        text = getattr(delta, "text", "")
                        if watcher.feed_text(text):
                            aborted = True
                            break
                    elif dtype == "thinking_delta":
                        thinking = getattr(delta, "thinking", "")
                        if watcher.feed_thinking(thinking):
                            aborted = True
                            break
                    elif dtype == "input_json_delta":
                        partial = getattr(delta, "partial_json", "")
                        idx = getattr(event, "index", 0)
                        block = tool_blocks.get(idx)
                        if block is not None:
                            block["input_json"] += partial
                            if watcher.feed_tool_call_args(block["name"], partial):
                                aborted = True
                                break

            # Whether we aborted or not, the SDK can synthesise the final
            # message snapshot - which gives us the same `.content` shape the
            # non-streaming path uses.
            if aborted:
                try:
                    response = stream.current_message_snapshot
                except Exception:  # pragma: no cover
                    response = await stream.get_final_message()
            else:
                response = await stream.get_final_message()

        return aborted, response
