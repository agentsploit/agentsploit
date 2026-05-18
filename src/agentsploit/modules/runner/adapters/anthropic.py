"""AnthropicAdapter — runs the payload through a real Claude with native tool use."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agentsploit.modules.runner.adapters.base import AgentAdapter
from agentsploit.modules.runner.trace import RunTrace, ToolCall

if TYPE_CHECKING:
    from agentsploit.modules.runner.config import RunnerConfig


class AnthropicAdapter(AgentAdapter):
    """Drive Anthropic's Messages API with tool use until the agent stops calling tools."""

    async def run(self, config: RunnerConfig, payload: str) -> RunTrace:
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
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
            }
            for t in config.mock_tools
        ]

        # API conversation state — separate from the trace, which is normalised.
        api_messages: list[dict[str, Any]] = [
            {"role": "user", "content": config.trigger_prompt},
        ]

        payload_tool_name = next(
            (t.name for t in config.mock_tools if t.returns_payload),
            None,
        )

        for _ in range(config.max_turns):
            try:
                # The Anthropic SDK uses strongly-typed TypedDicts for
                # `messages`/`tools`; runtime accepts plain dicts but mypy
                # doesn't see the equivalence.
                response = await client.messages.create(
                    model=config.model,
                    max_tokens=4096,
                    system=config.system_prompt if config.system_prompt else "",
                    messages=api_messages,  # type: ignore[arg-type]
                    tools=tools_payload,  # type: ignore[arg-type]
                )
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

                    matched = next((t for t in config.mock_tools if t.name == tc.name), None)
                    tool_output = (
                        matched.render_response(payload)
                        if matched
                        else f"[runner] tool {tc.name!r} not registered"
                    )
                    trace.add_tool_result(tc.id, tool_output)
                    tool_result_blocks.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": tc.id,
                            "content": tool_output,
                        }
                    )

            trace.add_assistant(
                text="\n".join(text_parts),
                thinking="\n".join(thinking_parts),
                tool_calls=tool_calls,
            )

            stop_reason = getattr(response, "stop_reason", None)
            if not tool_calls or stop_reason == "end_turn":
                break

            api_messages.append({"role": "assistant", "content": assistant_blocks})
            api_messages.append({"role": "user", "content": tool_result_blocks})

            # If the agent isn't calling the payload tool at all, terminate early
            if payload_tool_name and not any(tc.name == payload_tool_name for tc in tool_calls):
                # gave the model the prompt, it called other tools but never the
                # payload-bearing one — that's still a valid trace, but no canary surface
                continue

        trace.finished_at = datetime.now(UTC)
        return trace
