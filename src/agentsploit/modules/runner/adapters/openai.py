"""OpenAIAdapter — drives OpenAI Chat Completions with tool use.

Loops until the agent stops calling tools or hits `max_turns`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agentsploit.modules.runner.adapters.base import AgentAdapter
from agentsploit.modules.runner.trace import RunTrace, ToolCall

if TYPE_CHECKING:
    from agentsploit.modules.runner.config import RunnerConfig


class OpenAIAdapter(AgentAdapter):
    """Drive OpenAI Chat Completions until the agent stops calling tools.

    Translates the v0.3 runner shapes (RunnerConfig, MockTool, RunTrace) into
    OpenAI's `chat.completions.create` semantics:
      * `tools` list of `{type: "function", function: {name, description, parameters}}`
      * Response: `choices[0].message` with optional `tool_calls` list
      * tool_call.function.arguments is a JSON STRING (parse before use)
      * Follow-up "tool" role messages need `tool_call_id` + `content`
    """

    async def run(self, config: RunnerConfig, payload: str) -> RunTrace:
        trace = RunTrace(
            provider="openai",
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
            from openai import AsyncOpenAI
        except ImportError as e:  # pragma: no cover
            trace.error = f"openai SDK not installed: {e}"
            trace.finished_at = datetime.now(UTC)
            return trace

        client_kwargs: dict[str, Any] = {"api_key": api_key, "timeout": config.timeout_seconds}
        if config.endpoint:
            client_kwargs["base_url"] = config.endpoint
        client = AsyncOpenAI(**client_kwargs)

        tools_payload: list[dict[str, Any]] = [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema or {"type": "object", "properties": {}},
                },
            }
            for t in config.mock_tools
        ]

        api_messages: list[dict[str, Any]] = []
        if config.system_prompt:
            api_messages.append({"role": "system", "content": config.system_prompt})
        api_messages.append({"role": "user", "content": config.trigger_prompt})

        for _ in range(config.max_turns):
            try:
                response = await client.chat.completions.create(
                    model=config.model,
                    messages=api_messages,  # type: ignore[arg-type]
                    tools=tools_payload,  # type: ignore[arg-type]
                )
            except Exception as e:
                trace.error = f"OpenAI API error: {e}"
                trace.finished_at = datetime.now(UTC)
                return trace

            choice = response.choices[0]
            message = choice.message
            text = message.content or ""

            tool_calls: list[ToolCall] = []
            tool_call_payloads: list[dict[str, Any]] = []

            if message.tool_calls:
                for raw_tc in message.tool_calls:
                    # Only function-typed tool calls have `.function`. Custom-
                    # typed tool calls (an OpenAI variant) carry their own
                    # shape and we don't currently support them.
                    if getattr(raw_tc, "type", None) != "function":
                        continue
                    func = getattr(raw_tc, "function", None)
                    if func is None:
                        continue

                    # OpenAI sends arguments as a JSON string — parse it
                    raw_args = func.arguments or "{}"
                    try:
                        args = json.loads(raw_args)
                    except json.JSONDecodeError:
                        args = {"_raw": raw_args}
                    if not isinstance(args, dict):
                        args = {"_raw": str(args)}

                    tool_calls.append(ToolCall(id=raw_tc.id, name=func.name, arguments=args))
                    tool_call_payloads.append(
                        {
                            "id": raw_tc.id,
                            "type": "function",
                            "function": {"name": func.name, "arguments": raw_args},
                        }
                    )

            trace.add_assistant(text=text, tool_calls=tool_calls)

            if not tool_calls or choice.finish_reason in ("stop", "length"):
                break

            api_messages.append(
                {"role": "assistant", "content": text or None, "tool_calls": tool_call_payloads}
            )

            for call in tool_calls:
                matched = next((t for t in config.mock_tools if t.name == call.name), None)
                tool_output = (
                    matched.render_response(payload, call.arguments)
                    if matched
                    else f"[runner] tool {call.name!r} not registered"
                )
                trace.add_tool_result(call.id, tool_output)
                api_messages.append(
                    {"role": "tool", "tool_call_id": call.id, "content": tool_output}
                )

        trace.finished_at = datetime.now(UTC)
        return trace
