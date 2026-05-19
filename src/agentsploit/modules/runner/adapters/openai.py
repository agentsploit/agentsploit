"""OpenAIAdapter - drives OpenAI Chat Completions with tool use.

Loops until the agent stops calling tools or hits `max_turns`. v1.2 adds
streaming via `chat.completions.create(stream=True)`: deltas are fed
through a StreamWatcher that can abort mid-response.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agentsploit.modules.runner.adapters.base import AgentAdapter
from agentsploit.modules.runner.trace import RunTrace, ToolCall

if TYPE_CHECKING:
    from agentsploit.modules.runner.config import RunnerConfig
    from agentsploit.modules.runner.watcher import StreamWatcher


class OpenAIAdapter(AgentAdapter):
    """Drive OpenAI Chat Completions until the agent stops calling tools.

    Translates the v0.3 runner shapes (RunnerConfig, MockTool, RunTrace) into
    OpenAI's `chat.completions.create` semantics:
      * `tools` list of `{type: "function", function: {name, description, parameters}}`
      * Response: `choices[0].message` with optional `tool_calls` list
      * tool_call.function.arguments is a JSON STRING (parse before use)
      * Follow-up "tool" role messages need `tool_call_id` + `content`
    """

    async def run(
        self,
        config: RunnerConfig,
        payload: str,
        *,
        watcher: StreamWatcher | None = None,
    ) -> RunTrace:
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
        # v1.4: prepend prior conversation history if supplied. The thread
        # poisoner uses this to resume a poisoned conversation thread.
        api_messages.extend(config.prepopulated_history)
        api_messages.append({"role": "user", "content": config.trigger_prompt})

        use_stream = bool(watcher is not None and config.stream)

        for _ in range(config.max_turns):
            try:
                if use_stream:
                    assert watcher is not None  # narrowed by `use_stream` guard
                    (
                        aborted,
                        text,
                        tool_calls,
                        tool_call_payloads,
                        finish_reason,
                    ) = await self._stream_one_turn(
                        client, config, api_messages, tools_payload, watcher
                    )
                else:
                    response = await client.chat.completions.create(
                        model=config.model,
                        messages=api_messages,  # type: ignore[arg-type]
                        tools=tools_payload,  # type: ignore[arg-type]
                    )
                    aborted = False
                    text, tool_calls, tool_call_payloads, finish_reason = self._parse_full_response(
                        response
                    )
            except Exception as e:
                trace.error = f"OpenAI API error: {e}"
                trace.finished_at = datetime.now(UTC)
                return trace

            trace.add_assistant(text=text, tool_calls=tool_calls)

            if aborted:
                # Stop before invoking any sink tools - the abort point is the
                # safety win of streaming.
                trace.terminated_at_canary = True
                trace.finished_at = datetime.now(UTC)
                return trace

            if not tool_calls or finish_reason in ("stop", "length"):
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

    # ---------------------------------------------------------------- helpers

    def _parse_full_response(
        self, response: Any
    ) -> tuple[str, list[ToolCall], list[dict[str, Any]], str | None]:
        choice = response.choices[0]
        message = choice.message
        text = message.content or ""

        tool_calls: list[ToolCall] = []
        tool_call_payloads: list[dict[str, Any]] = []

        if message.tool_calls:
            for raw_tc in message.tool_calls:
                if getattr(raw_tc, "type", None) != "function":
                    continue
                func = getattr(raw_tc, "function", None)
                if func is None:
                    continue
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
        return text, tool_calls, tool_call_payloads, choice.finish_reason

    # ---------------------------------------------------------------- streaming

    async def _stream_one_turn(
        self,
        client: Any,
        config: RunnerConfig,
        api_messages: list[dict[str, Any]],
        tools_payload: list[dict[str, Any]],
        watcher: StreamWatcher,
    ) -> tuple[bool, str, list[ToolCall], list[dict[str, Any]], str | None]:
        """Stream one turn through the watcher.

        Returns (aborted, text, tool_calls, tool_call_payloads, finish_reason).
        On abort the assembled tool_calls reflect partial input state (whatever
        accumulated before the watcher fired).
        """
        aborted = False
        accumulated_text = ""
        # tool_call_index -> assembled state
        partial_tcs: dict[int, dict[str, str]] = {}
        finish_reason: str | None = None

        stream = await client.chat.completions.create(
            model=config.model,
            messages=api_messages,
            tools=tools_payload,
            stream=True,
        )

        async for chunk in stream:
            if not chunk.choices:
                continue
            choice = chunk.choices[0]
            delta = choice.delta
            if choice.finish_reason:
                finish_reason = choice.finish_reason

            content = getattr(delta, "content", None)
            if content:
                accumulated_text += content
                if watcher.feed_text(content):
                    aborted = True
                    break

            raw_tcs = getattr(delta, "tool_calls", None) or []
            for raw_tc in raw_tcs:
                idx = getattr(raw_tc, "index", 0)
                slot = partial_tcs.setdefault(idx, {"id": "", "name": "", "arguments": ""})
                if getattr(raw_tc, "id", None):
                    slot["id"] = raw_tc.id
                func = getattr(raw_tc, "function", None)
                if func is None:
                    continue
                if getattr(func, "name", None):
                    slot["name"] = func.name
                args_delta = getattr(func, "arguments", None)
                if args_delta:
                    slot["arguments"] += args_delta
                    if slot["name"] and watcher.feed_tool_call_args(slot["name"], args_delta):
                        aborted = True
                        break
            if aborted:
                break

        tool_calls: list[ToolCall] = []
        tool_call_payloads: list[dict[str, Any]] = []
        for slot in partial_tcs.values():
            if not slot["name"]:
                continue
            raw_args = slot["arguments"] or "{}"
            try:
                args = json.loads(raw_args)
            except json.JSONDecodeError:
                args = {"_raw": raw_args}
            if not isinstance(args, dict):
                args = {"_raw": str(args)}
            tool_calls.append(ToolCall(id=slot["id"] or "tc", name=slot["name"], arguments=args))
            tool_call_payloads.append(
                {
                    "id": slot["id"] or "tc",
                    "type": "function",
                    "function": {"name": slot["name"], "arguments": raw_args},
                }
            )

        return aborted, accumulated_text, tool_calls, tool_call_payloads, finish_reason
