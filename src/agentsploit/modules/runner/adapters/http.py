"""GenericHTTPAdapter - POST to a custom agent endpoint with an OpenAI-shaped contract.

Many in-house production agents wrap an LLM behind a custom HTTP endpoint.
Their exact request/response shape varies, but the most common convention
mirrors OpenAI's Chat Completions:

    Request body:
        {
          "messages": [{"role": "user|system|assistant|tool", ...}],
          "tools":    [{"type": "function", "function": {...}}]
        }

    Response body:
        {
          "choices": [{
            "message": {
              "content": "...",
              "tool_calls": [{"id": "...", "function": {"name": "...", "arguments": "..."}}]
            },
            "finish_reason": "stop|tool_calls|length"
          }]
        }

The adapter assumes this shape. For custom shapes, subclass and override
`_build_request_body` / `_parse_response`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import httpx

from agentsploit.modules.runner.adapters.base import AgentAdapter
from agentsploit.modules.runner.trace import RunTrace, ToolCall

if TYPE_CHECKING:
    from agentsploit.modules.runner.config import RunnerConfig
    from agentsploit.modules.runner.watcher import StreamWatcher


class GenericHTTPAdapter(AgentAdapter):
    """Drive a custom HTTP agent endpoint using OpenAI-shaped semantics.

    Streaming note: v1.2's `watcher` parameter is accepted for ABC
    compliance but ignored. Custom HTTP agents don't have a standard
    streaming protocol; if your endpoint supports SSE, subclass this and
    override `run()` to wire the watcher.
    """

    async def run(
        self,
        config: RunnerConfig,
        payload: str,
        *,
        watcher: StreamWatcher | None = None,  # accepted for ABC, unused
    ) -> RunTrace:
        trace = RunTrace(
            provider="http",
            model=config.model,
            system_prompt=config.system_prompt,
        )
        trace.add_user(config.trigger_prompt)

        if not config.endpoint:
            trace.error = "RunnerConfig.endpoint is required for provider=http"
            trace.finished_at = datetime.now(UTC)
            return trace

        try:
            api_key = config.resolve_api_key()
        except ValueError as e:
            trace.error = str(e)
            trace.finished_at = datetime.now(UTC)
            return trace

        headers = self._build_headers(config, api_key)
        tools_payload = self._build_tools_payload(config)

        api_messages: list[dict[str, Any]] = []
        if config.system_prompt:
            api_messages.append({"role": "system", "content": config.system_prompt})
        api_messages.append({"role": "user", "content": config.trigger_prompt})

        async with httpx.AsyncClient(timeout=config.timeout_seconds) as client:
            for _ in range(config.max_turns):
                body = self._build_request_body(api_messages, tools_payload, config)
                try:
                    response = await client.post(config.endpoint, json=body, headers=headers)
                except httpx.HTTPError as e:
                    trace.error = f"HTTP error calling agent endpoint: {e}"
                    trace.finished_at = datetime.now(UTC)
                    return trace

                if response.status_code >= 400:
                    trace.error = (
                        f"Agent endpoint returned {response.status_code}: {response.text[:400]}"
                    )
                    trace.finished_at = datetime.now(UTC)
                    return trace

                try:
                    payload_json = response.json()
                except json.JSONDecodeError as e:
                    trace.error = f"Agent endpoint returned non-JSON: {e}"
                    trace.finished_at = datetime.now(UTC)
                    return trace

                text, tool_calls, finish_reason, raw_assistant_msg = self._parse_response(
                    payload_json
                )

                trace.add_assistant(text=text, tool_calls=tool_calls)

                if not tool_calls or finish_reason in ("stop", "length"):
                    break

                api_messages.append(raw_assistant_msg)

                for tc in tool_calls:
                    matched = next((t for t in config.mock_tools if t.name == tc.name), None)
                    tool_output = (
                        matched.render_response(payload, tc.arguments)
                        if matched
                        else f"[runner] tool {tc.name!r} not registered"
                    )
                    trace.add_tool_result(tc.id, tool_output)
                    api_messages.append(
                        {"role": "tool", "tool_call_id": tc.id, "content": tool_output}
                    )

        trace.finished_at = datetime.now(UTC)
        return trace

    # -------------------------------------------------------- override points

    def _build_headers(self, config: RunnerConfig, api_key: str | None) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "agentsploit/0.9.0",
        }
        headers.update(config.headers)
        if api_key and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {api_key}"
        return headers

    def _build_tools_payload(self, config: RunnerConfig) -> list[dict[str, Any]]:
        return [
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

    def _build_request_body(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        config: RunnerConfig,
    ) -> dict[str, Any]:
        return {
            "model": config.model,
            "messages": messages,
            "tools": tools,
        }

    def _parse_response(
        self, payload: dict[str, Any]
    ) -> tuple[str, list[ToolCall], str | None, dict[str, Any]]:
        """Return (text, tool_calls, finish_reason, raw_assistant_message)."""
        choices = payload.get("choices") or []
        if not choices:
            return "", [], "stop", {"role": "assistant", "content": ""}

        choice = choices[0]
        msg = choice.get("message") or {}
        text = str(msg.get("content") or "")
        finish_reason = choice.get("finish_reason")

        tool_calls: list[ToolCall] = []
        raw_tcs = msg.get("tool_calls") or []
        for tc in raw_tcs:
            func = tc.get("function") or {}
            raw_args = func.get("arguments") or "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            except (json.JSONDecodeError, TypeError):
                args = {"_raw": str(raw_args)}
            if not isinstance(args, dict):
                args = {"_raw": str(args)}

            tool_calls.append(
                ToolCall(
                    id=str(tc.get("id") or "tc"),
                    name=str(func.get("name") or ""),
                    arguments=args,
                )
            )

        return text, tool_calls, finish_reason, msg
