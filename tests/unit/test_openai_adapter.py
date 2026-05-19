"""OpenAIAdapter unit tests.

Stubs out the openai client by patching AsyncOpenAI's underlying httpx client
with a MockTransport — same approach as the HTTP adapter tests.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from agentsploit.modules.runner.adapters.openai import OpenAIAdapter
from agentsploit.modules.runner.config import RunnerConfig
from agentsploit.modules.runner.tools import MockTool


def _config() -> RunnerConfig:
    return RunnerConfig(
        provider="openai",
        model="gpt-4o",
        api_key_env="OPENAI_API_KEY",
        trigger_prompt="please read x",
        mock_tools=[
            MockTool(
                name="read_document",
                description="reads docs",
                returns_payload=True,
                input_schema={
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            ),
        ],
    )


async def test_missing_api_key_recorded_as_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    trace = await OpenAIAdapter().run(_config(), "payload")
    assert trace.error is not None
    assert "not set" in trace.error


@pytest.mark.asyncio
async def test_full_loop_against_mock_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two-turn loop: tool call → tool result → final text response."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake")

    seen: list[httpx.Request] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if len(seen) == 1:
            return httpx.Response(
                200,
                json=_openai_response(
                    tool_calls=[
                        {
                            "id": "call_001",
                            "type": "function",
                            "function": {
                                "name": "read_document",
                                "arguments": json.dumps({"name": "x.pdf"}),
                            },
                        }
                    ],
                    finish_reason="tool_calls",
                ),
            )
        return httpx.Response(
            200,
            json=_openai_response(content="done.", finish_reason="stop"),
        )

    # AsyncOpenAI builds its own httpx client; patch httpx.AsyncClient to use
    # our mock transport so all the SDK's HTTP calls hit the handler.
    original_init = httpx.AsyncClient.__init__

    def _patched_init(self: httpx.AsyncClient, **kwargs: object) -> None:
        kwargs["transport"] = httpx.MockTransport(_handler)
        original_init(self, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", _patched_init)

    trace = await OpenAIAdapter().run(_config(), "the-payload-content")

    assert trace.error is None, trace.error
    assert len(seen) == 2

    body = json.loads(seen[0].content)
    assert body["model"] == "gpt-4o"
    assert body["tools"][0]["function"]["name"] == "read_document"
    assert any(m["role"] == "user" for m in body["messages"])

    # Bearer auth must be set
    auth = seen[0].headers.get("Authorization")
    assert auth and auth.startswith("Bearer ")


# --------------------------------------------------------------- helpers


def _openai_response(
    *,
    content: str = "",
    tool_calls: list[dict[str, Any]] | None = None,
    finish_reason: str = "stop",
) -> dict[str, Any]:
    """Minimal OpenAI Chat Completions response shape the SDK accepts."""
    msg: dict[str, Any] = {"role": "assistant", "content": content or None}
    if tool_calls:
        msg["tool_calls"] = tool_calls

    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 0,
        "model": "gpt-4o",
        "choices": [
            {
                "index": 0,
                "message": msg,
                "finish_reason": finish_reason,
                "logprobs": None,
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
