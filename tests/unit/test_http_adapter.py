"""GenericHTTPAdapter unit tests with httpx.MockTransport."""

from __future__ import annotations

import json

import httpx
import pytest

from agentsploit.modules.runner.adapters.http import GenericHTTPAdapter
from agentsploit.modules.runner.config import RunnerConfig
from agentsploit.modules.runner.tools import MockTool


def _config(**overrides: object) -> RunnerConfig:
    defaults: dict[str, object] = {
        "provider": "http",
        "model": "test-agent",
        "endpoint": "https://agent.example.com/v1/chat",
        "trigger_prompt": "do the thing",
        "mock_tools": [
            MockTool(
                name="read_document",
                description="reads a document",
                returns_payload=True,
                input_schema={
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                },
            ),
        ],
    }
    defaults.update(overrides)
    return RunnerConfig(**defaults)  # type: ignore[arg-type]


async def test_missing_endpoint_records_error() -> None:
    trace = await GenericHTTPAdapter().run(
        _config(endpoint=None),
        "payload",
    )
    assert trace.error is not None
    assert "endpoint is required" in trace.error


@pytest.mark.asyncio
async def test_full_loop_against_mock_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    """One round-trip: agent calls read_document, gets payload back, then stops."""
    cfg = _config(api_key_env="MY_KEY")
    monkeypatch.setenv("MY_KEY", "tok-xyz")

    seen_requests: list[httpx.Request] = []

    def _handler(req: httpx.Request) -> httpx.Response:
        seen_requests.append(req)
        if len(seen_requests) == 1:
            # Turn 1: agent calls read_document
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "content": "",
                                "tool_calls": [
                                    {
                                        "id": "call_001",
                                        "type": "function",
                                        "function": {
                                            "name": "read_document",
                                            "arguments": json.dumps({"name": "x.pdf"}),
                                        },
                                    }
                                ],
                            },
                            "finish_reason": "tool_calls",
                        }
                    ]
                },
            )
        # Turn 2: agent emits a final text response and stops
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "Done."}, "finish_reason": "stop"}]},
        )

    # Patch httpx.AsyncClient to use our mock transport for any client built
    # inside the adapter. The adapter constructs `httpx.AsyncClient(timeout=...)`
    # so we patch the class to wire in our MockTransport.
    original_init = httpx.AsyncClient.__init__

    def _patched_init(self: httpx.AsyncClient, **kwargs: object) -> None:
        kwargs["transport"] = httpx.MockTransport(_handler)
        original_init(self, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", _patched_init)

    trace = await GenericHTTPAdapter().run(cfg, "the-payload-content")

    assert trace.error is None
    # Two HTTP round-trips: tool call + final response
    assert len(seen_requests) == 2

    # First request should include both the user message and the tools list
    body = json.loads(seen_requests[0].content)
    assert body["model"] == "test-agent"
    assert body["tools"][0]["function"]["name"] == "read_document"
    assert any(m["role"] == "user" for m in body["messages"])

    # Bearer token should be on the request
    assert seen_requests[0].headers.get("Authorization") == "Bearer tok-xyz"

    # The trace should contain the tool call + tool result + final text
    assistant_msgs = [m for m in trace.messages if getattr(m, "role", None) == "assistant"]
    assert len(assistant_msgs) == 2
    assert any(
        tc.name == "read_document" for m in assistant_msgs for tc in getattr(m, "tool_calls", [])
    )


@pytest.mark.asyncio
async def test_5xx_response_recorded_as_error(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _config(api_key_env="MY_KEY")
    monkeypatch.setenv("MY_KEY", "tok-xyz")

    def _handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    original_init = httpx.AsyncClient.__init__

    def _patched_init(self: httpx.AsyncClient, **kwargs: object) -> None:
        kwargs["transport"] = httpx.MockTransport(_handler)
        original_init(self, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", _patched_init)

    trace = await GenericHTTPAdapter().run(cfg, "payload")
    assert trace.error is not None
    assert "500" in trace.error
