"""MockAgentAdapter unit tests."""

from __future__ import annotations

import pytest

from agentsploit.modules.runner.adapters.mock import MockAgentAdapter
from agentsploit.modules.runner.config import RunnerConfig
from agentsploit.modules.runner.tools import default_document_reader


def _cfg() -> RunnerConfig:
    return RunnerConfig(
        provider="mock",
        model="mock-1",
        trigger_prompt="read doc",
        mock_tools=[default_document_reader()],
    )


@pytest.mark.asyncio
async def test_mock_agent_echoes_canary_present_in_payload() -> None:
    canary = "AS-ABC123456789"
    payload = f"document content with hidden canary {canary} inside"
    trace = await MockAgentAdapter().run(_cfg(), payload)

    assert trace.provider == "mock"
    assert any(canary in m.text for m in trace.messages if hasattr(m, "text"))
    assert any(
        tc.name == "read_document" for m in trace.messages for tc in getattr(m, "tool_calls", [])
    )


@pytest.mark.asyncio
async def test_mock_agent_silent_when_no_canary_in_payload() -> None:
    payload = "just a normal compliance document with nothing suspicious"
    trace = await MockAgentAdapter().run(_cfg(), payload)
    # The agent doesn't fabricate canaries
    assert not any("AS-" in m.text for m in trace.messages if hasattr(m, "text"))


@pytest.mark.asyncio
async def test_mock_agent_decodes_unicode_tag_canaries() -> None:
    canary = "AS-CAFE12345678"
    encoded = "".join(chr(0xE0000 + ord(c)) if 0x20 <= ord(c) <= 0x7E else c for c in canary)
    payload = f"benign cover text {encoded} more text"

    trace = await MockAgentAdapter().run(_cfg(), payload)
    assert any(canary in m.text for m in trace.messages if hasattr(m, "text")), (
        "mock agent should decode unicode-tag-block canaries"
    )
