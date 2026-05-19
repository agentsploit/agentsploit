"""RunTrace - the full conversation captured during a runner invocation.

Adapter-agnostic: every adapter normalises its provider's transcript shape
into these types so the canary detector and reporter don't need to care.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class UserMessage(BaseModel):
    role: Literal["user"] = "user"
    content: str
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ToolCall(BaseModel):
    """A tool the agent decided to invoke."""

    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ToolResult(BaseModel):
    """The result we returned to the agent for a ToolCall."""

    tool_call_id: str
    content: str
    is_error: bool = False
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AssistantMessage(BaseModel):
    """A single assistant turn - text response + zero or more tool calls."""

    role: Literal["assistant"] = "assistant"
    text: str = ""
    thinking: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))


Message = UserMessage | AssistantMessage


class RunTrace(BaseModel):
    """The full record of one agent run.

    Captured by the adapter, scanned by the CanaryDetector, persisted by the
    Session for audit. Contains everything needed to reproduce the run.
    """

    provider: str
    model: str
    system_prompt: str = ""
    messages: list[Message] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    error: str | None = None

    def add_user(self, content: str) -> None:
        self.messages.append(UserMessage(content=content))

    def add_assistant(
        self,
        text: str = "",
        thinking: str = "",
        tool_calls: list[ToolCall] | None = None,
    ) -> None:
        self.messages.append(
            AssistantMessage(
                text=text,
                thinking=thinking,
                tool_calls=tool_calls or [],
            )
        )

    def add_tool_result(self, tool_call_id: str, content: str, is_error: bool = False) -> None:
        self.tool_results.append(
            ToolResult(tool_call_id=tool_call_id, content=content, is_error=is_error)
        )

    def all_assistant_text(self) -> str:
        """Concatenated text + thinking across every assistant turn."""
        parts: list[str] = []
        for m in self.messages:
            if isinstance(m, AssistantMessage):
                if m.text:
                    parts.append(m.text)
                if m.thinking:
                    parts.append(m.thinking)
        return "\n".join(parts)

    def all_tool_call_args(self) -> str:
        """Concatenated string form of every tool-call arg, across all turns."""
        import json

        parts: list[str] = []
        for m in self.messages:
            if isinstance(m, AssistantMessage):
                for tc in m.tool_calls:
                    parts.append(f"{tc.name}({json.dumps(tc.arguments)})")
        return "\n".join(parts)
