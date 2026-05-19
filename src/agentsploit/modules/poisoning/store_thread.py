"""ConversationThread + ThreadStore: the medium for v1.4 thread poisoning.

Unlike v0.8 (key-value note store) and v1.1 (vector store), the medium
here is the conversation history itself. An attacker controls one turn
in a shared thread; the agent treats that turn as part of its own
trusted context and acts on it in a later turn.

Most realistic against:
  - OpenAI Assistants threads (persistent thread IDs)
  - Customer-support chatbots with multi-message state
  - Multi-tenant chat platforms where users share session context
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, Field


class ThreadMessage(BaseModel):
    """One message in a conversation thread.

    Mirrors the v0.3 RunTrace message shape but lives apart from a run so
    it can be shared across multiple agent invocations (which is the
    point of thread poisoning).
    """

    role: Literal["user", "assistant", "system", "tool"]
    content: str = ""
    name: str | None = None
    """Author identity for `user`/`tool` roles. Useful for multi-tenant
    chat platforms where messages from different users mix in one thread."""
    tool_call_id: str | None = None
    """Set on tool-result messages (role=tool)."""
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    """OpenAI-shaped tool-call list on assistant messages."""


class ConversationThread(BaseModel):
    """Ordered sequence of messages persisting across agent invocations."""

    thread_id: str
    messages: list[ThreadMessage] = Field(default_factory=list)

    def append(self, msg: ThreadMessage) -> None:
        self.messages.append(msg)

    def add_user(self, content: str, name: str | None = None) -> None:
        self.append(ThreadMessage(role="user", content=content, name=name))

    def add_assistant(self, content: str) -> None:
        self.append(ThreadMessage(role="assistant", content=content))

    def to_api_messages(self) -> list[dict[str, Any]]:
        """Convert to the OpenAI/Anthropic-friendly dict shape adapters use."""
        out: list[dict[str, Any]] = []
        for m in self.messages:
            entry: dict[str, Any] = {"role": m.role, "content": m.content}
            if m.name:
                entry["name"] = m.name
            if m.tool_call_id:
                entry["tool_call_id"] = m.tool_call_id
            if m.tool_calls:
                entry["tool_calls"] = m.tool_calls
            out.append(entry)
        return out


@dataclass
class ThreadStore:
    """Maps thread_id -> ConversationThread.

    Counters are tracked for evidence the same way v0.8's note store does:
    if `appends` == 0 the attacker setup failed; if `reads` == 0 the victim
    never resumed the thread.
    """

    threads: dict[str, ConversationThread] = field(default_factory=dict)
    appends: int = 0
    reads: int = 0

    def get_or_create(self, thread_id: str) -> ConversationThread:
        if thread_id not in self.threads:
            self.threads[thread_id] = ConversationThread(thread_id=thread_id)
        return self.threads[thread_id]

    def append_message(self, thread_id: str, msg: ThreadMessage) -> None:
        self.get_or_create(thread_id).append(msg)
        self.appends += 1

    def read_thread(self, thread_id: str) -> list[ThreadMessage]:
        self.reads += 1
        thread = self.threads.get(thread_id)
        return list(thread.messages) if thread else []

    def snapshot(self) -> dict[str, list[dict[str, Any]]]:
        return {tid: [m.model_dump() for m in t.messages] for tid, t in self.threads.items()}
