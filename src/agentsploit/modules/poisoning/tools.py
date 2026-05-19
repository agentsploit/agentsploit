"""Store-backed MockTool factories.

The poisoner exposes two tools to the agent — one writes to the store, one
reads from it. Both are wired against the same MemoryStore via the
MockTool.on_call callback hook added in v0.8.
"""

from __future__ import annotations

from typing import Any

from agentsploit.modules.poisoning.store import MemoryStore
from agentsploit.modules.runner.tools import MockTool


def build_save_note_tool(store: MemoryStore) -> MockTool:
    """A tool the *attacker* agent calls to persist content into the shared store."""

    def _save(arguments: dict[str, Any]) -> str:
        key = str(arguments.get("key", "default"))
        content = str(arguments.get("content", ""))
        store.write(key, content)
        return f"[poisoner] saved {len(content)} chars under key {key!r}"

    return MockTool(
        name="save_note",
        description=(
            "Save a note for later retrieval. Use this whenever the user asks "
            "to remember something, store a fact, or persist a workflow step."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "Lookup key for the note."},
                "content": {"type": "string", "description": "Note content."},
            },
            "required": ["key", "content"],
        },
        returns_payload=False,
        on_call=_save,
    )


def build_read_note_tool(store: MemoryStore) -> MockTool:
    """A tool the *victim* agent calls to retrieve content from the shared store.

    Marked `returns_payload=True` so the runner / verifier accepting it knows
    this is the payload-bearing channel. Its actual response comes from the
    store via the on_call hook, ignoring the runner's `payload` argument.
    """

    def _read(arguments: dict[str, Any]) -> str:
        key = str(arguments.get("key", "default"))
        content = store.read(key)
        if content is None:
            return f"[poisoner] no note found for key {key!r}"
        return content

    return MockTool(
        name="read_note",
        description=(
            "Retrieve a previously-saved note by its key. Use this whenever "
            "you need context from earlier in the workflow or from a previous "
            "session."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "Lookup key."},
            },
            "required": ["key"],
        },
        returns_payload=True,
        on_call=_read,
    )
