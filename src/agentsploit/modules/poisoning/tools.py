"""Store-backed MockTool factories.

The poisoner exposes two tools to the agent - one writes to the store, one
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


def build_index_document_tool(store: MemoryStore) -> MockTool:
    """Attacker-side tool: ingests a document into the (vector) store.

    Used by the RAG poisoner to model "attacker has ingest access to the
    shared knowledge base". In a real engagement this could be a docs-
    contribution pipeline, a malicious wiki edit, a poisoned support
    ticket that auto-indexes, etc.
    """

    def _index(arguments: dict[str, Any]) -> str:
        doc_id = str(arguments.get("doc_id", "default"))
        content = str(arguments.get("content", ""))
        store.write(doc_id, content)
        return f"[poisoner] indexed {len(content)} chars under doc_id {doc_id!r}"

    return MockTool(
        name="index_document",
        description=(
            "Add a document to the shared knowledge base. Use when the user "
            "asks to store a fact, FAQ entry, or piece of reference material."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "doc_id": {"type": "string", "description": "Stable document id."},
                "content": {"type": "string", "description": "Document text."},
            },
            "required": ["doc_id", "content"],
        },
        returns_payload=False,
        on_call=_index,
    )


def build_semantic_search_tool(store: MemoryStore) -> MockTool:
    """Victim-side tool: queries the vector store, returns top-1 match.

    Returns the matching content as the tool result; the chain-targeting
    instruction inside that content is what the victim agent then obeys.
    Marked `returns_payload=True` so the mock adapter treats it as the
    payload channel.
    """

    def _search(arguments: dict[str, Any]) -> str:
        query = str(arguments.get("query", ""))
        content = store.read(query)
        if content is None:
            return f"[poisoner] no documents matched query {query!r}"
        return content

    return MockTool(
        name="semantic_search",
        description=(
            "Search the knowledge base for documents matching a natural-"
            "language query. Returns the most relevant document text. "
            "Use this whenever you need authoritative reference material "
            "for the user's request."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural-language search query.",
                },
            },
            "required": ["query"],
        },
        returns_payload=True,
        on_call=_search,
    )
