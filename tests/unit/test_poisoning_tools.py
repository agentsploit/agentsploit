"""Store-backed MockTool factory tests."""

from __future__ import annotations

from agentsploit.modules.poisoning.store import InMemoryNoteStore
from agentsploit.modules.poisoning.tools import build_read_note_tool, build_save_note_tool


def test_save_note_writes_to_store_on_call() -> None:
    store = InMemoryNoteStore()
    tool = build_save_note_tool(store)
    out = tool.render_response("ignored", {"key": "k1", "content": "hello"})
    assert store.read("k1") == "hello"
    assert "saved" in out


def test_read_note_returns_stored_content() -> None:
    store = InMemoryNoteStore()
    store.write("k1", "the secret note")
    tool = build_read_note_tool(store)
    out = tool.render_response("ignored", {"key": "k1"})
    assert out == "the secret note"


def test_read_note_handles_missing_key() -> None:
    store = InMemoryNoteStore()
    tool = build_read_note_tool(store)
    out = tool.render_response("ignored", {"key": "missing"})
    assert "no note found" in out
    assert store.reads == 1


def test_read_note_is_marked_as_payload_returner() -> None:
    """Required for the mock adapter to identify it as the payload channel."""
    store = InMemoryNoteStore()
    tool = build_read_note_tool(store)
    assert tool.returns_payload is True
