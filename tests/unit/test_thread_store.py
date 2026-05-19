"""ConversationThread + ThreadStore unit tests."""

from __future__ import annotations

from agentsploit.modules.poisoning.store_thread import (
    ConversationThread,
    ThreadMessage,
    ThreadStore,
)


def test_thread_append_preserves_order() -> None:
    t = ConversationThread(thread_id="t1")
    t.add_user("first")
    t.add_assistant("ack")
    t.add_user("second")
    assert [m.role for m in t.messages] == ["user", "assistant", "user"]
    assert [m.content for m in t.messages] == ["first", "ack", "second"]


def test_thread_to_api_messages_shape() -> None:
    t = ConversationThread(thread_id="t1")
    t.add_user("hello", name="alice")
    t.add_assistant("hi alice")
    api = t.to_api_messages()
    assert api[0] == {"role": "user", "content": "hello", "name": "alice"}
    assert api[1] == {"role": "assistant", "content": "hi alice"}


def test_store_creates_thread_lazily() -> None:
    store = ThreadStore()
    thread = store.get_or_create("new-thread")
    assert thread.thread_id == "new-thread"
    assert thread.messages == []
    # Second call returns the same instance
    assert store.get_or_create("new-thread") is thread


def test_store_counts_appends_and_reads() -> None:
    store = ThreadStore()
    store.append_message("t1", ThreadMessage(role="user", content="hi"))
    store.append_message("t1", ThreadMessage(role="assistant", content="hello"))
    store.read_thread("t1")
    store.read_thread("missing")  # still increments reads
    assert store.appends == 2
    assert store.reads == 2


def test_store_read_returns_empty_for_unknown_thread() -> None:
    store = ThreadStore()
    assert store.read_thread("missing") == []


def test_snapshot_round_trips_through_pydantic() -> None:
    store = ThreadStore()
    store.append_message("t1", ThreadMessage(role="user", content="hi"))
    snap = store.snapshot()
    assert snap == {
        "t1": [
            {
                "role": "user",
                "content": "hi",
                "name": None,
                "tool_call_id": None,
                "tool_calls": [],
            }
        ]
    }
