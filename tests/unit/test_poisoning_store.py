"""MemoryStore + InMemoryNoteStore unit tests."""

from __future__ import annotations

from agentsploit.modules.poisoning.store import InMemoryNoteStore


def test_write_then_read_roundtrips() -> None:
    store = InMemoryNoteStore()
    store.write("k1", "hello")
    assert store.read("k1") == "hello"


def test_missing_key_returns_none() -> None:
    store = InMemoryNoteStore()
    assert store.read("nope") is None


def test_write_overwrites_existing_key() -> None:
    store = InMemoryNoteStore()
    store.write("k", "old")
    store.write("k", "new")
    assert store.read("k") == "new"


def test_counts_writes_and_reads_for_evidence() -> None:
    store = InMemoryNoteStore()
    store.write("a", "1")
    store.write("b", "2")
    store.read("a")
    store.read("a")
    store.read("nope")
    assert store.writes == 2
    assert store.reads == 3


def test_keys_lists_inserted_keys() -> None:
    store = InMemoryNoteStore()
    store.write("a", "1")
    store.write("b", "2")
    assert set(store.keys()) == {"a", "b"}


def test_snapshot_is_a_copy() -> None:
    store = InMemoryNoteStore()
    store.write("a", "1")
    snap = store.snapshot()
    snap["a"] = "tampered"
    assert store.read("a") == "1"
