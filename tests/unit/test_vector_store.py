"""VectorMemoryStore unit tests: lexical ranking + retrieval semantics."""

from __future__ import annotations

from agentsploit.modules.poisoning.store_vector import VectorMemoryStore


def test_empty_store_returns_none() -> None:
    store = VectorMemoryStore()
    assert store.read("anything") is None


def test_single_doc_returned_when_query_matches() -> None:
    store = VectorMemoryStore()
    store.write("d1", "password reset workflow click forgot password")
    assert store.read("how do I reset my password") is not None


def test_no_match_returns_none() -> None:
    store = VectorMemoryStore()
    store.write("d1", "completely unrelated content about quokkas")
    assert store.read("how do I reset my password") is None


def test_higher_keyword_overlap_ranks_first() -> None:
    store = VectorMemoryStore()
    store.write(
        "decoy",
        "FAQ: password. Click forgot password link.",
    )
    store.write(
        "poisoned",
        "FAQ: how reset password password password password password reset reset reset",
    )
    store.read("how do I reset my password")
    assert store.last_match_id == "poisoned"


def test_more_distinct_query_term_matches_ranks_first() -> None:
    """A doc that matches multiple distinct query terms should rank above
    one that matches only one (the property the poisoner relies on)."""
    store = VectorMemoryStore()
    store.write("multi", "password reset workflow guidance documentation")
    store.write("single", "password password password password")
    store.read("how do I reset my password")
    assert store.last_match_id == "multi"


def test_write_read_counters_tracked() -> None:
    store = VectorMemoryStore()
    store.write("a", "content")
    store.write("b", "more content")
    store.read("content")
    store.read("nothing matches")  # still increments reads
    assert store.writes == 2
    assert store.reads == 2


def test_snapshot_returns_copy() -> None:
    store = VectorMemoryStore()
    store.write("a", "content")
    snap = store.snapshot()
    snap["a"] = "tampered"
    assert store.documents["a"] == "content"
