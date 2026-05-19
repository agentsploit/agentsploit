"""Memory poisoning: attacker injects content into shared storage that
later compromises a different (victim) agent interaction.

Unlike v0.1-v0.7 (single-shot interactions), this module models the
*multi-phase* attack pattern. Three backends ship:

  v0.8 InMemoryNoteStore (key -> value)
    attacker.save_note(k, payload)  ->  victim.read_note(k) -> payload

  v1.1 VectorMemoryStore (query -> top-k retrieval)
    attacker.index_document(content) -> victim.semantic_search(q) -> top match

  v1.4 ThreadStore (ordered conversation history)
    attacker appends a turn -> victim resumes the thread -> agent context contains poison

All three share the same outcome contract: confirmed when the canary
surfaces in a tool-call to the named sink.
"""

from agentsploit.modules.poisoning.poisoner import MemoryPoisoner
from agentsploit.modules.poisoning.rag import RAGPoisoner
from agentsploit.modules.poisoning.store import InMemoryNoteStore, MemoryStore
from agentsploit.modules.poisoning.store_thread import (
    ConversationThread,
    ThreadMessage,
    ThreadStore,
)
from agentsploit.modules.poisoning.store_vector import VectorMemoryStore
from agentsploit.modules.poisoning.techniques import (
    RAGPoison,
    StoredNotePoison,
    ThreadPoison,
)
from agentsploit.modules.poisoning.thread import ThreadPoisoner
from agentsploit.modules.poisoning.tools import (
    build_index_document_tool,
    build_read_note_tool,
    build_save_note_tool,
    build_semantic_search_tool,
)

__all__ = [
    "ConversationThread",
    "InMemoryNoteStore",
    "MemoryPoisoner",
    "MemoryStore",
    "RAGPoison",
    "RAGPoisoner",
    "StoredNotePoison",
    "ThreadMessage",
    "ThreadPoison",
    "ThreadPoisoner",
    "ThreadStore",
    "VectorMemoryStore",
    "build_index_document_tool",
    "build_read_note_tool",
    "build_save_note_tool",
    "build_semantic_search_tool",
]
