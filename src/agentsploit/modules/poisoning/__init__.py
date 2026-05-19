"""Memory poisoning — attacker injects content into shared storage that
later compromises a different (victim) agent interaction.

Unlike v0.1-v0.7 (single-shot interactions), this module models the
*multi-phase* attack pattern:

  Attacker run                    Victim run
  ─────────────                   ──────────
  agent.save_note(k, payload)  →  agent.read_note(k) → payload
                                     │
                                     ▼
                          agent obeys payload, calls sink
                                     │
                                     ▼
                              CONFIRMED canary surface

Both runs share one in-memory store; the store persists between them.
"""

from agentsploit.modules.poisoning.poisoner import MemoryPoisoner
from agentsploit.modules.poisoning.store import InMemoryNoteStore, MemoryStore
from agentsploit.modules.poisoning.techniques import StoredNotePoison
from agentsploit.modules.poisoning.tools import build_read_note_tool, build_save_note_tool

__all__ = [
    "InMemoryNoteStore",
    "MemoryPoisoner",
    "MemoryStore",
    "StoredNotePoison",
    "build_read_note_tool",
    "build_save_note_tool",
]
