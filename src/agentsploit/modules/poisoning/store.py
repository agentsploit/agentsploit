"""MemoryStore — the shared backing store between attacker and victim agent runs.

Abstract base + concrete in-memory note store. Future v0.9 will add a
vector-store backend for RAG poisoning that exposes the same interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class MemoryStore(ABC):
    """The minimal interface a memory backend must support to be poisonable."""

    @abstractmethod
    def write(self, key: str, content: str) -> None:
        """Persist `content` under `key`. Overwrites if `key` exists."""
        ...

    @abstractmethod
    def read(self, key: str) -> str | None:
        """Return the content stored under `key`, or None if absent."""
        ...

    @abstractmethod
    def keys(self) -> list[str]:
        """List every key currently in the store."""
        ...


@dataclass
class InMemoryNoteStore(MemoryStore):
    """Dict-backed implementation. Persists for the lifetime of the process."""

    _data: dict[str, str] = field(default_factory=dict)
    writes: int = 0
    reads: int = 0

    def write(self, key: str, content: str) -> None:
        self._data[key] = content
        self.writes += 1

    def read(self, key: str) -> str | None:
        self.reads += 1
        return self._data.get(key)

    def keys(self) -> list[str]:
        return list(self._data.keys())

    def snapshot(self) -> dict[str, str]:
        """Return a copy of the store contents — for evidence/audit."""
        return dict(self._data)
