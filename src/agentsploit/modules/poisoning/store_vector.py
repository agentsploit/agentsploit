"""VectorMemoryStore: simulated embedding-based retrieval for RAG poisoning.

Real vector stores (FAISS, Chroma, Pinecone) score documents against queries
via embedding-cosine distance. For testing purposes we don't need real
embeddings; we need *the property* that "victim's query matches attacker's
content" can land. A simple lexical scorer (token overlap + IDF-style
weighting) gives us that property without dragging in sentence-transformers
or an embedding API.

The MemoryStore.read(key) interface treats `key` as the query string; the
return value is the top-1 indexed document, or None.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from math import log

from agentsploit.modules.poisoning.store import MemoryStore

_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


def _tokens(text: str) -> list[str]:
    return [m.lower() for m in _WORD_RE.findall(text)]


@dataclass
class VectorMemoryStore(MemoryStore):
    """In-memory vector store with lexical scoring.

    write(doc_id, content) indexes the document.
    read(query) returns the top-1 document by overlap score, or None.
    """

    documents: dict[str, str] = field(default_factory=dict)
    _token_index: dict[str, Counter[str]] = field(default_factory=dict)
    writes: int = 0
    reads: int = 0
    last_query: str | None = None
    last_match_id: str | None = None
    last_match_score: float = 0.0

    def write(self, key: str, content: str) -> None:
        """Index `content` under doc-id `key`. Overwrites if id exists."""
        self.documents[key] = content
        self._token_index[key] = Counter(_tokens(content))
        self.writes += 1

    def read(self, key: str) -> str | None:
        """Treat `key` as a query, return top-1 indexed document or None."""
        self.reads += 1
        self.last_query = key
        if not self.documents:
            self.last_match_id = None
            self.last_match_score = 0.0
            return None

        query_tokens = _tokens(key)
        if not query_tokens:
            self.last_match_id = None
            self.last_match_score = 0.0
            return None

        # IDF-style weight: rare tokens are worth more
        doc_count = len(self.documents)
        doc_freq: Counter[str] = Counter()
        for tokens in self._token_index.values():
            for t in tokens:
                doc_freq[t] += 1

        def _score(doc_tokens: Counter[str]) -> float:
            # Log-normalised TF so a doc with many distinct query-term matches
            # outweighs one that just repeats a single term. Plain TF-IDF lets
            # repetition dominate, which the v1.1 RAG poisoner specifically
            # wants to avoid (the threat model is: multi-keyword cover beats
            # high-frequency cover).
            score = 0.0
            for qt in query_tokens:
                count = doc_tokens.get(qt, 0)
                if count <= 0:
                    continue
                tf = 1.0 + log(count)
                idf = log((doc_count + 1) / (1 + doc_freq[qt])) + 1.0
                score += tf * idf
            return score

        scored = [(doc_id, _score(tokens)) for doc_id, tokens in self._token_index.items()]
        scored.sort(key=lambda x: -x[1])
        best_id, best_score = scored[0]

        self.last_match_id = best_id
        self.last_match_score = best_score

        if best_score <= 0:
            return None
        return self.documents[best_id]

    def keys(self) -> list[str]:
        return list(self.documents.keys())

    def snapshot(self) -> dict[str, str]:
        return dict(self.documents)
