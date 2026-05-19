"""Mapper models - Graph, Node, Edge, Path, and the taxonomies they use."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Classification(StrEnum):
    """Where a tool sits in an attack chain."""

    SOURCE = "source"
    """Pulls content from outside the trust boundary (web pages, emails, files).
    These are entry points for indirect prompt injection."""

    PIVOT = "pivot"
    """Transforms or stores data inside the trust boundary. Increases path
    length but rarely interesting as an end goal."""

    SINK = "sink"
    """Performs an externally-visible action: send, post, execute, mutate.
    The interesting destination of an attack path."""

    UNKNOWN = "unknown"
    """Could not classify with high confidence - treated as a pivot at scoring time."""


class Privilege(IntEnum):
    """How impactful a sink tool is. Higher = worse if reached."""

    READ = 0
    INTERNAL_ACTION = 1
    EGRESS = 2
    MUTATION = 3
    EXECUTION = 4

    @property
    def label(self) -> str:
        return self.name.lower()


class Node(BaseModel):
    """A single MCP tool as a graph node."""

    id: str
    """Stable identifier: `<server-uri>::<tool-name>`."""

    server_uri: str
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)

    classification: Classification = Classification.UNKNOWN
    privilege: Privilege = Privilege.INTERNAL_ACTION
    classification_reasons: list[str] = Field(default_factory=list)

    @classmethod
    def from_tool(cls, server_uri: str, tool: dict[str, Any]) -> Node:
        name = str(tool.get("name", "<unnamed>"))
        return cls(
            id=f"{server_uri}::{name}",
            server_uri=server_uri,
            name=name,
            description=str(tool.get("description", "")),
            input_schema=tool.get("inputSchema") or tool.get("input_schema") or {},
        )


class Edge(BaseModel):
    """A possible data-flow from one tool's output to another tool's input."""

    src: str
    """Node id of the source tool."""

    dst: str
    """Node id of the destination tool."""

    weight: float = 1.0
    """Lower = more plausible. Used by shortest-path queries."""

    reasons: list[str] = Field(default_factory=list)
    """Human-readable explanations of why we inferred this edge."""


class Graph(BaseModel):
    """A directed graph of tools and inferred data-flow edges."""

    nodes: dict[str, Node] = Field(default_factory=dict)
    edges: list[Edge] = Field(default_factory=list)
    built_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    targets: list[str] = Field(default_factory=list)

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def neighbors(self, node_id: str) -> list[Edge]:
        return [e for e in self.edges if e.src == node_id]

    def sources(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.classification == Classification.SOURCE]

    def sinks(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.classification == Classification.SINK]

    def get(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)


class Path(BaseModel):
    """A discovered attack path through the graph."""

    nodes: list[Node]
    """Ordered list of nodes from source to sink (inclusive)."""

    edges: list[Edge]
    """Edges traversed; len = len(nodes) - 1."""

    total_weight: float

    @property
    def source(self) -> Node:
        return self.nodes[0]

    @property
    def sink(self) -> Node:
        return self.nodes[-1]

    @property
    def length(self) -> int:
        return len(self.edges)

    @property
    def severity_score(self) -> int:
        """Higher = scarier. Used for Finding severity bucketing."""
        return int(self.sink.privilege) * 10 + max(0, 5 - self.length)

    def render(self) -> str:
        return " -> ".join(f"{n.name}@{_short(n.server_uri)}" for n in self.nodes)


def _short(uri: str, max_len: int = 24) -> str:
    return uri if len(uri) <= max_len else "…" + uri[-(max_len - 1) :]
