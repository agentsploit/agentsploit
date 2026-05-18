"""Graph exporters: JSON (lossless), DOT (graphviz), Mermaid (GitHub-renderable)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from agentsploit.modules.mapper.models import Classification, Privilege

if TYPE_CHECKING:
    from agentsploit.modules.mapper.models import Graph


_CLASS_COLOUR: dict[Classification, str] = {
    Classification.SOURCE: "#86efac",  # green
    Classification.PIVOT: "#e5e7eb",  # grey
    Classification.SINK: "#fca5a5",  # red
    Classification.UNKNOWN: "#fde68a",  # yellow
}

_PRIVILEGE_RANK: dict[Privilege, str] = {
    Privilege.READ: "READ",
    Privilege.INTERNAL_ACTION: "ACT",
    Privilege.EGRESS: "EGRESS",
    Privilege.MUTATION: "MUTATE",
    Privilege.EXECUTION: "EXEC",
}


def to_json(graph: Graph, *, indent: int = 2) -> str:
    return json.dumps(graph.model_dump(mode="json"), indent=indent, default=str)


def to_dot(graph: Graph) -> str:
    """GraphViz DOT format. Render with `dot -Tsvg graph.dot -o graph.svg`."""
    lines = [
        "digraph AgentSploitGraph {",
        "  rankdir=LR;",
        '  node [shape=box, style="rounded,filled", fontname="Helvetica"];',
        '  edge [fontname="Helvetica", fontsize=9, color="#9ca3af"];',
        "",
    ]
    for node in graph.nodes.values():
        colour = _CLASS_COLOUR[node.classification]
        label = f"{node.name}\\n[{_PRIVILEGE_RANK[node.privilege]}]"
        lines.append(f'  "{node.id}" [label="{label}", fillcolor="{colour}"];')
    lines.append("")
    for edge in graph.edges:
        lines.append(f'  "{edge.src}" -> "{edge.dst}" [label="{edge.weight:.1f}"];')
    lines.append("}")
    return "\n".join(lines)


def to_mermaid(graph: Graph) -> str:
    """Mermaid flowchart syntax — renders inline in GitHub markdown."""
    lines = ["flowchart LR"]
    for node in graph.nodes.values():
        label = f"{node.name}<br/>[{_PRIVILEGE_RANK[node.privilege]}]"
        shape = _mermaid_shape(node.classification, _sanitize_id(node.id), label)
        lines.append(f"    {shape}")
        cls = node.classification.value
        lines.append(f"    class {_sanitize_id(node.id)} {cls};")
    for edge in graph.edges:
        s = _sanitize_id(edge.src)
        d = _sanitize_id(edge.dst)
        lines.append(f"    {s} -->|{edge.weight:.1f}| {d}")
    # Class definitions for Mermaid styling
    lines += [
        "    classDef source fill:#86efac,stroke:#16a34a,color:#000;",
        "    classDef pivot fill:#e5e7eb,stroke:#9ca3af,color:#000;",
        "    classDef sink fill:#fca5a5,stroke:#dc2626,color:#000;",
        "    classDef unknown fill:#fde68a,stroke:#ca8a04,color:#000;",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------- helpers


def _sanitize_id(node_id: str) -> str:
    """Mermaid IDs can't have most punctuation; squash to alnum + underscore."""
    out = []
    for c in node_id:
        out.append(c if c.isalnum() else "_")
    return "n_" + "".join(out)[:60]


def _mermaid_shape(cls: Classification, ident: str, label: str) -> str:
    match cls:
        case Classification.SOURCE:
            return f'{ident}(("{label}"))'  # circle
        case Classification.SINK:
            return f'{ident}[["{label}"]]'  # subroutine
        case _:
            return f'{ident}["{label}"]'  # box
