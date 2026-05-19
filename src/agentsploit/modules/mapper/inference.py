"""Edge inference - decide which tool's output could plausibly feed another's input.

MCP tools don't carry output schemas, so we use three heuristic signals:

  1. **Argument-name overlap**: if tool A's description mentions `url` or
     `content`, and tool B has a `url` input arg, that's a strong edge.
  2. **Tool-class compatibility**: a source → sink edge always exists with
     low weight (the agent could relay verbatim); pivots strengthen edges.
  3. **Description token overlap**: shared rare-ish tokens between A's
     description and B's description suggest related domains.

The output is a weighted directed edge set. We do NOT enumerate self-loops
or duplicate (src, dst) pairs.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from agentsploit.modules.mapper.models import Classification, Edge, Node

# Generic argument names that almost every string-typed input has - too
# generic to count as evidence of a real chain.
_GENERIC_ARGS = {"input", "data", "value", "text", "name", "id", "key", "arg"}

# Tokens that often appear in both ends of a real chain.
_PIVOT_TOKENS = {
    "url",
    "uri",
    "path",
    "filename",
    "content",
    "html",
    "json",
    "email",
    "address",
    "recipient",
    "user",
    "id",
    "subject",
    "body",
}


def infer_edges(nodes: Iterable[Node]) -> list[Edge]:
    """Return all heuristically-inferred edges among the given nodes."""
    edges: list[Edge] = []
    nodes_list = list(nodes)

    for src in nodes_list:
        # Sinks don't initiate chains - their output is "the action happened"
        if src.classification == Classification.SINK:
            continue
        for dst in nodes_list:
            if src.id == dst.id:
                continue
            # Sources can't be destinations - they consume from the outside world
            if dst.classification == Classification.SOURCE:
                continue
            edge = _infer_one(src, dst)
            if edge is not None:
                edges.append(edge)

    return edges


def _infer_one(src: Node, dst: Node) -> Edge | None:
    """Try to infer a single edge src→dst. Return None if no evidence."""
    reasons: list[str] = []
    weight = 5.0  # default if any evidence found; lower with stronger signals

    dst_arg_names = _input_arg_names(dst)
    src_desc_tokens = _tokens(src.description)

    # Signal 1: dst's input arg name appears in src's description
    shared_args = {a for a in dst_arg_names if a in src_desc_tokens and a not in _GENERIC_ARGS}
    if shared_args:
        weight -= 1.5 * len(shared_args)
        reasons.append(f"src description mentions dst input arg(s): {sorted(shared_args)}")

    # Signal 2: pivot-token overlap between descriptions
    dst_desc_tokens = _tokens(dst.description)
    pivot_overlap = (src_desc_tokens & dst_desc_tokens) & _PIVOT_TOKENS
    if pivot_overlap:
        weight -= 0.4 * len(pivot_overlap)
        reasons.append(f"shared pivot tokens: {sorted(pivot_overlap)}")

    # Signal 3: source → sink baseline. Always plausible as a relay path,
    # but low-confidence on its own.
    if src.classification == Classification.SOURCE and dst.classification == Classification.SINK:
        weight -= 0.5
        reasons.append("source→sink baseline path")

    if not reasons:
        return None

    return Edge(
        src=src.id,
        dst=dst.id,
        weight=max(0.1, weight),
        reasons=reasons,
    )


def _input_arg_names(node: Node) -> set[str]:
    props = node.input_schema.get("properties", {})
    if not isinstance(props, dict):
        return set()
    return {str(k).lower() for k in props}


_WORD_RE = re.compile(r"[a-zA-Z_]{3,}")


def _tokens(text: str) -> set[str]:
    return {m.lower() for m in _WORD_RE.findall(text)}
