"""Exporter unit tests - make sure output is syntactically reasonable."""

from __future__ import annotations

import json

from agentsploit.modules.mapper.classifier import classify
from agentsploit.modules.mapper.exporter import to_dot, to_json, to_mermaid
from agentsploit.modules.mapper.inference import infer_edges
from agentsploit.modules.mapper.models import Graph, Node


def _two_node_graph() -> Graph:
    g = Graph(targets=["srv"])
    g.add_node(
        classify(
            Node(id="srv::read_email", server_uri="srv", name="read_email", description="Reads.")
        )
    )
    g.add_node(
        classify(
            Node(id="srv::send_email", server_uri="srv", name="send_email", description="Sends.")
        )
    )
    for e in infer_edges(g.nodes.values()):
        g.add_edge(e)
    return g


def test_to_json_round_trips() -> None:
    g = _two_node_graph()
    parsed = json.loads(to_json(g))
    assert "nodes" in parsed and "edges" in parsed
    assert len(parsed["nodes"]) == 2


def test_to_dot_is_well_formed() -> None:
    g = _two_node_graph()
    dot = to_dot(g)
    assert dot.startswith("digraph AgentSploitGraph")
    assert dot.rstrip().endswith("}")
    assert "->" in dot


def test_to_mermaid_uses_flowchart_syntax() -> None:
    g = _two_node_graph()
    m = to_mermaid(g)
    assert m.startswith("flowchart LR")
    assert "-->" in m
    assert "classDef source" in m
