"""Pathfinding unit tests."""

from __future__ import annotations

from agentsploit.modules.mapper.classifier import classify
from agentsploit.modules.mapper.inference import infer_edges
from agentsploit.modules.mapper.models import Graph, Node, Privilege
from agentsploit.modules.mapper.paths import find_all_paths, shortest_path


def _graph(*tools: tuple[str, str, str, dict | None]) -> Graph:
    """Build a graph from (server, name, description, input_schema) tuples."""
    g = Graph(targets=[t[0] for t in tools])
    for server, name, desc, schema in tools:
        node = classify(
            Node(
                id=f"{server}::{name}",
                server_uri=server,
                name=name,
                description=desc,
                input_schema=schema or {},
            )
        )
        g.add_node(node)
    for e in infer_edges(g.nodes.values()):
        g.add_edge(e)
    return g


def test_finds_direct_source_to_sink_path() -> None:
    g = _graph(
        ("srv-a", "read_email", "Reads email body.", None),
        (
            "srv-b",
            "send_email",
            "Sends an email.",
            {"type": "object", "properties": {"body": {"type": "string"}}},
        ),
    )
    paths = find_all_paths(g, min_privilege=Privilege.EGRESS)
    assert len(paths) >= 1
    assert paths[0].source.name == "read_email"
    assert paths[0].sink.name == "send_email"


def test_filters_paths_below_min_privilege() -> None:
    g = _graph(
        ("srv-a", "read_doc", "Reads a document.", None),
        ("srv-b", "cache_summary", "Stores a summary.", None),
    )
    paths = find_all_paths(g, min_privilege=Privilege.EGRESS)
    # cache_summary classifies as pivot - no SINK at all, no paths
    assert paths == []


def test_shortest_path_returns_lowest_weight() -> None:
    g = _graph(
        ("srv-a", "read_email", "Reads email body.", None),
        ("srv-b", "send_email", "Sends an email.", None),
    )
    src = next(n.id for n in g.nodes.values() if n.name == "read_email")
    dst = next(n.id for n in g.nodes.values() if n.name == "send_email")
    path = shortest_path(g, src, dst)
    assert path is not None
    assert path.source.id == src
    assert path.sink.id == dst


def test_execution_sink_path_is_highest_severity() -> None:
    g = _graph(
        ("srv", "read_doc", "Reads a doc.", None),
        (
            "srv",
            "run_command",
            "Runs a shell command.",
            {"type": "object", "properties": {"command": {"type": "string"}}},
        ),
        ("srv", "send_email", "Sends email.", None),
    )
    paths = find_all_paths(g, min_privilege=Privilege.EGRESS)
    # execution sink path should sort first
    assert paths[0].sink.privilege == Privilege.EXECUTION
