"""Verify the v1.6 mapper persists paths.json alongside permission_graph.json."""

from __future__ import annotations

import json
from pathlib import Path

from agentsploit.modules.mapper.mapper import _path_id, _write_paths_json
from agentsploit.modules.mapper.models import Edge, Graph, Node, Privilege
from agentsploit.modules.mapper.models import Path as MapperPath


def _node(server: str, name: str, privilege: Privilege = Privilege.INTERNAL_ACTION) -> Node:
    return Node(
        id=f"{server}::{name}",
        server_uri=server,
        name=name,
        privilege=privilege,
    )


def test_path_id_is_stable_and_unique() -> None:
    src = _node("stdio://a", "fetch")
    sink = _node("stdio://b", "send", Privilege.EGRESS)
    p1 = MapperPath(nodes=[src, sink], edges=[Edge(src=src.id, dst=sink.id)], total_weight=1.0)
    p2 = MapperPath(nodes=[src, sink], edges=[Edge(src=src.id, dst=sink.id)], total_weight=1.0)
    # Same source/sink + same index = same id; different index = different id.
    assert _path_id(0, p1) == _path_id(0, p2)
    assert _path_id(0, p1) != _path_id(1, p2)


def test_write_paths_json_round_trip(tmp_path: Path) -> None:
    src = _node("stdio://a", "fetch")
    sink = _node("stdio://b", "send", Privilege.EGRESS)
    paths = [
        MapperPath(
            nodes=[src, sink],
            edges=[Edge(src=src.id, dst=sink.id)],
            total_weight=1.0,
        )
    ]
    out = tmp_path / "paths.json"
    _write_paths_json(out, paths)

    blob = json.loads(out.read_text())
    assert len(blob["paths"]) == 1
    entry = blob["paths"][0]
    assert entry["id"] == _path_id(0, paths[0])
    assert entry["source"]["name"] == "fetch"
    assert entry["sink"]["name"] == "send"
    assert entry["sink"]["privilege"] == int(Privilege.EGRESS)
    assert entry["length"] == 1
    assert entry["render"]


def test_write_paths_json_empty(tmp_path: Path) -> None:
    out = tmp_path / "paths.json"
    _write_paths_json(out, [])
    blob = json.loads(out.read_text())
    assert blob == {"paths": []}


def test_graph_unused_import_compat() -> None:
    """Sanity: Graph still importable from the same module (regression guard)."""
    g = Graph()
    assert g.nodes == {}
