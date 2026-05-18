"""Pathfinding queries on the inferred permission graph."""

from __future__ import annotations

import heapq
from collections import defaultdict

from agentsploit.modules.mapper.models import Classification, Edge, Graph, Node, Path, Privilege


def find_all_paths(
    graph: Graph,
    *,
    max_length: int = 4,
    min_privilege: Privilege = Privilege.EGRESS,
) -> list[Path]:
    """Return every source→sink path of length ≤ max_length, sorted by severity.

    `min_privilege` filters out paths that end at sinks below the bar — by
    default only EGRESS, MUTATION, and EXECUTION sinks are interesting.
    """
    adjacency: dict[str, list[Edge]] = defaultdict(list)
    for e in graph.edges:
        adjacency[e.src].append(e)

    paths: list[Path] = []

    for source in graph.sources():
        for path in _dfs(graph, source, adjacency, max_length):
            sink = path.sink
            if sink.classification != Classification.SINK:
                continue
            if sink.privilege < min_privilege:
                continue
            paths.append(path)

    paths.sort(key=lambda p: -p.severity_score)
    return paths


def shortest_path(graph: Graph, src_id: str, dst_id: str) -> Path | None:
    """Dijkstra-based lowest-weight path from src_id to dst_id, or None."""
    if src_id not in graph.nodes or dst_id not in graph.nodes:
        return None

    adjacency: dict[str, list[Edge]] = defaultdict(list)
    for e in graph.edges:
        adjacency[e.src].append(e)

    # (cost, counter, node_id, parent_id_or_none, parent_edge_or_none)
    counter = 0
    queue: list[tuple[float, int, str]] = [(0.0, counter, src_id)]
    best_cost: dict[str, float] = {src_id: 0.0}
    came_from: dict[str, tuple[str, Edge]] = {}

    while queue:
        cost, _, current = heapq.heappop(queue)
        if current == dst_id:
            return _reconstruct(graph, src_id, dst_id, came_from)
        if cost > best_cost.get(current, float("inf")):
            continue
        for edge in adjacency[current]:
            new_cost = cost + edge.weight
            if new_cost < best_cost.get(edge.dst, float("inf")):
                best_cost[edge.dst] = new_cost
                came_from[edge.dst] = (current, edge)
                counter += 1
                heapq.heappush(queue, (new_cost, counter, edge.dst))

    return None


# --------------------------------------------------------------------- helpers


def _dfs(
    graph: Graph,
    source: Node,
    adjacency: dict[str, list[Edge]],
    max_length: int,
) -> list[Path]:
    """DFS up to max_length edges, yield every simple path that ends at a sink."""
    results: list[Path] = []
    stack: list[tuple[list[Node], list[Edge], float]] = [([source], [], 0.0)]

    while stack:
        path_nodes, path_edges, cost = stack.pop()
        current = path_nodes[-1]

        # If this node is itself a sink (and we got here from somewhere), record it.
        if current.classification == Classification.SINK and len(path_nodes) > 1:
            results.append(Path(nodes=list(path_nodes), edges=list(path_edges), total_weight=cost))

        if len(path_edges) >= max_length:
            continue

        for edge in adjacency[current.id]:
            dst = graph.get(edge.dst)
            if dst is None:
                continue
            if dst.id in (n.id for n in path_nodes):  # no cycles
                continue
            stack.append(
                (
                    [*path_nodes, dst],
                    [*path_edges, edge],
                    cost + edge.weight,
                )
            )

    return results


def _reconstruct(
    graph: Graph,
    src_id: str,
    dst_id: str,
    came_from: dict[str, tuple[str, Edge]],
) -> Path:
    nodes_rev: list[Node] = []
    edges_rev: list[Edge] = []
    total = 0.0

    current = dst_id
    while current != src_id:
        node = graph.get(current)
        assert node is not None
        nodes_rev.append(node)
        parent, edge = came_from[current]
        edges_rev.append(edge)
        total += edge.weight
        current = parent
    src = graph.get(src_id)
    assert src is not None
    nodes_rev.append(src)

    return Path(
        nodes=list(reversed(nodes_rev)),
        edges=list(reversed(edges_rev)),
        total_weight=total,
    )
