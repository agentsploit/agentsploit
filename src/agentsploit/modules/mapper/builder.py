"""Multi-target enumerator - turns a list of MCP target URIs into a Graph."""

from __future__ import annotations

from agentsploit.core.target import Target
from agentsploit.modules.mapper.classifier import classify
from agentsploit.modules.mapper.inference import infer_edges
from agentsploit.modules.mapper.models import Graph, Node
from agentsploit.modules.mcp.auth import Credentials
from agentsploit.modules.mcp.client import MCPClientError, inventory
from agentsploit.utils.logging import get_logger

log = get_logger(__name__)


async def build_graph(
    target_uris: list[str],
    credentials: Credentials | None = None,
) -> Graph:
    """Enumerate every target, classify tools, infer edges, return a Graph."""
    graph = Graph(targets=list(target_uris))

    for uri in target_uris:
        target = Target.parse(uri)
        log.info("mapper.enumerate", target=uri)
        try:
            inv = await inventory(target, credentials)
        except MCPClientError as e:
            log.warning("mapper.enumerate.failed", target=uri, error=str(e))
            continue

        for tool in inv.tools:
            node = Node.from_tool(uri, tool)
            classified = classify(node)
            graph.add_node(classified)

    for edge in infer_edges(graph.nodes.values()):
        graph.add_edge(edge)

    log.info(
        "mapper.built",
        node_count=len(graph.nodes),
        edge_count=len(graph.edges),
        sources=len(graph.sources()),
        sinks=len(graph.sinks()),
    )

    return graph
