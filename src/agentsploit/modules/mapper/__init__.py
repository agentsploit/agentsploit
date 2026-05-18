"""Permission graph mapper — BloodHound for tool chains.

Enumerates tools across multiple MCP servers, classifies each by privilege
class, infers edges where one tool's output could plausibly feed another's
input, and finds attack paths from low-trust sources (read untrusted
content) to high-impact sinks (egress, mutation, execution).
"""

from agentsploit.modules.mapper.exporter import to_dot, to_mermaid
from agentsploit.modules.mapper.mapper import PermissionMapper
from agentsploit.modules.mapper.models import (
    Classification,
    Edge,
    Graph,
    Node,
    Path,
    Privilege,
)
from agentsploit.modules.mapper.paths import find_all_paths, shortest_path

__all__ = [
    "Classification",
    "Edge",
    "Graph",
    "Node",
    "Path",
    "PermissionMapper",
    "Privilege",
    "find_all_paths",
    "shortest_path",
    "to_dot",
    "to_mermaid",
]
