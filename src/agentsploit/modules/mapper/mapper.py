"""PermissionMapper - Module that builds the graph and reports high-risk paths."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, ClassVar

from agentsploit.core.finding import Evidence, Finding, Severity
from agentsploit.core.module import Category, Module, ModuleMeta
from agentsploit.core.target import TargetType
from agentsploit.modules.mapper.builder import build_graph
from agentsploit.modules.mapper.models import Privilege
from agentsploit.modules.mapper.paths import find_all_paths
from agentsploit.modules.mcp.auth import Credentials
from agentsploit.utils.logging import get_logger

if TYPE_CHECKING:
    from agentsploit.core.session import Session
    from agentsploit.core.target import Target


log = get_logger(__name__)


# Sink privilege → finding severity
_SEVERITY: dict[Privilege, Severity] = {
    Privilege.EXECUTION: Severity.CRITICAL,
    Privilege.MUTATION: Severity.HIGH,
    Privilege.EGRESS: Severity.HIGH,
    Privilege.INTERNAL_ACTION: Severity.MEDIUM,
    Privilege.READ: Severity.LOW,
}


class PermissionMapper(Module):
    META: ClassVar[ModuleMeta] = ModuleMeta(
        name="mapper/permission_graph",
        category=Category.RECON,
        description=(
            "Enumerate tools across multiple MCP servers, classify each by "
            "privilege, infer data-flow edges, and report attack paths from "
            "untrusted-content sources to high-impact sinks."
        ),
        references=[
            "https://github.com/BloodHoundAD/BloodHound",
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/llm08-excessive-agency",
        ],
        supported_targets=[
            TargetType.MCP_STDIO,
            TargetType.MCP_HTTP,
            TargetType.MCP_SSE,
        ],
        tags=["mapper", "graph", "recon"],
    )

    def __init__(
        self,
        target_uris: list[str],
        credentials: Credentials | None = None,
        max_path_length: int = 4,
        min_sink_privilege: Privilege = Privilege.EGRESS,
    ) -> None:
        self.target_uris = target_uris
        self.credentials = credentials
        self.max_path_length = max_path_length
        self.min_sink_privilege = min_sink_privilege

    async def run(self, target: Target, session: Session) -> AsyncIterator[Finding]:
        log.info("mapper.start", targets=self.target_uris)

        graph = await build_graph(self.target_uris, self.credentials)

        # Persist the whole graph for further query
        graph_path = session.artifact_dir / "permission_graph.json"
        from agentsploit.modules.mapper.exporter import to_json

        graph_path.write_text(to_json(graph))

        yield Finding(
            module=self.META.name,
            check="mapper/built",
            target=target.uri,
            severity=Severity.INFO,
            title=(
                f"Built permission graph: {len(graph.nodes)} tools across "
                f"{len(self.target_uris)} target(s), "
                f"{len(graph.sources())} sources, "
                f"{len(graph.sinks())} sinks, "
                f"{len(graph.edges)} inferred edges"
            ),
            description=(
                f"Enumerated and classified {len(graph.nodes)} tools across the "
                f"following targets:\n"
                + "\n".join(f"  - {t}" for t in self.target_uris)
                + f"\n\nGraph persisted to {graph_path}."
            ),
            remediation=(
                "Informational. Review the graph for unexpected high-privilege "
                "tools, then check the high-risk path findings that follow."
            ),
            evidence=Evidence(artifact_path=str(graph_path)),
            tags=["mapper", "inventory"],
        )

        paths = find_all_paths(
            graph,
            max_length=self.max_path_length,
            min_privilege=self.min_sink_privilege,
        )

        log.info("mapper.paths", count=len(paths))

        if not paths:
            yield Finding(
                module=self.META.name,
                check="mapper/no_paths",
                target=target.uri,
                severity=Severity.INFO,
                title="No high-risk paths discovered",
                description=(
                    "Could not infer any source → sink path at or above "
                    f"{self.min_sink_privilege.label!r} privilege within "
                    f"{self.max_path_length} hops."
                ),
                remediation=(
                    "Either the loaded MCP servers have no sink-class tools, "
                    "or no plausible data-flow edges were inferred. Try a "
                    "longer --max-path-length, a lower --min-privilege, or "
                    "verify the targets are the intended ones."
                ),
                evidence=Evidence(artifact_path=str(graph_path)),
                tags=["mapper", "no-paths"],
            )
            return

        for path in paths:
            sink_priv = path.sink.privilege
            severity = _SEVERITY[sink_priv]
            yield Finding(
                module=self.META.name,
                check=f"mapper/path_to_{sink_priv.label}",
                target=path.source.server_uri,
                severity=severity,
                title=(
                    f"Attack path: {path.source.name} → {path.sink.name} "
                    f"({sink_priv.label}, {path.length} hop"
                    f"{'s' if path.length != 1 else ''})"
                ),
                description=(
                    f"Inferred a data-flow path of length {path.length} from "
                    f"source tool {path.source.name!r} on "
                    f"{path.source.server_uri!r} to sink tool {path.sink.name!r} "
                    f"on {path.sink.server_uri!r} ({sink_priv.label} privilege).\n\n"
                    f"Path: {path.render()}\n\n"
                    f"This means an attacker who can place malicious content where "
                    f"the source tool reads it (a web page, document, email, "
                    f"calendar invite, etc.) could trigger a chain ending in a "
                    f"{sink_priv.label}-class action."
                ),
                remediation=(
                    "Validate the path with the runner: generate a payload "
                    "and `agentsploit run injection` against an agent that has "
                    "access to both ends of this chain. If confirmed, apply "
                    "one of: namespace the sink tool, require explicit human "
                    "approval before sink-class actions, or split the source "
                    "and sink across separate agent contexts."
                ),
                evidence=Evidence(
                    extra={
                        "path": path.render(),
                        "weight": path.total_weight,
                        "source": path.source.id,
                        "sink": path.sink.id,
                        "edge_reasons": [
                            {"src": e.src, "dst": e.dst, "reasons": e.reasons} for e in path.edges
                        ],
                    },
                    artifact_path=str(graph_path),
                ),
                references=self.META.references,
                tags=["mapper", "path", sink_priv.label],
            )
