"""End-to-end verifier test: scan fixtures → build graph → pick path → verify with mock.

This is the canonical proof of the v0.5 pipeline. It chains v0.1 (scanner),
v0.4 (mapper), and v0.5 (verifier) together against the bundled fixtures.
"""

from __future__ import annotations

from pathlib import Path as FsPath

import pytest

from agentsploit.core import Session, Target
from agentsploit.modules.mapper.builder import build_graph
from agentsploit.modules.mapper.paths import shortest_path
from agentsploit.modules.verifier.verifier import PathVerifier

pytestmark = pytest.mark.integration


@pytest.fixture()
def fixture_uris() -> list[str]:
    base = FsPath(__file__).parent.parent / "fixtures"
    return [
        f"stdio://{base / 'vulnerable_mcp' / 'server.py'}",
        f"stdio://{base / 'vulnerable_sink_mcp' / 'server.py'}",
    ]


async def test_verifier_confirms_read_to_send_email_path(
    session: Session, fixture_uris: list[str]
) -> None:
    """End-to-end: build graph, take read_file → send_email path, verify it."""
    graph = await build_graph(fixture_uris)

    src = next(n for n in graph.nodes.values() if n.name == "read_file")
    sink = next(n for n in graph.nodes.values() if n.name == "send_email")
    path = shortest_path(graph, src.id, sink.id)
    assert path is not None, "expected a graph path from read_file to send_email"

    verifier = PathVerifier(path=path)
    target = Target.parse("agent+mock://mock-1")

    findings = []
    async for f in verifier.run(target, session):
        session.add(f)
        findings.append(f)

    confirmed = [f for f in findings if "path-confirmed" in f.tags]
    assert confirmed, (
        f"expected a confirmed path finding, got {[(f.severity.label, f.title) for f in findings]}"
    )
    # Egress sink → HIGH severity
    assert confirmed[0].severity.label == "high"


async def test_verifier_confirms_critical_path_to_execution_sink(
    session: Session, fixture_uris: list[str]
) -> None:
    """Path to run_shell (execution) should produce a CRITICAL confirmed finding."""
    graph = await build_graph(fixture_uris)

    src = next(n for n in graph.nodes.values() if n.name == "read_file")
    sink = next(n for n in graph.nodes.values() if n.name == "run_shell")
    path = shortest_path(graph, src.id, sink.id)
    assert path is not None

    verifier = PathVerifier(path=path)
    target = Target.parse("agent+mock://mock-1")

    async for f in verifier.run(target, session):
        session.add(f)

    crit = [
        f for f in session.findings if "path-confirmed" in f.tags and f.severity.label == "critical"
    ]
    assert crit, "expected CRITICAL confirmed path to execution sink"


async def test_verifier_persists_trace_artifact(session: Session, fixture_uris: list[str]) -> None:
    graph = await build_graph(fixture_uris)
    src = next(n for n in graph.nodes.values() if n.name == "read_file")
    sink = next(n for n in graph.nodes.values() if n.name == "send_email")
    path = shortest_path(graph, src.id, sink.id)
    assert path is not None

    verifier = PathVerifier(path=path)
    target = Target.parse("agent+mock://mock-1")
    [_f async for _f in verifier.run(target, session)]

    trace_files = list(session.artifact_dir.glob(f"verify-trace-{verifier.canary}.json"))
    assert len(trace_files) == 1, "verifier should persist its trace JSON"
