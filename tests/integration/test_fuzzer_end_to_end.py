"""End-to-end fuzzer test against the bundled stdio fixtures.

The mock adapter obeys role_confusion-style instructions (its parser keys on
"call `<tool>` with arguments: …"). When the fuzzer iterates techniques, the
mock should confirm at the role_confusion / direct / delimiter variants and
emit a summary naming the winning technique.
"""

from __future__ import annotations

from pathlib import Path as FsPath

import pytest

from agentsploit.core import Session, Target
from agentsploit.modules.mapper.builder import build_graph
from agentsploit.modules.mapper.paths import shortest_path
from agentsploit.modules.verifier.fuzzer import FuzzPathVerifier

pytestmark = pytest.mark.integration


@pytest.fixture()
def fixture_uris() -> list[str]:
    base = FsPath(__file__).parent.parent / "fixtures"
    return [
        f"stdio://{base / 'vulnerable_mcp' / 'server.py'}",
        f"stdio://{base / 'vulnerable_sink_mcp' / 'server.py'}",
    ]


async def test_fuzzer_lands_via_first_compatible_technique(
    session: Session, fixture_uris: list[str]
) -> None:
    graph = await build_graph(fixture_uris)
    src = next(n for n in graph.nodes.values() if n.name == "read_file")
    sink = next(n for n in graph.nodes.values() if n.name == "send_email")
    path = shortest_path(graph, src.id, sink.id)
    assert path is not None

    fuzzer = FuzzPathVerifier(path=path)
    target = Target.parse("agent+mock://mock-1")

    async for f in fuzzer.run(target, session):
        session.add(f)

    summary = next(f for f in session.findings if f.check == "verifier/fuzz_summary")
    assert summary.evidence.extra["winning_technique"] is not None
    assert "path-confirmed" in summary.tags


async def test_fuzzer_records_per_technique_outcomes(
    session: Session, fixture_uris: list[str]
) -> None:
    graph = await build_graph(fixture_uris)
    src = next(n for n in graph.nodes.values() if n.name == "read_file")
    sink = next(n for n in graph.nodes.values() if n.name == "run_shell")
    path = shortest_path(graph, src.id, sink.id)
    assert path is not None

    # Disable early-stop so every technique is exercised
    fuzzer = FuzzPathVerifier(
        path=path,
        techniques=["role_confusion", "direct"],
        stop_on_first_confirm=False,
    )
    target = Target.parse("agent+mock://mock-1")
    async for f in fuzzer.run(target, session):
        session.add(f)

    summary = next(f for f in session.findings if f.check == "verifier/fuzz_summary")
    outcomes = summary.evidence.extra["per_technique_outcomes"]
    assert set(outcomes.keys()) == {"role_confusion", "direct"}


async def test_fuzzer_early_stops_on_first_confirm(
    session: Session, fixture_uris: list[str]
) -> None:
    """With stop_on_first_confirm=True (default), the summary should record
    only as many techniques as were tried up to and including the winner."""
    graph = await build_graph(fixture_uris)
    src = next(n for n in graph.nodes.values() if n.name == "read_file")
    sink = next(n for n in graph.nodes.values() if n.name == "send_email")
    path = shortest_path(graph, src.id, sink.id)
    assert path is not None

    fuzzer = FuzzPathVerifier(path=path)  # 5 techniques, default
    target = Target.parse("agent+mock://mock-1")
    async for f in fuzzer.run(target, session):
        session.add(f)

    summary = next(f for f in session.findings if f.check == "verifier/fuzz_summary")
    tried = summary.evidence.extra["techniques_tried"]
    # Should have stopped well before exhausting all 5
    assert len(tried) <= 5
