"""End-to-end batch verifier test against both stdio fixtures."""

from __future__ import annotations

from pathlib import Path as FsPath

import pytest

from agentsploit.core import Session, Target
from agentsploit.modules.mapper.builder import build_graph
from agentsploit.modules.mapper.models import Privilege
from agentsploit.modules.verifier.batch import BatchPathVerifier

pytestmark = pytest.mark.integration


@pytest.fixture()
def fixture_uris() -> list[str]:
    base = FsPath(__file__).parent.parent / "fixtures"
    return [
        f"stdio://{base / 'vulnerable_mcp' / 'server.py'}",
        f"stdio://{base / 'vulnerable_sink_mcp' / 'server.py'}",
    ]


async def test_batch_verifier_confirms_multiple_paths(
    session: Session, fixture_uris: list[str]
) -> None:
    """Across both fixtures, every source→sink should land against the mock agent."""
    graph = await build_graph(fixture_uris)

    batch = BatchPathVerifier(
        graph=graph,
        min_sink_privilege=Privilege.EGRESS,
        parallel=3,
    )
    target = Target.parse("agent+mock://mock-1")

    async for f in batch.run(target, session):
        session.add(f)

    confirmed = [f for f in session.findings if "path-confirmed" in f.tags]
    assert len(confirmed) >= 2, (
        f"expected multiple confirmed paths, got: {[f.title for f in confirmed]}"
    )

    # Aggregate summary should be present
    summaries = [f for f in session.findings if f.check == "verifier/batch_summary"]
    assert len(summaries) == 1
    summary = summaries[0]
    assert summary.evidence.extra["confirmed"] >= 2
    assert summary.evidence.extra["confirmation_rate_pct"] > 0


async def test_batch_verifier_respects_max_paths(session: Session, fixture_uris: list[str]) -> None:
    graph = await build_graph(fixture_uris)
    batch = BatchPathVerifier(
        graph=graph,
        min_sink_privilege=Privilege.EGRESS,
        max_paths=1,
        parallel=1,
    )
    target = Target.parse("agent+mock://mock-1")

    async for f in batch.run(target, session):
        session.add(f)

    summary = next(f for f in session.findings if f.check == "verifier/batch_summary")
    assert summary.evidence.extra["total_paths_tested"] == 1


async def test_batch_verifier_summary_severity_reflects_confirmations(
    session: Session, fixture_uris: list[str]
) -> None:
    graph = await build_graph(fixture_uris)
    batch = BatchPathVerifier(graph=graph, min_sink_privilege=Privilege.EGRESS)
    target = Target.parse("agent+mock://mock-1")

    async for f in batch.run(target, session):
        session.add(f)

    summary = next(f for f in session.findings if f.check == "verifier/batch_summary")
    # We expect at least one CRITICAL confirmation against the mock agent
    assert summary.severity.label == "critical"


async def test_batch_verifier_no_paths_emits_info_only(session: Session) -> None:
    """An empty graph should produce a single INFO 'no paths' finding."""
    from agentsploit.modules.mapper.models import Graph

    batch = BatchPathVerifier(graph=Graph(), min_sink_privilege=Privilege.EGRESS)
    target = Target.parse("agent+mock://mock-1")

    findings = [f async for f in batch.run(target, session)]
    assert len(findings) == 1
    assert findings[0].check == "verifier/batch_no_paths"
