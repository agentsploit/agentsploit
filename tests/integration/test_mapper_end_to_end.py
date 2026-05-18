"""End-to-end mapper test against both stdio fixtures.

Confirms the v0.4 pipeline:
  1. Enumerate tools from two MCP servers
  2. Classify each as source / pivot / sink
  3. Infer edges across servers
  4. Find paths and emit findings
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsploit.core import Session, Target
from agentsploit.modules.mapper.mapper import PermissionMapper
from agentsploit.modules.mapper.models import Privilege

pytestmark = pytest.mark.integration


@pytest.fixture()
def source_fixture_uri() -> str:
    p = Path(__file__).parent.parent / "fixtures" / "vulnerable_mcp" / "server.py"
    return f"stdio://{p}"


@pytest.fixture()
def sink_fixture_uri() -> str:
    p = Path(__file__).parent.parent / "fixtures" / "vulnerable_sink_mcp" / "server.py"
    return f"stdio://{p}"


async def test_mapper_finds_cross_server_paths(
    session: Session, source_fixture_uri: str, sink_fixture_uri: str
) -> None:
    mapper = PermissionMapper(
        target_uris=[source_fixture_uri, sink_fixture_uri],
        max_path_length=3,
        min_sink_privilege=Privilege.EGRESS,
    )
    target = Target.parse(source_fixture_uri)

    async for f in mapper.run(target, session):
        session.add(f)

    # Expect: an inventory finding, and at least one path finding
    inventory = [f for f in session.findings if f.check == "mapper/built"]
    assert len(inventory) == 1
    assert "8 tools" in inventory[0].title  # 4 from each fixture

    paths = [f for f in session.findings if "path" in f.tags]
    assert paths, "expected at least one cross-server path"

    # Sanity-check the source/sink classifications: the source fixture has
    # read_file (source) and read_secret_file (source); the sink fixture has
    # send_email (egress), git_push (mutation), run_shell (execution).
    sink_tags = {tag for f in paths for tag in f.tags}
    assert any(t in sink_tags for t in ("egress", "mutation", "execution"))


async def test_mapper_persists_graph_artifact(
    session: Session, source_fixture_uri: str, sink_fixture_uri: str
) -> None:
    mapper = PermissionMapper(
        target_uris=[source_fixture_uri, sink_fixture_uri],
    )
    target = Target.parse(source_fixture_uri)
    [_f async for _f in mapper.run(target, session)]

    graph_files = list(session.artifact_dir.glob("permission_graph.json"))
    assert len(graph_files) == 1, "permission_graph.json should be persisted"


async def test_execution_sink_path_is_critical_severity(
    session: Session, source_fixture_uri: str, sink_fixture_uri: str
) -> None:
    """The sink fixture has run_shell — any path ending there should be CRITICAL."""
    mapper = PermissionMapper(
        target_uris=[source_fixture_uri, sink_fixture_uri],
        min_sink_privilege=Privilege.EXECUTION,
    )
    target = Target.parse(source_fixture_uri)
    async for f in mapper.run(target, session):
        session.add(f)

    crit = [f for f in session.findings if f.severity.label == "critical"]
    assert crit, "expected CRITICAL finding for path ending at execution sink"
