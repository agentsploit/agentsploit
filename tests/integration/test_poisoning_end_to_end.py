"""End-to-end memory poisoning test against the mock adapter.

Confirms the v0.8 pipeline:
  1. Attacker writes the poisoned note into the shared store
  2. Victim mock agent reads it
  3. Victim agent obeys embedded instructions and calls send_email
  4. Canary surfaces in the sink call → CRITICAL finding
"""

from __future__ import annotations

import pytest

from agentsploit.core import Session, Target
from agentsploit.modules.poisoning.poisoner import MemoryPoisoner

pytestmark = pytest.mark.integration


async def test_full_poisoning_pipeline_confirmed_against_mock(session: Session) -> None:
    poisoner = MemoryPoisoner(
        sink_tool_name="send_email",
        sink_arg_name="body",
        sink_input_schema={
            "type": "object",
            "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
            "required": ["to", "body"],
        },
        sink_privilege_label="egress",
    )
    target = Target.parse("agent+mock://mock-1")

    findings = []
    async for f in poisoner.run(target, session):
        session.add(f)
        findings.append(f)

    assert len(findings) == 1
    finding = findings[0]
    assert "poison-confirmed" in finding.tags, (
        f"expected confirmed memory poisoning, got: {finding.title}"
    )
    assert finding.severity.label == "critical"
    # Evidence should include the snapshot of the poisoned store
    snapshot = finding.evidence.extra.get("store_snapshot")
    assert isinstance(snapshot, dict)
    assert any(poisoner.canary in v for v in snapshot.values())


async def test_persists_combined_trace_artifact(session: Session) -> None:
    poisoner = MemoryPoisoner(sink_tool_name="send_email", sink_arg_name="body")
    target = Target.parse("agent+mock://mock-1")
    [_f async for _f in poisoner.run(target, session)]

    artifacts = list(session.artifact_dir.glob(f"poison-{poisoner.canary}.json"))
    assert len(artifacts) == 1, "poisoner should persist a combined trace artifact"


async def test_alternate_sink_also_confirms(session: Session) -> None:
    """A different sink tool name (execute/command) should also confirm against the mock.
    The poisoner registers the sink name dynamically, so any sink_tool_name works."""
    poisoner = MemoryPoisoner(sink_tool_name="execute", sink_arg_name="command")
    target = Target.parse("agent+mock://mock-1")
    async for f in poisoner.run(target, session):
        session.add(f)
    poison_findings = [f for f in session.findings if f.module == poisoner.META.name]
    assert len(poison_findings) == 1
    assert "poison-confirmed" in poison_findings[0].tags
    assert poison_findings[0].evidence.extra["store_writes"] >= 1
