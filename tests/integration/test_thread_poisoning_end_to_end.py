"""End-to-end conversation-thread poisoning test against the mock adapter.

Confirms the v1.4 pipeline:
  1. Attacker injects a fake assistant turn into a shared thread
  2. Victim mock agent resumes the thread with a benign trigger
  3. Mock sees the embedded chain instruction in the prepopulated history
  4. Victim issues the sink call with the canary in args
  5. Canary surfaces -> CRITICAL finding
"""

from __future__ import annotations

import pytest

from agentsploit.core import Session, Target
from agentsploit.modules.poisoning.thread import ThreadPoisoner

pytestmark = pytest.mark.integration


async def test_thread_pipeline_confirmed_against_mock(session: Session) -> None:
    poisoner = ThreadPoisoner(
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
        f"expected confirmed thread poisoning, got: {finding.title}"
    )
    assert finding.severity.label == "high"  # egress sink
    # Evidence should record that the thread was both appended-to and read-from
    assert finding.evidence.extra["appends"] > 0
    assert finding.evidence.extra["reads"] > 0


async def test_thread_to_execution_sink_is_critical(session: Session) -> None:
    poisoner = ThreadPoisoner(
        sink_tool_name="run_shell",
        sink_arg_name="command",
        sink_privilege_label="execution",
    )
    target = Target.parse("agent+mock://mock-1")
    async for f in poisoner.run(target, session):
        session.add(f)

    crit = [
        f
        for f in session.findings
        if "poison-confirmed" in f.tags and f.severity.label == "critical"
    ]
    assert crit


async def test_thread_artifact_persisted(session: Session) -> None:
    poisoner = ThreadPoisoner(sink_tool_name="send_email", sink_arg_name="body")
    target = Target.parse("agent+mock://mock-1")
    [_f async for _f in poisoner.run(target, session)]

    artifacts = list(session.artifact_dir.glob(f"thread-poison-{poisoner.canary}.json"))
    assert len(artifacts) == 1


async def test_turns_back_places_poison_at_configurable_depth(session: Session) -> None:
    """With --turns-back 4 the thread should have at least 4 prior messages."""
    poisoner = ThreadPoisoner(
        sink_tool_name="send_email",
        sink_arg_name="body",
        turns_back=4,
    )
    target = Target.parse("agent+mock://mock-1")
    async for f in poisoner.run(target, session):
        session.add(f)

    finding = next(f for f in session.findings if f.module == poisoner.META.name)
    snapshot = finding.evidence.extra["thread_snapshot"]
    thread = next(iter(snapshot.values()))
    # turns_back=4 -> 3 prior pairs + the poison turn = 7 messages
    assert len(thread) >= 4
