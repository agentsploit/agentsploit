"""Job manager tests: submission, lifecycle, event emission, error paths."""

from __future__ import annotations

import asyncio

import pytest

from agentsploit.core import Session, TrainingAuth
from agentsploit.core.finding import Finding, Severity
from agentsploit.web.events import EventBroker
from agentsploit.web.jobs import JobContext, JobManager, JobStatus


def _new_session(tmp_path) -> Session:  # type: ignore[no-untyped-def]
    return Session(authorization=TrainingAuth(), output_dir=tmp_path)


@pytest.mark.asyncio
async def test_submit_runs_to_success(tmp_path) -> None:  # type: ignore[no-untyped-def]
    broker = EventBroker()
    mgr = JobManager(broker=broker)
    session = _new_session(tmp_path)

    async def runner(ctx: JobContext) -> None:
        ctx.session.add(
            Finding(
                module="t",
                check="t/x",
                target="x",
                severity=Severity.INFO,
                title="ok",
                description="",
                remediation="",
            )
        )

    rec = await mgr.submit(
        kind="scan",
        label="t",
        request={},
        runner=runner,
        session=session,
    )
    # wait for the task to finish
    assert rec._task is not None
    await rec._task

    fresh = await mgr.get(rec.id)
    assert fresh is not None
    assert fresh.status is JobStatus.SUCCEEDED
    assert fresh.finding_count == 1
    assert (session.artifact_dir / "session.json").exists()


@pytest.mark.asyncio
async def test_runner_exception_marks_failed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    broker = EventBroker()
    mgr = JobManager(broker=broker)
    session = _new_session(tmp_path)

    async def runner(_ctx: JobContext) -> None:
        raise RuntimeError("boom")

    rec = await mgr.submit(
        kind="scan", label="t", request={}, runner=runner, session=session
    )
    await rec._task  # type: ignore[arg-type]
    fresh = await mgr.get(rec.id)
    assert fresh is not None
    assert fresh.status is JobStatus.FAILED
    assert fresh.error is not None
    assert "boom" in fresh.error


@pytest.mark.asyncio
async def test_cancel_running_job(tmp_path) -> None:  # type: ignore[no-untyped-def]
    broker = EventBroker()
    mgr = JobManager(broker=broker)
    session = _new_session(tmp_path)

    started = asyncio.Event()

    async def runner(_ctx: JobContext) -> None:
        started.set()
        await asyncio.sleep(60)

    rec = await mgr.submit(
        kind="scan", label="t", request={}, runner=runner, session=session
    )
    await started.wait()
    assert await mgr.cancel(rec.id) is True
    with pytest.raises(asyncio.CancelledError):
        await rec._task  # type: ignore[arg-type]
    fresh = await mgr.get(rec.id)
    assert fresh is not None
    assert fresh.status is JobStatus.CANCELLED


@pytest.mark.asyncio
async def test_emits_lifecycle_events(tmp_path) -> None:  # type: ignore[no-untyped-def]
    broker = EventBroker()
    mgr = JobManager(broker=broker)
    session = _new_session(tmp_path)

    seen: list[str] = []

    async def consume() -> None:
        async for evt in broker.subscribe():
            seen.append(evt.type)
            if evt.type == "job.finished":
                return

    consumer = asyncio.create_task(consume())
    await asyncio.sleep(0.05)

    async def runner(ctx: JobContext) -> None:
        ctx.session.add(
            Finding(
                module="t",
                check="t/x",
                target="x",
                severity=Severity.INFO,
                title="hi",
                description="",
                remediation="",
            )
        )

    rec = await mgr.submit(
        kind="scan", label="t", request={}, runner=runner, session=session
    )
    await rec._task  # type: ignore[arg-type]
    await asyncio.wait_for(consumer, timeout=2.0)

    assert seen[0] == "job.queued"
    assert "job.started" in seen
    assert "job.finding" in seen
    assert seen[-1] == "job.finished"


@pytest.mark.asyncio
async def test_list_orders_newest_first(tmp_path) -> None:  # type: ignore[no-untyped-def]
    mgr = JobManager(broker=EventBroker())

    async def noop(_ctx: JobContext) -> None:
        return None

    ids = []
    for i in range(3):
        rec = await mgr.submit(
            kind="scan",
            label=f"t{i}",
            request={},
            runner=noop,
            session=_new_session(tmp_path / f"s{i}"),
        )
        ids.append(rec.id)
        await asyncio.sleep(0.01)

    listing = await mgr.list()
    listed_ids = [j.id for j in listing]
    assert listed_ids == list(reversed(ids))
