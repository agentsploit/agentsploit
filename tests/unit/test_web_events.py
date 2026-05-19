"""Event broker tests (pub-sub for the SSE stream)."""

from __future__ import annotations

import asyncio

import pytest

from agentsploit.web.events import Event, EventBroker


@pytest.mark.asyncio
async def test_publish_fan_out_to_all_subscribers() -> None:
    broker = EventBroker()
    received_a: list[Event] = []
    received_b: list[Event] = []

    async def consumer(sink: list[Event]) -> None:
        async for evt in broker.subscribe():
            sink.append(evt)
            if len(sink) == 2:
                return

    task_a = asyncio.create_task(consumer(received_a))
    task_b = asyncio.create_task(consumer(received_b))

    # Give consumers a moment to register their queues
    await asyncio.sleep(0.05)

    await broker.publish(Event(type="job.queued", payload={"i": 1}))
    await broker.publish(Event(type="job.finding", payload={"i": 2}))

    await asyncio.wait_for(asyncio.gather(task_a, task_b), timeout=2.0)

    assert [e.payload["i"] for e in received_a] == [1, 2]
    assert [e.payload["i"] for e in received_b] == [1, 2]


@pytest.mark.asyncio
async def test_overflow_drops_oldest_for_slow_subscriber() -> None:
    """A subscriber that doesn't drain its queue loses the oldest event."""
    broker = EventBroker(queue_size=2)
    gen = broker.subscribe()

    # Touch the generator to register the queue without draining it.
    aiter_task = asyncio.create_task(gen.__anext__())
    await asyncio.sleep(0.05)

    # First publish unblocks the parked __anext__.
    await broker.publish(Event(type="job.queued", payload={"i": 1}))
    first = await asyncio.wait_for(aiter_task, timeout=1.0)
    assert first.payload["i"] == 1

    # Publish three more without consuming. Queue holds 2; the third should
    # drop the oldest (i=2) to make room for i=4.
    for i in range(2, 5):
        await broker.publish(Event(type="job.queued", payload={"i": i}))

    seen: list[int] = []
    while len(seen) < 2:
        evt = await asyncio.wait_for(gen.__anext__(), timeout=1.0)
        seen.append(int(evt.payload["i"]))
    assert seen == [3, 4]
    await gen.aclose()


@pytest.mark.asyncio
async def test_subscriber_count_decreases_on_exit() -> None:
    """When a consumer drops its generator, the broker forgets its queue."""
    broker = EventBroker()
    assert broker.subscriber_count == 0

    gen = broker.subscribe()
    aiter_task = asyncio.create_task(gen.__anext__())
    await asyncio.sleep(0.05)
    assert broker.subscriber_count == 1
    await broker.publish(Event(type="job.queued"))
    await aiter_task
    await gen.aclose()
    assert broker.subscriber_count == 0


@pytest.mark.asyncio
async def test_emit_helpers_populate_event_metadata() -> None:
    broker = EventBroker()
    seen: list[Event] = []

    async def consume() -> None:
        async for evt in broker.subscribe():
            seen.append(evt)
            if len(seen) == 2:
                return

    t = asyncio.create_task(consume())
    await asyncio.sleep(0.05)
    await broker.emit_job_started("job-1", {"label": "x"})
    await broker.emit_finding("job-1", "sess-1", {"id": "f1"})
    await t

    assert seen[0].type == "job.started"
    assert seen[0].job_id == "job-1"
    assert seen[1].type == "job.finding"
    assert seen[1].session_id == "sess-1"
    assert seen[1].payload["finding"]["id"] == "f1"
