"""In-process pub-sub event broker driving the SSE event stream.

v1.6 streams job + finding events to the UI in real time. Architecture
is the simplest thing that works for a single-operator tool:

    publisher -> EventBroker -> fan-out to one asyncio.Queue per subscriber

Subscribers (one per SSE connection) pull from their personal queue with
``async for evt in broker.subscribe(): ...``. Slow subscribers cannot
back up other subscribers - each has its own queue, and we drop the
oldest event when a subscriber's queue overflows (logged so an operator
knows their UI was missing live data).

Events are dataclasses serialised to dicts at the SSE boundary; tests
can subscribe directly without going through HTTP.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, Literal

from agentsploit.utils.logging import get_logger

log = get_logger(__name__)


EventType = Literal[
    "job.queued",
    "job.started",
    "job.finding",
    "job.finished",
    "job.failed",
    "job.cancelled",
]


@dataclass
class Event:
    """One event on the broker.

    `payload` is intentionally a free-form dict; each event type defines
    its own shape (see the docstrings on the broker.emit_* helpers).
    """

    type: EventType
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    job_id: str | None = None
    session_id: str | None = None

    def to_sse_data(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "timestamp": self.timestamp,
            "job_id": self.job_id,
            "session_id": self.session_id,
            "payload": self.payload,
        }


class EventBroker:
    """Simple async fan-out broker.

    Per-subscriber queues are bounded; on overflow we drop the oldest
    event for that subscriber and emit a warning. Subscribers are
    detached automatically when the consumer stops iterating.
    """

    DEFAULT_QUEUE_SIZE = 256

    def __init__(self, queue_size: int = DEFAULT_QUEUE_SIZE):
        self._queues: list[asyncio.Queue[Event]] = []
        self._queue_size = queue_size
        self._lock = asyncio.Lock()

    async def publish(self, event: Event) -> None:
        """Fan event out to every subscriber. Drops on overflow."""
        async with self._lock:
            subs = list(self._queues)
        for q in subs:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    _ = q.get_nowait()
                    q.put_nowait(event)
                    log.warning("event broker dropped oldest event for slow subscriber")
                except asyncio.QueueEmpty:
                    pass

    async def subscribe(self) -> AsyncIterator[Event]:
        """Yield events until the consumer stops iterating.

        Usage::

            async for evt in broker.subscribe():
                ...
        """
        q: asyncio.Queue[Event] = asyncio.Queue(maxsize=self._queue_size)
        async with self._lock:
            self._queues.append(q)
        try:
            while True:
                yield await q.get()
        finally:
            async with self._lock:
                if q in self._queues:
                    self._queues.remove(q)

    @property
    def subscriber_count(self) -> int:
        return len(self._queues)

    # -------------------------------------------------- convenience emitters

    async def emit_job_queued(self, job_id: str, payload: dict[str, Any]) -> None:
        await self.publish(Event(type="job.queued", job_id=job_id, payload=payload))

    async def emit_job_started(self, job_id: str, payload: dict[str, Any]) -> None:
        await self.publish(Event(type="job.started", job_id=job_id, payload=payload))

    async def emit_finding(
        self, job_id: str, session_id: str, finding: dict[str, Any]
    ) -> None:
        """A scan/verify job just produced a finding.

        Payload shape mirrors `FindingDTO` in api.py so the UI can
        re-use the same render path.
        """
        await self.publish(
            Event(
                type="job.finding",
                job_id=job_id,
                session_id=session_id,
                payload={"finding": finding},
            )
        )

    async def emit_job_finished(
        self, job_id: str, session_id: str | None, finding_count: int
    ) -> None:
        await self.publish(
            Event(
                type="job.finished",
                job_id=job_id,
                session_id=session_id,
                payload={"finding_count": finding_count},
            )
        )

    async def emit_job_failed(self, job_id: str, error: str) -> None:
        await self.publish(
            Event(type="job.failed", job_id=job_id, payload={"error": error})
        )

    async def emit_job_cancelled(self, job_id: str) -> None:
        await self.publish(Event(type="job.cancelled", job_id=job_id))


# Module-level default broker. build_app() can override it.
_default_broker: EventBroker | None = None


def get_broker() -> EventBroker:
    global _default_broker
    if _default_broker is None:
        _default_broker = EventBroker()
    return _default_broker


def set_broker(broker: EventBroker) -> None:
    """Replace the default broker (used by tests + server startup)."""
    global _default_broker
    _default_broker = broker
