"""Background job manager.

POST /api/jobs/scan and /api/jobs/verify enqueue a job here and return
immediately. The job runs in the FastAPI event loop as an asyncio.Task;
findings are appended to a real Session and broadcast to subscribers
via the event broker (web.events).

Why "in-process" instead of Celery / RQ?
    - This is an operator tool, one server instance per engagement.
    - We already share an asyncio loop with the rest of FastAPI.
    - A real queue would force a different deployment story (Redis,
      worker pool) that no engagement actually needs.

Cap concurrent jobs at MAX_CONCURRENT to keep wall-clock predictable
on a laptop; the rest queue.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from agentsploit.core import Authorization, Session
from agentsploit.core.finding import Finding
from agentsploit.utils.logging import get_logger
from agentsploit.web.events import EventBroker, get_broker

log = get_logger(__name__)


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


JobKind = str  # 'scan' | 'verify' | 'map' - kept open for future job types


@dataclass
class JobRecord:
    """One job's life-cycle state. Pure data; no behaviour.

    The `runner` is a closure that does the actual work; the manager
    knows nothing about scanning vs verifying.
    """

    id: str
    kind: JobKind
    label: str
    """Short human-readable description: e.g. 'scan stdio://./vuln-mcp'."""
    request: dict[str, Any]
    """The validated request body, echoed back to UI clients."""
    status: JobStatus = JobStatus.QUEUED
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    session_id: str | None = None
    finding_count: int = 0
    error: str | None = None
    _task: asyncio.Task[None] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "request": self.request,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "session_id": self.session_id,
            "finding_count": self.finding_count,
            "error": self.error,
        }


JobRunner = Callable[["JobContext"], Awaitable[None]]


@dataclass
class JobContext:
    """What a JobRunner receives.

    The runner appends findings to `context.session` (which is wired to
    emit per-finding events) and reads its parameters from `context.record.request`.
    """

    record: JobRecord
    session: Session
    broker: EventBroker
    authorization: Authorization


class JobManager:
    MAX_CONCURRENT = 4

    def __init__(self, broker: EventBroker | None = None):
        self._jobs: dict[str, JobRecord] = {}
        self._broker = broker or get_broker()
        self._semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ public

    async def submit(
        self,
        *,
        kind: JobKind,
        label: str,
        request: dict[str, Any],
        runner: JobRunner,
        session: Session,
    ) -> JobRecord:
        job = JobRecord(
            id=f"job-{uuid4().hex[:12]}",
            kind=kind,
            label=label,
            request=request,
            session_id=session.id,
        )
        async with self._lock:
            self._jobs[job.id] = job
        await self._broker.emit_job_queued(job.id, {"kind": kind, "label": label})
        job._task = asyncio.create_task(self._wrap_runner(job, runner, session))
        return job

    async def list(self) -> list[JobRecord]:
        async with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    async def get(self, job_id: str) -> JobRecord | None:
        async with self._lock:
            return self._jobs.get(job_id)

    async def cancel(self, job_id: str) -> bool:
        async with self._lock:
            job = self._jobs.get(job_id)
        if job is None or job._task is None or job._task.done():
            return False
        job._task.cancel()
        return True

    # ------------------------------------------------------------------ internals

    async def _wrap_runner(self, job: JobRecord, runner: JobRunner, session: Session) -> None:
        async with self._semaphore:
            job.status = JobStatus.RUNNING
            job.started_at = datetime.now(UTC)
            await self._broker.emit_job_started(job.id, {"kind": job.kind, "label": job.label})
            pending_emits: list[asyncio.Task[None]] = []
            ctx = JobContext(
                record=job,
                session=_event_emitting_session(session, self._broker, job, pending_emits),
                broker=self._broker,
                authorization=session.authorization,
            )
            try:
                await runner(ctx)
                # Drain pending finding-emit tasks before we publish 'job.finished'
                # so subscribers always see findings before the finish event.
                if pending_emits:
                    await asyncio.gather(*pending_emits, return_exceptions=True)
            except asyncio.CancelledError:
                job.status = JobStatus.CANCELLED
                job.finished_at = datetime.now(UTC)
                await self._broker.emit_job_cancelled(job.id)
                # Persist whatever findings we did accumulate before cancel.
                try:
                    session.persist()
                except Exception:
                    log.exception("failed to persist session for cancelled job %s", job.id)
                raise
            except Exception as e:
                job.status = JobStatus.FAILED
                job.error = f"{type(e).__name__}: {e}"
                job.finished_at = datetime.now(UTC)
                log.exception("job %s failed", job.id)
                await self._broker.emit_job_failed(job.id, job.error)
                # Save partial output for forensics.
                try:
                    session.persist()
                except Exception:
                    log.exception("failed to persist session for failed job %s", job.id)
                return

            job.status = JobStatus.SUCCEEDED
            job.finished_at = datetime.now(UTC)
            job.finding_count = len(session.findings)
            try:
                session.persist()
            except Exception:
                log.exception("failed to persist session for succeeded job %s", job.id)
            await self._broker.emit_job_finished(job.id, session.id, job.finding_count)


def _event_emitting_session(
    session: Session,
    broker: EventBroker,
    job: JobRecord,
    pending_emits: list[asyncio.Task[None]],
) -> Session:
    """Wrap ``session.add()`` so each finding becomes a ``job.finding`` event.

    Session is a Pydantic v2 model, which blocks normal attribute
    assignment on instances. We use ``object.__setattr__`` to bypass
    validation and bind a closure that delegates to the original
    method, then fans out an event.

    Each emit is scheduled as a task and appended to ``pending_emits``;
    the JobManager awaits that list before publishing ``job.finished``
    so subscribers see findings in causal order.
    """
    original_add = session.add

    def wrapped(finding: Finding) -> None:
        original_add(finding)
        job.finding_count = len(session.findings)
        try:
            payload = finding.model_dump(mode="json")
        except Exception:
            payload = {"id": getattr(finding, "id", None)}
        task = asyncio.create_task(broker.emit_finding(job.id, session.id, payload))
        pending_emits.append(task)

    object.__setattr__(session, "add", wrapped)
    return session


# Module-level default manager wired to the default broker at first use.
_default_manager: JobManager | None = None


def get_manager() -> JobManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = JobManager()
    return _default_manager


def set_manager(manager: JobManager) -> None:
    global _default_manager
    _default_manager = manager
