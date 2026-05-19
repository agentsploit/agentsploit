"""REST API for AgentSploit's web UI.

v1.5 shipped read-only endpoints (sessions, findings, graph, traces).
v1.6 adds write endpoints (POST /api/jobs/scan, /api/jobs/verify), a
live SSE event stream (GET /api/events), and a path-explorer endpoint
backed by the new `paths.json` mapper artifact.

The API reads from a configurable engagement-output directory (defaults
to ``./engagements/`` in the CWD). Every endpoint is path-traversal
safe. Every endpoint requires a bearer token unless the server is
started with ``--no-auth`` (see web/auth.py).
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from agentsploit.core import Authorization, Session, TrainingAuth
from agentsploit.version import __version__
from agentsploit.web.auth import require_token
from agentsploit.web.events import get_broker
from agentsploit.web.jobs import JobManager, get_manager

router = APIRouter(prefix="/api", tags=["api"], dependencies=[Depends(require_token)])


# Set by build_app() at server startup.
class _State:
    engagement_dir: Path = Path("./engagements")
    authorization: Authorization | None = None
    """Active engagement authorization, used by write endpoints to scope-check
    every requested target. None means no auth file loaded yet -- write
    endpoints will refuse to run jobs."""


def configure(
    engagement_dir: Path,
    authorization: Authorization | None = None,
) -> None:
    """Called from server.build_app() to set the engagement root + auth context."""
    _State.engagement_dir = engagement_dir.resolve()
    _State.authorization = authorization


# -------------------------------------------------------------- models


class HealthResponse(BaseModel):
    status: str
    version: str
    engagement_dir: str


class SessionSummary(BaseModel):
    session_id: str
    engagement_id: str
    started_at: str | None = None
    finished_at: str | None = None
    finding_count: int
    has_graph: bool
    has_traces: bool


class FindingDTO(BaseModel):
    id: str
    detected_at: str
    module: str
    check: str
    target: str
    severity: int
    severity_label: str
    title: str
    description: str
    remediation: str
    references: list[str]
    tags: list[str]
    evidence: dict[str, Any]


# -------------------------------------------------------------- helpers


def _safe_session_path(session_id: str) -> Path:
    """Resolve `session_id` under the engagement dir, guarding against traversal."""
    if "/" in session_id or "\\" in session_id or ".." in session_id:
        raise HTTPException(status_code=400, detail="invalid session id")
    # The on-disk layout is `<engagement_dir>/<engagement_id>/<session_id>/`.
    # Walk all engagement subdirs to find the session.
    root = _State.engagement_dir
    for engagement in root.iterdir() if root.exists() else []:
        if not engagement.is_dir():
            continue
        candidate = engagement / session_id
        if candidate.is_dir():
            return candidate
    raise HTTPException(status_code=404, detail=f"session {session_id!r} not found")


def _read_manifest(session_dir: Path) -> dict[str, Any]:
    manifest = session_dir / "session.json"
    if not manifest.exists():
        return {}
    try:
        data = json.loads(manifest.read_text())
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def _format_severity_label(level: int | str) -> str:
    if isinstance(level, str):
        return level
    mapping = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
    return mapping.get(int(level), str(level))


# -------------------------------------------------------------- endpoints


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=__version__,
        engagement_dir=str(_State.engagement_dir),
    )


@router.get("/sessions", response_model=list[SessionSummary])
def list_sessions() -> list[SessionSummary]:
    """List every session under the engagement dir, newest first."""
    summaries: list[SessionSummary] = []
    root = _State.engagement_dir
    if not root.exists():
        return summaries

    for engagement in root.iterdir():
        if not engagement.is_dir():
            continue
        for session in engagement.iterdir():
            if not session.is_dir():
                continue
            manifest = _read_manifest(session)
            if not manifest:
                continue
            summaries.append(
                SessionSummary(
                    session_id=str(manifest.get("session_id", session.name)),
                    engagement_id=str(manifest.get("engagement_id", engagement.name)),
                    started_at=manifest.get("started_at") and str(manifest["started_at"]),
                    finished_at=manifest.get("finished_at") and str(manifest["finished_at"]),
                    finding_count=int(manifest.get("finding_count", 0)),
                    has_graph=(session / "permission_graph.json").exists(),
                    has_traces=any(session.glob("trace-*.json")),
                )
            )

    # Newest first (started_at desc, fallback to mtime)
    def _sort_key(s: SessionSummary) -> str:
        return s.started_at or s.finished_at or ""

    summaries.sort(key=_sort_key, reverse=True)
    return summaries


@router.get("/sessions/{session_id}", response_model=SessionSummary)
def get_session(session_id: str) -> SessionSummary:
    session_dir = _safe_session_path(session_id)
    manifest = _read_manifest(session_dir)
    if not manifest:
        raise HTTPException(status_code=404, detail="session manifest not found")
    return SessionSummary(
        session_id=str(manifest.get("session_id", session_id)),
        engagement_id=str(manifest.get("engagement_id", "")),
        started_at=manifest.get("started_at") and str(manifest["started_at"]),
        finished_at=manifest.get("finished_at") and str(manifest["finished_at"]),
        finding_count=int(manifest.get("finding_count", 0)),
        has_graph=(session_dir / "permission_graph.json").exists(),
        has_traces=any(session_dir.glob("trace-*.json")),
    )


@router.get("/sessions/{session_id}/findings", response_model=list[FindingDTO])
def get_findings(session_id: str) -> list[FindingDTO]:
    session_dir = _safe_session_path(session_id)
    manifest = _read_manifest(session_dir)
    findings_raw = manifest.get("findings") or []
    if not isinstance(findings_raw, list):
        return []

    out: list[FindingDTO] = []
    for raw in findings_raw:
        if not isinstance(raw, dict):
            continue
        evidence = raw.get("evidence") or {}
        if not isinstance(evidence, dict):
            evidence = {}
        severity = raw.get("severity", 0)
        sev_int = int(severity) if isinstance(severity, int) else 0
        out.append(
            FindingDTO(
                id=str(raw.get("id", "")),
                detected_at=str(raw.get("detected_at", "")),
                module=str(raw.get("module", "")),
                check=str(raw.get("check", "")),
                target=str(raw.get("target", "")),
                severity=sev_int,
                severity_label=_format_severity_label(sev_int),
                title=str(raw.get("title", "")),
                description=str(raw.get("description", "")),
                remediation=str(raw.get("remediation", "")),
                references=list(raw.get("references") or []),
                tags=list(raw.get("tags") or []),
                evidence=dict(evidence),
            )
        )

    out.sort(key=lambda f: -f.severity)
    return out


@router.get("/sessions/{session_id}/graph")
def get_graph(session_id: str) -> JSONResponse:
    """Returns the permission_graph.json contents verbatim if present."""
    session_dir = _safe_session_path(session_id)
    graph_path = session_dir / "permission_graph.json"
    if not graph_path.exists():
        raise HTTPException(status_code=404, detail="this session has no permission graph")
    try:
        data = json.loads(graph_path.read_text())
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"invalid graph JSON: {e}") from e
    return JSONResponse(content=data)


@router.get("/sessions/{session_id}/traces")
def list_traces(session_id: str) -> dict[str, list[dict[str, str]]]:
    """List trace artifacts in this session."""
    session_dir = _safe_session_path(session_id)
    traces: list[dict[str, str]] = []
    for path in sorted(session_dir.glob("*-*.json")):
        if path.name == "session.json" or path.name == "permission_graph.json":
            continue
        traces.append(
            {
                "filename": path.name,
                "size_bytes": str(path.stat().st_size),
                "modified_at": datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
            }
        )
    return {"traces": traces}


@router.get("/sessions/{session_id}/traces/{trace_filename}")
def get_trace(session_id: str, trace_filename: str) -> JSONResponse:
    if "/" in trace_filename or "\\" in trace_filename or ".." in trace_filename:
        raise HTTPException(status_code=400, detail="invalid trace filename")
    session_dir = _safe_session_path(session_id)
    trace_path = session_dir / trace_filename
    if not trace_path.exists() or trace_path.suffix != ".json":
        raise HTTPException(status_code=404, detail="trace not found")
    try:
        data = json.loads(trace_path.read_text())
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"invalid trace JSON: {e}") from e
    return JSONResponse(content=data)


# -------------------------------------------------------------- v1.6: paths


class PathSummary(BaseModel):
    """One row in the path-explorer table."""

    id: str
    source_name: str
    source_server_uri: str
    sink_name: str
    sink_server_uri: str
    sink_privilege: int
    sink_privilege_label: str
    length: int
    total_weight: float
    severity_score: int
    render: str


_PRIVILEGE_LABELS = ["read", "internal_action", "egress", "mutation", "execution"]


@router.get("/sessions/{session_id}/paths", response_model=list[PathSummary])
def list_paths(session_id: str) -> list[PathSummary]:
    """List the attack paths discovered by `map build` for this session.

    Reads ``paths.json`` produced by the v1.6 mapper. Sessions written by
    earlier versions do not have this artefact; for those we return an
    empty list rather than 404, so the UI can fall back to the graph view.
    """
    session_dir = _safe_session_path(session_id)
    paths_path = session_dir / "paths.json"
    if not paths_path.exists():
        return []
    try:
        blob = json.loads(paths_path.read_text())
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"invalid paths JSON: {e}") from e
    items = blob.get("paths") or []
    out: list[PathSummary] = []
    for raw in items:
        if not isinstance(raw, dict):
            continue
        source = raw.get("source") or {}
        sink = raw.get("sink") or {}
        privilege = int(sink.get("privilege", 0))
        label = (
            _PRIVILEGE_LABELS[privilege]
            if 0 <= privilege < len(_PRIVILEGE_LABELS)
            else str(privilege)
        )
        out.append(
            PathSummary(
                id=str(raw.get("id", "")),
                source_name=str(source.get("name", "")),
                source_server_uri=str(source.get("server_uri", "")),
                sink_name=str(sink.get("name", "")),
                sink_server_uri=str(sink.get("server_uri", "")),
                sink_privilege=privilege,
                sink_privilege_label=label,
                length=int(raw.get("length", 0)),
                total_weight=float(raw.get("total_weight", 0.0)),
                severity_score=int(raw.get("severity_score", 0)),
                render=str(raw.get("render", "")),
            )
        )
    out.sort(key=lambda p: -p.severity_score)
    return out


# -------------------------------------------------------------- v1.6: jobs


class ScanRequest(BaseModel):
    target_uri: str
    checks: list[str] | None = None
    headers: list[str] | None = None
    bearer_token: str | None = None
    bearer_env: str | None = None
    insecure: bool = False
    timeout: float = 30.0


class VerifyRequest(BaseModel):
    source_session_id: str = Field(
        ...,
        description="The map-session whose paths.json contains the path to verify.",
    )
    path_id: str
    agent_config_path: str | None = None
    sink_arg: str | None = None


class JobAccepted(BaseModel):
    job_id: str
    status: str
    session_id: str


def _require_authorization() -> Authorization:
    auth = _State.authorization
    if auth is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "server started without an authorization context; "
                "restart with `agentsploit serve --auth <file>` or `--training`"
            ),
        )
    return auth


def _new_session(auth: Authorization) -> Session:
    return Session(authorization=auth, output_dir=_State.engagement_dir)


@router.post("/jobs/scan", response_model=JobAccepted, status_code=202)
async def submit_scan_job(req: ScanRequest) -> JobAccepted:
    """Queue an MCP scan against a target. Returns immediately with a job_id."""
    from agentsploit.core.authorization import AuthorizationError
    from agentsploit.web.runners import get_runner

    auth = _require_authorization()
    try:
        auth.check(req.target_uri)
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=str(e)) from e

    session = _new_session(auth)
    manager: JobManager = get_manager()
    record = await manager.submit(
        kind="scan",
        label=f"scan {req.target_uri}",
        request=req.model_dump(),
        runner=get_runner("scan"),
        session=session,
    )
    return JobAccepted(job_id=record.id, status=record.status.value, session_id=session.id)


@router.post("/jobs/verify", response_model=JobAccepted, status_code=202)
async def submit_verify_job(req: VerifyRequest) -> JobAccepted:
    """Queue a path-verification job. Returns immediately with a job_id."""
    from agentsploit.web.runners import get_runner

    auth = _require_authorization()
    # Ensure the source session is reachable so we fail-fast instead of in the runner.
    _safe_session_path(req.source_session_id)

    session = _new_session(auth)
    manager = get_manager()
    record = await manager.submit(
        kind="verify",
        label=f"verify path {req.path_id}",
        request=req.model_dump(),
        runner=get_runner("verify"),
        session=session,
    )
    return JobAccepted(job_id=record.id, status=record.status.value, session_id=session.id)


@router.get("/jobs")
async def list_jobs() -> list[dict[str, Any]]:
    return [j.to_dict() for j in await get_manager().list()]


@router.get("/jobs/{job_id}")
async def get_job(job_id: str) -> dict[str, Any]:
    job = await get_manager().get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job.to_dict()


@router.post("/jobs/{job_id}/cancel", status_code=202)
async def cancel_job(job_id: str) -> dict[str, Any]:
    ok = await get_manager().cancel(job_id)
    if not ok:
        raise HTTPException(status_code=404, detail="job not running or not found")
    return {"job_id": job_id, "status": "cancelling"}


# -------------------------------------------------------------- v1.6: SSE


@router.get("/events")
async def stream_events() -> StreamingResponse:
    """Server-Sent Events: job + finding events from the broker.

    Subscribers get a personal queue; slow consumers cause oldest-drop
    on their queue only (see web/events.EventBroker).
    """
    broker = get_broker()

    async def _gen() -> Any:
        # Initial comment keeps the connection open through reverse proxies
        # while there are no events.
        yield ": ok\n\n"
        try:
            async for evt in broker.subscribe():
                line = json.dumps(evt.to_sse_data())
                yield f"event: {evt.type}\ndata: {line}\n\n"
        except asyncio.CancelledError:  # client disconnected
            return

    return StreamingResponse(
        _gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",  # nginx
        },
    )


# Re-export TrainingAuth so tests can import it through the api module.
__all__ = ["TrainingAuth", "configure", "router"]
