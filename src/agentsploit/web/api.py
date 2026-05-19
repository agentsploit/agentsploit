"""REST API for AgentSploit's web UI.

All read-only as of v1.5. Write endpoints (trigger scans/verifies from the
UI) land in v1.6 alongside the live-engagement dashboard.

The API reads from a configurable engagement-output directory (defaults to
`./engagements/` in the CWD). Every endpoint is path-traversal-safe.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from agentsploit.version import __version__

router = APIRouter(prefix="/api", tags=["api"])


# Set by build_app() at server startup.
class _State:
    engagement_dir: Path = Path("./engagements")


def configure(engagement_dir: Path) -> None:
    """Called from server.build_app() to set the engagement root."""
    _State.engagement_dir = engagement_dir.resolve()


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
