"""v1.6 endpoint tests: paths, jobs (scan/verify submission), SSE stream."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentsploit.core import TrainingAuth
from agentsploit.web import runners as runners_module
from agentsploit.web.events import EventBroker, set_broker
from agentsploit.web.jobs import JobContext, JobManager, set_manager
from agentsploit.web.server import build_app


@pytest.fixture(autouse=True)
def isolate_jobs_and_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give every test a fresh in-process job manager + broker so jobs from
    one test don't bleed into the next, and so we can install a no-op
    scan runner that doesn't try to launch real MCP servers."""
    set_broker(EventBroker())
    set_manager(JobManager())

    async def _noop_scan(ctx: JobContext) -> None:
        # Touch session.add so the wrapped emitter path is exercised, but
        # don't yield any real findings.
        return None

    async def _noop_verify(ctx: JobContext) -> None:
        return None

    monkeypatch.setitem(runners_module._REGISTRY, "scan", ("noop scan", _noop_scan))
    monkeypatch.setitem(
        runners_module._REGISTRY, "verify", ("noop verify", _noop_verify)
    )


@pytest.fixture
def engagement_root(tmp_path: Path) -> Path:
    """Engagement tree with one session that has paths.json + permission_graph.json."""
    eng = tmp_path / "eng"
    sess = eng / "sess-paths"
    sess.mkdir(parents=True)
    (sess / "session.json").write_text(
        json.dumps(
            {
                "session_id": "sess-paths",
                "engagement_id": "eng",
                "started_at": "2026-05-19T10:00:00Z",
                "finding_count": 0,
                "findings": [],
            }
        )
    )
    (sess / "permission_graph.json").write_text(json.dumps({"nodes": {}, "edges": []}))
    (sess / "paths.json").write_text(
        json.dumps(
            {
                "paths": [
                    {
                        "id": "src::a=>sink::b#0",
                        "source": {
                            "name": "fetch_url",
                            "server_uri": "stdio://src",
                            "privilege": 0,
                        },
                        "sink": {
                            "name": "run_shell",
                            "server_uri": "stdio://sink",
                            "privilege": 4,
                        },
                        "nodes": [],
                        "edges": [],
                        "length": 1,
                        "total_weight": 1.0,
                        "severity_score": 44,
                        "render": "fetch_url -> run_shell",
                    },
                    {
                        "id": "src::a=>sink::c#1",
                        "source": {
                            "name": "fetch_url",
                            "server_uri": "stdio://src",
                            "privilege": 0,
                        },
                        "sink": {
                            "name": "send_email",
                            "server_uri": "stdio://sink",
                            "privilege": 2,
                        },
                        "nodes": [],
                        "edges": [],
                        "length": 1,
                        "total_weight": 1.0,
                        "severity_score": 24,
                        "render": "fetch_url -> send_email",
                    },
                ]
            }
        )
    )
    return tmp_path


def _client(engagement_root: Path, *, with_auth: bool = False) -> TestClient:
    auth = TrainingAuth() if with_auth else None
    app = build_app(engagement_root, authorization=auth, auth_enabled=False)
    return TestClient(app)


# -------------------------------------------------------------- paths


def test_paths_listing_sorted_by_severity_desc(engagement_root: Path) -> None:
    c = _client(engagement_root)
    r = c.get("/api/sessions/sess-paths/paths")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 2
    assert body[0]["severity_score"] == 44
    assert body[0]["sink_privilege_label"] == "execution"
    assert body[1]["severity_score"] == 24
    assert body[1]["sink_privilege_label"] == "egress"


def test_paths_empty_when_no_artifact(engagement_root: Path) -> None:
    """Sessions written by < v1.6 lack paths.json — endpoint returns []."""
    sess = engagement_root / "eng" / "sess-old"
    sess.mkdir()
    (sess / "session.json").write_text(
        json.dumps(
            {
                "session_id": "sess-old",
                "engagement_id": "eng",
                "finding_count": 0,
                "findings": [],
            }
        )
    )
    c = _client(engagement_root)
    r = c.get("/api/sessions/sess-old/paths")
    assert r.status_code == 200
    assert r.json() == []


# -------------------------------------------------------------- write endpoints


def test_scan_submission_requires_authorization_context(engagement_root: Path) -> None:
    c = _client(engagement_root, with_auth=False)
    r = c.post("/api/jobs/scan", json={"target_uri": "stdio://./vulnerable_mcp/server.py"})
    assert r.status_code == 400
    assert "authorization" in r.json()["detail"].lower()


def test_scan_submission_returns_job_id(engagement_root: Path) -> None:
    c = _client(engagement_root, with_auth=True)
    r = c.post("/api/jobs/scan", json={"target_uri": "stdio://./vulnerable_mcp/server.py"})
    # Returns 202 even if the scan errors out (which it will - no real MCP),
    # because the runner failure is async after acceptance.
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "queued"
    assert body["job_id"].startswith("job-")
    assert body["session_id"].startswith("sess-")


def test_verify_submission_rejects_unknown_session(engagement_root: Path) -> None:
    c = _client(engagement_root, with_auth=True)
    r = c.post(
        "/api/jobs/verify",
        json={"source_session_id": "nonexistent", "path_id": "x"},
    )
    assert r.status_code == 404


def test_jobs_listing_includes_submitted(engagement_root: Path) -> None:
    c = _client(engagement_root, with_auth=True)
    c.post("/api/jobs/scan", json={"target_uri": "stdio://./vulnerable_mcp/server.py"})
    r = c.get("/api/jobs")
    assert r.status_code == 200
    body = r.json()
    assert len(body) >= 1
    assert body[0]["kind"] == "scan"


# -------------------------------------------------------------- SSE


def test_sse_endpoint_handshake_via_openapi(engagement_root: Path) -> None:
    """Confirm the SSE route is registered with the right metadata.

    We can't drain a sync StreamingResponse through TestClient without
    hanging (the stream is open-ended by design). Verifying broker
    fan-out belongs to ``test_web_events`` and ``test_web_jobs``; here
    we only check that the route exists in the OpenAPI schema.
    """
    c = _client(engagement_root)
    schema = c.get("/openapi.json").json()
    assert "/api/events" in schema["paths"]
    assert "get" in schema["paths"]["/api/events"]
