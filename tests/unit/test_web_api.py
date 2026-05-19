"""REST API unit tests for the web UI server."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentsploit.version import __version__
from agentsploit.web.server import build_app


@pytest.fixture
def engagement_root(tmp_path: Path) -> Path:
    """Lay out a fake engagement tree with two sessions: one full, one empty."""
    eng = tmp_path / "eng-2025-q4"
    sess_a = eng / "sess-aaaa"
    sess_b = eng / "sess-bbbb"
    sess_a.mkdir(parents=True)
    sess_b.mkdir(parents=True)

    (sess_a / "session.json").write_text(
        json.dumps(
            {
                "session_id": "sess-aaaa",
                "engagement_id": "eng-2025-q4",
                "started_at": "2026-05-18T10:00:00Z",
                "finished_at": "2026-05-18T10:05:00Z",
                "finding_count": 2,
                "findings": [
                    {
                        "id": "f1",
                        "detected_at": "2026-05-18T10:01:00Z",
                        "module": "injection_generator",
                        "check": "tool_smuggling",
                        "target": "stdio://mcp-server",
                        "severity": 3,
                        "title": "Tool-smuggling injection accepted",
                        "description": "Agent executed an injected tool call.",
                        "remediation": "Validate tool descriptions.",
                        "references": ["OWASP-LLM01"],
                        "tags": ["prompt-injection"],
                        "evidence": {"canary": "AGS-CANARY-1"},
                    },
                    {
                        "id": "f2",
                        "detected_at": "2026-05-18T10:02:00Z",
                        "module": "scanner",
                        "check": "exposed_secret",
                        "target": "stdio://mcp-server",
                        "severity": 2,
                        "title": "Secret in tool description",
                        "description": "AWS access key found.",
                        "remediation": "Rotate the key.",
                        "references": [],
                        "tags": [],
                        "evidence": {},
                    },
                ],
            }
        )
    )
    (sess_a / "permission_graph.json").write_text(
        json.dumps({"nodes": {}, "edges": []})
    )
    (sess_a / "trace-001.json").write_text(json.dumps({"messages": []}))

    # sess-bbbb has only a manifest, no graph, no traces, no findings
    (sess_b / "session.json").write_text(
        json.dumps(
            {
                "session_id": "sess-bbbb",
                "engagement_id": "eng-2025-q4",
                "started_at": "2026-05-17T08:00:00Z",
                "finding_count": 0,
                "findings": [],
            }
        )
    )

    return tmp_path


@pytest.fixture
def client(engagement_root: Path) -> TestClient:
    app = build_app(engagement_root)
    return TestClient(app)


def test_health(client: TestClient) -> None:
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["version"] == __version__


def test_sessions_lists_both_newest_first(client: TestClient) -> None:
    r = client.get("/api/sessions")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 2
    # sess-aaaa started later -> first
    assert body[0]["session_id"] == "sess-aaaa"
    assert body[0]["finding_count"] == 2
    assert body[0]["has_graph"] is True
    assert body[0]["has_traces"] is True
    assert body[1]["session_id"] == "sess-bbbb"
    assert body[1]["has_graph"] is False
    assert body[1]["has_traces"] is False


def test_session_detail(client: TestClient) -> None:
    r = client.get("/api/sessions/sess-aaaa")
    assert r.status_code == 200
    assert r.json()["finding_count"] == 2


def test_session_not_found(client: TestClient) -> None:
    r = client.get("/api/sessions/nope")
    assert r.status_code == 404


def test_findings_sorted_by_severity_desc(client: TestClient) -> None:
    r = client.get("/api/sessions/sess-aaaa/findings")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 2
    assert body[0]["severity"] == 3
    assert body[0]["severity_label"] == "high"
    assert body[1]["severity"] == 2
    assert body[1]["severity_label"] == "medium"


def test_graph_returns_json(client: TestClient) -> None:
    r = client.get("/api/sessions/sess-aaaa/graph")
    assert r.status_code == 200
    assert r.json() == {"nodes": {}, "edges": []}


def test_graph_missing(client: TestClient) -> None:
    r = client.get("/api/sessions/sess-bbbb/graph")
    assert r.status_code == 404


def test_traces_list(client: TestClient) -> None:
    r = client.get("/api/sessions/sess-aaaa/traces")
    assert r.status_code == 200
    traces = r.json()["traces"]
    assert len(traces) == 1
    assert traces[0]["filename"] == "trace-001.json"


def test_trace_content(client: TestClient) -> None:
    r = client.get("/api/sessions/sess-aaaa/traces/trace-001.json")
    assert r.status_code == 200
    assert r.json() == {"messages": []}


def test_trace_path_traversal_blocked(client: TestClient) -> None:
    r = client.get("/api/sessions/sess-aaaa/traces/..%2F..%2Fetc%2Fpasswd")
    # Either 400 (filename validator) or 404 (FastAPI route mismatch). Either way, not 200.
    assert r.status_code in (400, 404)


def test_session_id_path_traversal_blocked(client: TestClient) -> None:
    # Path-shaped ids never reach the routing handler — they trigger the
    # 'not found' branch in the path matcher. Confirm we don't 200 / leak.
    r = client.get("/api/sessions/..%2F..%2Fetc")
    assert r.status_code in (400, 404)


def test_empty_engagement_root(tmp_path: Path) -> None:
    app = build_app(tmp_path / "does-not-exist")
    c = TestClient(app)
    r = c.get("/api/sessions")
    assert r.status_code == 200
    assert r.json() == []
