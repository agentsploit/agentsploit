"""Smoke test: verify the packaged frontend bundle is discoverable.

This isn't a strict requirement — running from source without `npm run build`
is supported and serves a graceful fallback page — but if the bundle IS
present it must be wired correctly so the wheel ships a working UI.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from agentsploit.web.server import _frontend_dir, build_app


def test_frontend_dir_resolves() -> None:
    """`_frontend_dir` should never raise; may return None if not built."""
    p = _frontend_dir()
    assert p is None or isinstance(p, Path)


def test_spa_serves_index_when_bundle_present(tmp_path: Path) -> None:
    """If the frontend bundle is built, requesting / returns the SPA shell."""
    frontend = _frontend_dir()
    if frontend is None or not (frontend / "index.html").exists():
        import pytest

        pytest.skip("frontend bundle not built; run `cd ui && npm run build`")

    app = build_app(tmp_path, auth_enabled=False)
    c = TestClient(app)
    r = c.get("/")
    assert r.status_code == 200
    # Vite-built shells embed a module script tag — close enough to recognise
    # we got the bundle and not the fallback page.
    body = r.text.lower()
    assert "<!doctype html>" in body
    assert "agentsploit" in body or 'id="root"' in body


def test_api_route_takes_priority_over_spa(tmp_path: Path) -> None:
    """The catch-all SPA route must not swallow /api/* requests."""
    app = build_app(tmp_path, auth_enabled=False)
    c = TestClient(app)
    r = c.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
