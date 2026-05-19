"""Auth + token persistence tests for the v1.6 web UI."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentsploit.web.auth import load_or_create_token
from agentsploit.web.server import build_app


def test_load_or_create_token_persists(tmp_path: Path) -> None:
    p = tmp_path / "web-token"
    t1 = load_or_create_token(p)
    t2 = load_or_create_token(p)
    assert t1 == t2
    assert p.exists()
    # urlsafe 32-byte tokens are 43 chars.
    assert len(t1) >= 30


def test_load_or_create_token_chmod_600(tmp_path: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("POSIX-only: chmod has no effect on Windows ACLs")
    p = tmp_path / "web-token"
    load_or_create_token(p)
    assert oct(p.stat().st_mode)[-3:] == "600"


def test_missing_token_returns_401(tmp_path: Path) -> None:
    app = build_app(tmp_path, auth_enabled=True, token="secret")
    c = TestClient(app)
    r = c.get("/api/health")
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate") == "Bearer"


def test_wrong_token_returns_403(tmp_path: Path) -> None:
    app = build_app(tmp_path, auth_enabled=True, token="secret")
    c = TestClient(app)
    r = c.get("/api/health", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 403


def test_correct_token_passes(tmp_path: Path) -> None:
    app = build_app(tmp_path, auth_enabled=True, token="secret")
    c = TestClient(app)
    r = c.get("/api/health", headers={"Authorization": "Bearer secret"})
    assert r.status_code == 200


def test_token_via_query_param(tmp_path: Path) -> None:
    """EventSource can't set headers - the SSE endpoint accepts ?token=."""
    app = build_app(tmp_path, auth_enabled=True, token="secret")
    c = TestClient(app)
    r = c.get("/api/health?token=secret")
    assert r.status_code == 200


def test_no_auth_mode_passes_without_token(tmp_path: Path) -> None:
    app = build_app(tmp_path, auth_enabled=False)
    c = TestClient(app)
    assert c.get("/api/health").status_code == 200


def test_auth_enabled_but_no_token_is_503(tmp_path: Path) -> None:
    """Misconfiguration: enabled but no token set should refuse, not allow through."""
    app = build_app(tmp_path, auth_enabled=True, token=None)
    c = TestClient(app)
    # any candidate token still hits the 503 path because expected is None
    r = c.get("/api/health", headers={"Authorization": "Bearer whatever"})
    assert r.status_code == 503


def test_non_ascii_token_does_not_500() -> None:
    """A non-ASCII candidate token must yield 403, not crash with 500.

    Regression: `secrets.compare_digest` raises TypeError on non-ASCII str
    inputs. Real HTTP clients can't send a non-ASCII Authorization header
    value, but the bug also fires if the on-disk token file gets corrupted
    with non-ASCII bytes. Call the dependency directly so we don't rely on
    httpx (which itself refuses to encode non-ASCII headers).
    """
    from fastapi import HTTPException

    from agentsploit.web.auth import configure as auth_configure
    from agentsploit.web.auth import require_token

    auth_configure(token="ascii-token", enabled=True)
    try:
        with pytest.raises(HTTPException) as exc:
            require_token(authorization="Bearer pässwörd", token_query=None)
        assert exc.value.status_code == 403
    finally:
        auth_configure(token=None, enabled=False)


def test_serve_refuses_off_loopback_without_auth(tmp_path: Path) -> None:
    """`agentsploit serve --host 0.0.0.0 --no-auth` should hard-fail."""
    from agentsploit.web.server import serve

    with pytest.raises(RuntimeError, match="Refusing to bind"):
        serve(host="0.0.0.0", port=18801, engagement_dir=tmp_path, auth_enabled=False)
