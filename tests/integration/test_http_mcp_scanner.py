"""Integration test - boot the vulnerable HTTP MCP fixture, scan it, verify findings."""

from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
from collections.abc import Iterator

import httpx
import pytest
import uvicorn

from agentsploit.core import Session, Target
from agentsploit.modules.mcp.auth import Credentials
from agentsploit.modules.mcp.scanner import MCPScanner
from tests.fixtures.vulnerable_http_mcp.server import build_app, find_free_port

pytestmark = pytest.mark.integration


class _ServerThread(threading.Thread):
    """Run uvicorn on a background thread; expose `.url` once ready."""

    def __init__(self, port: int) -> None:
        super().__init__(daemon=True)
        self.port = port
        self.url = f"http://127.0.0.1:{port}/mcp"
        config = uvicorn.Config(
            app=build_app(port),
            host="127.0.0.1",
            port=port,
            log_level="warning",
            loop="asyncio",
        )
        self._server = uvicorn.Server(config)

    def run(self) -> None:
        asyncio.run(self._server.serve())

    def stop(self) -> None:
        self._server.should_exit = True


@contextlib.contextmanager
def _running_fixture() -> Iterator[str]:
    port = find_free_port()
    thread = _ServerThread(port)
    thread.start()

    # Poll until the server accepts TCP - uvicorn boot is asynchronous.
    deadline = 5.0
    step = 0.05
    waited = 0.0
    while waited < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            pass
        threading.Event().wait(step)
        waited += step
    else:
        thread.stop()
        raise RuntimeError("fixture server failed to start within 5s")

    try:
        yield thread.url
    finally:
        thread.stop()
        thread.join(timeout=3)


@pytest.fixture()
def running_http_fixture() -> Iterator[str]:
    with _running_fixture() as url:
        yield url


async def test_scanner_against_vulnerable_http_fixture(
    session: Session, running_http_fixture: str
) -> None:
    target = Target.parse(running_http_fixture)
    creds = Credentials(bearer_token="fake-token-for-auth-bypass-probe", timeout_seconds=5.0)
    scanner = MCPScanner(credentials=creds)

    async for finding in scanner.run(target, session):
        session.add(finding)

    checks_fired = {f.check for f in session.findings}

    # Inventory checks should still fire over HTTP (we got the same poisoned
    # tool definitions back).
    assert "tool_poisoning" in checks_fired, "expected inventory check via HTTP"
    assert "tool_shadowing" in checks_fired
    assert "prompt_disclosure" in checks_fired
    assert "unsafe_tool_args" in checks_fired

    # HTTP probes that should fire against this fixture:
    assert "http_info_disclosure" in checks_fired, "leaky Server header missed"
    assert "http_cors" in checks_fired, "wildcard CORS + credentials missed"
    assert "http_auth_bypass" in checks_fired, "unauthenticated initialize accepted but not flagged"

    # The fixture is on localhost so tls_required should NOT fire.
    assert "http_tls_required" not in checks_fired

    # Starlette's CORS middleware auto-rewrites `*` + credentials to a
    # reflected Origin (spec-safe behaviour). Our probe picks that up as
    # HIGH-severity origin reflection.
    cors = [f for f in session.findings if f.check == "http_cors"]
    assert any(f.severity.label == "high" for f in cors), [
        (f.severity.label, f.title) for f in cors
    ]


async def test_fixture_serves_unauthenticated_initialize(running_http_fixture: str) -> None:
    """Sanity check: the fixture really does accept unauth - without this the
    auth-bypass assertion above is meaningless."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "smoke", "version": "0.0"},
        },
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.post(running_http_fixture, json=payload, headers=headers)
    assert resp.status_code == 200
