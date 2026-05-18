"""Shared test fixtures."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentsploit.core import Authorization, Session, registry


@pytest.fixture(autouse=True)
def _discover_modules() -> None:
    registry.discover()


@pytest.fixture()
def authorization() -> Authorization:
    now = datetime.now(UTC)
    return Authorization(
        authorized_by="test@example.com",
        authorized_at=now,
        valid_until=now + timedelta(days=1),
        engagement_id="test-eng",
        targets=["stdio://*", "http://localhost*"],
        forbidden=["*production*"],
    )


@pytest.fixture()
def session(authorization: Authorization, tmp_path: Path) -> Session:
    return Session(authorization=authorization, output_dir=tmp_path)


@pytest.fixture()
def vulnerable_fixture_uri() -> str:
    fixture = Path(__file__).parent / "fixtures" / "vulnerable_mcp" / "server.py"
    return f"stdio://{fixture}"
