"""Authorization model tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentsploit.core import Authorization, AuthorizationError, TrainingAuth


def _make(targets: list[str], **overrides: object) -> Authorization:
    now = datetime.now(UTC)
    defaults: dict[str, object] = {
        "authorized_by": "x@example.com",
        "authorized_at": now,
        "valid_until": now + timedelta(days=1),
        "targets": targets,
    }
    defaults.update(overrides)
    return Authorization(**defaults)  # type: ignore[arg-type]


def test_check_allows_matching_target() -> None:
    auth = _make(["stdio://*", "http://localhost*"])
    auth.check("stdio://./server.py")
    auth.check("http://localhost:8080")


def test_check_denies_non_matching_target() -> None:
    auth = _make(["stdio://*"])
    with pytest.raises(AuthorizationError, match="not in authorized scope"):
        auth.check("http://example.com")


def test_check_denies_forbidden_first() -> None:
    auth = _make(["http://*"], forbidden=["*production*"])
    with pytest.raises(AuthorizationError, match="forbidden pattern"):
        auth.check("http://api.production.example.com")


def test_check_expired() -> None:
    now = datetime.now(UTC)
    auth = _make(
        ["*"],
        authorized_at=now - timedelta(days=2),
        valid_until=now - timedelta(seconds=1),
    )
    with pytest.raises(AuthorizationError, match="expired"):
        auth.check("anything")


def test_targets_must_be_non_empty() -> None:
    with pytest.raises(ValueError, match="at least one pattern"):
        _make([])


def test_round_trip_load_save(tmp_path: Path) -> None:
    auth = _make(["stdio://*"], scope_notes="round-trip")
    path = tmp_path / "auth.yaml"
    auth.save(path)
    loaded = Authorization.load(path)
    assert loaded.authorized_by == auth.authorized_by
    assert loaded.targets == auth.targets
    assert loaded.source_hash == auth.source_hash
    assert loaded.source_hash != "unsaved"


def test_training_auth_allows_localhost_and_fixture() -> None:
    auth = TrainingAuth()
    auth.check("http://localhost:8000")
    auth.check("stdio://tests/fixtures/vulnerable_mcp/server.py")


def test_training_auth_rejects_arbitrary_target() -> None:
    auth = TrainingAuth()
    with pytest.raises(AuthorizationError):
        auth.check("http://example.com")
