"""Credentials abstraction tests."""

from __future__ import annotations

import pytest

from agentsploit.modules.mcp.auth import Credentials


def test_merged_headers_adds_bearer_and_user_agent() -> None:
    creds = Credentials(bearer_token="tok123")
    headers = creds.merged_headers()
    assert headers["Authorization"] == "Bearer tok123"
    assert "agentsploit/" in headers["User-Agent"]


def test_existing_authorization_header_is_not_overwritten() -> None:
    creds = Credentials(
        headers={"Authorization": "Basic abc"},
        bearer_token="ignoredbecauseheaderwins",
    )
    headers = creds.merged_headers()
    assert headers["Authorization"] == "Basic abc"


def test_from_cli_parses_repeated_headers() -> None:
    creds = Credentials.from_cli(
        headers=["X-Tenant: acme", "X-Env:prod"],
        timeout=10.0,
    )
    assert creds.headers == {"X-Tenant": "acme", "X-Env": "prod"}
    assert creds.timeout_seconds == 10.0


def test_from_cli_rejects_malformed_header() -> None:
    with pytest.raises(ValueError, match="Invalid header"):
        Credentials.from_cli(headers=["no-colon-here"])


def test_from_cli_resolves_bearer_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_TOKEN", "from-env-value")
    creds = Credentials.from_cli(bearer_env="MY_TOKEN")
    assert creds.bearer_token == "from-env-value"


def test_from_cli_missing_bearer_env_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DOES_NOT_EXIST", raising=False)
    with pytest.raises(ValueError, match="not set"):
        Credentials.from_cli(bearer_env="DOES_NOT_EXIST")


def test_insecure_disables_tls_verification() -> None:
    creds = Credentials.from_cli(insecure=True)
    assert creds.verify_tls is False
