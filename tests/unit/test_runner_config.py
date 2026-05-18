"""RunnerConfig validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agentsploit.modules.runner.config import RunnerConfig
from agentsploit.modules.runner.tools import MockTool


def _base_config(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "provider": "mock",
        "model": "mock-1",
        "trigger_prompt": "read x.pdf",
        "mock_tools": [
            {"name": "read_document", "description": "...", "returns_payload": True},
        ],
    }
    base.update(overrides)
    return base


def test_minimal_valid_config_parses() -> None:
    cfg = RunnerConfig.model_validate(_base_config())
    assert cfg.provider == "mock"
    assert cfg.mock_tools[0].name == "read_document"
    assert cfg.mock_tools[0].returns_payload is True


def test_unknown_provider_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown provider"):
        RunnerConfig.model_validate(_base_config(provider="cohere"))


def test_no_payload_tool_rejected() -> None:
    with pytest.raises(ValueError, match="returns_payload: true"):
        RunnerConfig.model_validate(
            _base_config(mock_tools=[{"name": "x", "description": "y", "returns_payload": False}])
        )


def test_multiple_payload_tools_rejected() -> None:
    with pytest.raises(ValueError, match="Only one mock_tool"):
        RunnerConfig.model_validate(
            _base_config(
                mock_tools=[
                    {"name": "a", "description": "1", "returns_payload": True},
                    {"name": "b", "description": "2", "returns_payload": True},
                ]
            )
        )


def test_resolve_api_key_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_KEY", "secret123")
    cfg = RunnerConfig.model_validate(_base_config(api_key_env="MY_KEY"))
    assert cfg.resolve_api_key() == "secret123"


def test_resolve_api_key_missing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NOPE", raising=False)
    cfg = RunnerConfig.model_validate(_base_config(api_key_env="NOPE"))
    with pytest.raises(ValueError, match="not set"):
        cfg.resolve_api_key()


def test_target_uri_synthesis() -> None:
    cfg = RunnerConfig.model_validate(_base_config(provider="anthropic", model="claude-sonnet-4-6"))
    assert cfg.target_uri() == "agent+anthropic://claude-sonnet-4-6"


def test_load_from_yaml(tmp_path: Path) -> None:
    cfg_path = tmp_path / "agent.yaml"
    cfg_path.write_text(yaml.safe_dump(_base_config()))
    cfg = RunnerConfig.load(cfg_path)
    assert cfg.provider == "mock"


def test_default_document_reader_present_by_default() -> None:
    cfg = RunnerConfig.model_validate({"provider": "mock", "model": "x", "trigger_prompt": "y"})
    assert len(cfg.mock_tools) == 1
    assert cfg.mock_tools[0].name == "read_document"
    assert isinstance(cfg.mock_tools[0], MockTool)
