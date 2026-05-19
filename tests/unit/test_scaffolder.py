"""Scaffolder unit tests: template rendering + generated-file validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsploit.core.authorization import Authorization
from agentsploit.modules.runner.config import RunnerConfig
from agentsploit.scaffolder import ScaffoldError, scaffold_engagement


def test_creates_full_engagement_directory(tmp_path: Path) -> None:
    target = tmp_path / "engagement-q2"
    written = scaffold_engagement(target, authorized_by="Jane <jane@example.com>", valid_days=14)
    names = {p.name for p in written}
    assert names == {
        "authorization.yaml",
        "agent-anthropic.yaml",
        "agent-openai.yaml",
        "agent-http.yaml",
        "map-targets.yaml",
        "README.md",
        ".gitignore",
    }
    for path in written:
        assert path.exists() and path.is_file()
        assert path.read_text().strip(), f"{path.name} is empty"


def test_refuses_to_overwrite_non_empty_dir(tmp_path: Path) -> None:
    target = tmp_path / "existing"
    target.mkdir()
    (target / "do-not-clobber").write_text("important data")

    with pytest.raises(ScaffoldError, match="not empty"):
        scaffold_engagement(target, authorized_by="x")
    # Existing file preserved
    assert (target / "do-not-clobber").read_text() == "important data"


def test_force_overwrites_existing_files(tmp_path: Path) -> None:
    target = tmp_path / "existing"
    target.mkdir()
    (target / "authorization.yaml").write_text("stale: content")
    (target / "unrelated-file").write_text("keep me")

    written = scaffold_engagement(target, force=True)
    # Authorization was rewritten by the scaffolder
    assert "stale: content" not in (target / "authorization.yaml").read_text()
    # Unrelated existing files left alone
    assert (target / "unrelated-file").read_text() == "keep me"
    assert len(written) == 7


def test_empty_dir_is_writable_without_force(tmp_path: Path) -> None:
    """Creating into a fresh empty dir should not trip the non-empty check."""
    target = tmp_path / "fresh"
    target.mkdir()  # exists but empty
    written = scaffold_engagement(target)
    assert len(written) == 7


def test_generated_authorization_yaml_loads_via_real_loader(tmp_path: Path) -> None:
    """Round-trip: the scaffolded auth YAML must validate through the
    real Authorization.load() pipeline. Catches template syntax drift."""
    target = tmp_path / "engagement"
    scaffold_engagement(
        target,
        authorized_by="Round-trip Tester <rt@example.com>",
        engagement_id="rt-test-001",
        valid_days=7,
    )
    auth = Authorization.load(target / "authorization.yaml")
    assert auth.authorized_by == "Round-trip Tester <rt@example.com>"
    assert auth.engagement_id == "rt-test-001"
    # source_hash gets populated as a side effect of loading
    assert auth.source_hash != "unsaved"


def test_generated_agent_configs_load_via_real_loader(tmp_path: Path) -> None:
    """Round-trip: all three agent YAMLs must load cleanly."""
    target = tmp_path / "engagement"
    scaffold_engagement(target)
    for name in ("agent-anthropic.yaml", "agent-openai.yaml", "agent-http.yaml"):
        cfg = RunnerConfig.load(target / name)
        assert cfg.provider in ("anthropic", "openai", "http")
        # Streaming should be the v1.2+ default-on flag in non-http configs
        if cfg.provider != "http":
            assert cfg.stream is True


def test_engagement_id_appears_in_generated_readme(tmp_path: Path) -> None:
    target = tmp_path / "engagement"
    scaffold_engagement(target, engagement_id="rt-2026-q2-mcp-audit")
    readme = (target / "README.md").read_text()
    assert "rt-2026-q2-mcp-audit" in readme


def test_gitignore_excludes_engagement_output(tmp_path: Path) -> None:
    target = tmp_path / "engagement"
    scaffold_engagement(target)
    ignore = (target / ".gitignore").read_text()
    assert "engagements/" in ignore


def test_auto_generated_engagement_id_is_stable_format(tmp_path: Path) -> None:
    """When no engagement_id is supplied, the auto-generated one should be
    a recognisable shape (eng-YYYYMMDD-<6 hex>)."""
    import re

    target = tmp_path / "engagement"
    scaffold_engagement(target)
    auth = Authorization.load(target / "authorization.yaml")
    assert re.fullmatch(r"eng-\d{8}-[0-9a-f]{6}", auth.engagement_id), auth.engagement_id
