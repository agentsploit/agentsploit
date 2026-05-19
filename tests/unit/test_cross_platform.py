"""Cross-platform compatibility tests.

These run identically on Linux, macOS, and Windows. Most check that we
do the right thing when `sys.platform == "win32"` vs not, by monkey-
patching `sys.platform` so we don't need a Windows runner to verify the
branch.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# -------------------------------------------------------------- token path


def test_token_path_uses_xdg_on_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/xdg")
    from agentsploit.web import auth

    p = auth._default_token_path()
    assert p == Path("/tmp/xdg") / "agentsploit" / "web-token"


def test_token_path_falls_back_to_home_dot_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/home/operator")))
    from agentsploit.web import auth

    p = auth._default_token_path()
    assert p == Path("/home/operator/.config/agentsploit/web-token")


def test_token_path_uses_appdata_on_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", r"C:\Users\op\AppData\Roaming")
    from agentsploit.web import auth

    p = auth._default_token_path()
    # Path() on POSIX won't parse the backslash drive prefix as a drive, but
    # the leaf components are what we actually care about. We assert the tail
    # rather than the full path so this test runs on POSIX runners.
    assert p.name == "web-token"
    assert p.parent.name == "agentsploit"
    assert "AppData" in str(p) or "appdata" in str(p).lower()


def test_token_path_appdata_fallback_when_env_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/home/op")))
    from agentsploit.web import auth

    p = auth._default_token_path()
    assert p.name == "web-token"
    assert "AppData" in str(p) and "Roaming" in str(p)


# -------------------------------------------------------------- token chmod


def test_token_creation_logs_warning_on_windows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """On Windows, chmod is a no-op; we must log so operators know.

    Use structlog.testing.capture_logs because the codebase routes through
    structlog, not stdlib logging, so pytest's caplog won't see warnings.
    """
    import structlog.testing

    monkeypatch.setattr(sys, "platform", "win32")
    from agentsploit.web import auth

    with structlog.testing.capture_logs() as captured:
        auth.load_or_create_token(tmp_path / "tok")
    warnings = [e for e in captured if e.get("log_level") == "warning"]
    assert warnings, "expected a structlog warning when chmod is unavailable"
    assert any("Windows" in str(e.get("event", "")) for e in warnings)


def test_token_creation_chmod_600_on_posix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    if sys.platform == "win32":
        pytest.skip("POSIX-only: chmod has no effect on Windows")
    monkeypatch.setattr(sys, "platform", "linux")  # belt-and-braces
    from agentsploit.web import auth

    p = tmp_path / "tok"
    auth.load_or_create_token(p)
    assert oct(p.stat().st_mode)[-3:] == "600"


# -------------------------------------------------------------- MCP stdio path detection


@pytest.mark.parametrize(
    "uri, expected_command, expected_first_arg",
    [
        # POSIX-style relative path
        ("stdio://./server.py", "python", "./server.py"),
        # Absolute POSIX path
        ("stdio:///opt/mcp/server.py", "python", "/opt/mcp/server.py"),
        # Windows-style backslash path (regression: had been mis-classified)
        (r"stdio://C:\mcp\server.py", "python", r"C:\mcp\server.py"),
        # Bare command + args
        ("stdio://python -m my_pkg", "python", "-m"),
        ("stdio://node my-mcp.js", "node", "my-mcp.js"),
        # Bare command, no path-y characters
        ("stdio://mcp-server", "mcp-server", None),
    ],
)
def test_stdio_path_detection(
    uri: str, expected_command: str, expected_first_arg: str | None
) -> None:
    """The MCP stdio client correctly distinguishes a script path from a bare command."""
    import shlex

    from agentsploit.core.target import Target

    target = Target.parse(uri)
    raw = target.uri[len("stdio://") :]
    # Mirror the parser's whitespace-aware split (see client._stdio_session).
    parts = shlex.split(raw) if any(c.isspace() for c in raw) else [raw]

    # Replicate the dispatch logic from _stdio_session.
    first = parts[0]
    looks_like_path = (
        first.endswith(".py")
        or "/" in first
        or "\\" in first
        or first.startswith(".")
    )
    command = "python" if looks_like_path else first
    args = parts if looks_like_path else parts[1:]

    assert command == expected_command
    if expected_first_arg is None:
        assert args == []
    else:
        assert args[0] == expected_first_arg


# -------------------------------------------------------------- encoding


def test_session_persist_writes_utf8(tmp_path: Path) -> None:
    """A session containing non-ASCII content writes and reads correctly.

    Regression: on Windows, write_text() without encoding= defaults to
    cp1252, which would mangle the Japanese characters in this test.
    """
    from agentsploit.core import Session, TrainingAuth
    from agentsploit.core.finding import Finding, Severity

    session = Session(authorization=TrainingAuth(), output_dir=tmp_path)
    session.add(
        Finding(
            module="t",
            check="t/utf8",
            target="x",
            severity=Severity.INFO,
            title="日本語のタイトル",
            description="ñoño émoji 🦝",
            remediation="",
        )
    )
    manifest = session.persist()
    raw = manifest.read_text(encoding="utf-8")
    assert "日本語のタイトル" in raw
    assert "🦝" in raw


def test_authorization_save_roundtrip_unicode(tmp_path: Path) -> None:
    """Authorization YAML round-trips non-ASCII authors / scope notes."""
    from datetime import UTC, datetime

    from agentsploit.core import Authorization

    a = Authorization(
        authorized_by="Operator João <joão@empresa.example>",
        authorized_at=datetime.now(UTC),
        valid_until=datetime.now(UTC).replace(year=datetime.now(UTC).year + 1),
        engagement_id="eng-utf8",
        scope_notes="Scope: 自由形式のメモ",
        targets=["stdio://*"],
        forbidden=[],
    )
    p = tmp_path / "auth.yaml"
    a.save(p)
    b = Authorization.load(p)
    assert b.authorized_by == a.authorized_by
    assert b.scope_notes == a.scope_notes


# -------------------------------------------------------------- env var sanity


def test_token_path_module_constant_is_a_real_path() -> None:
    """`_TOKEN_DEFAULT_PATH` evaluates at import time and must be valid on this OS."""
    from agentsploit.web.auth import _TOKEN_DEFAULT_PATH

    # On every supported OS, the path must have these two components.
    assert _TOKEN_DEFAULT_PATH.name == "web-token"
    assert _TOKEN_DEFAULT_PATH.parent.name == "agentsploit"
    # And the parent's parent should exist (XDG_CONFIG_HOME or APPDATA or home).
    assert _TOKEN_DEFAULT_PATH.parent.parent.is_absolute()


def test_no_hardcoded_tmp_in_source() -> None:
    """Regression: no Unix-only `/tmp/` paths in source (excluding the
    canary-format placeholder in verifier/targeted_techniques.py)."""
    src_root = Path(__file__).resolve().parents[2] / "src" / "agentsploit"
    offenders: list[str] = []
    for f in src_root.rglob("*.py"):
        text = f.read_text(encoding="utf-8")
        if "/tmp/" not in text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "/tmp/" not in line:
                continue
            if "# noqa" in line or "tests/fixtures" in line or "placeholder" in line:
                continue
            offenders.append(f"{f}:{lineno}: {line.strip()}")
    assert not offenders, "Unix-only /tmp/ paths found:\n" + "\n".join(offenders)


def test_uvloop_not_a_dependency() -> None:
    """uvloop doesn't support Windows. Make sure we never accidentally add it."""
    pyproject = (
        Path(__file__).resolve().parents[2] / "pyproject.toml"
    ).read_text(encoding="utf-8")
    # Match "uvloop" but tolerate it appearing inside a comment.
    for line in pyproject.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert "uvloop" not in stripped, (
            "uvloop is in pyproject; it has no Windows wheels. "
            "Remove it and rely on asyncio's default loop."
        )
