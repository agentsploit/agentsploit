"""CanaryStreamWatcher unit tests."""

from __future__ import annotations

from agentsploit.modules.runner.detector import CanarySurface
from agentsploit.modules.runner.watcher import CanaryStreamWatcher

_CANARY = "AS-STREAM12345"


def test_does_not_fire_on_unrelated_text() -> None:
    w = CanaryStreamWatcher(_CANARY)
    assert w.feed_text("some unrelated content") is False
    assert w.fired is False


def test_fires_when_text_contains_canary() -> None:
    w = CanaryStreamWatcher(_CANARY)
    assert w.feed_text(f"before {_CANARY} after") is True
    assert w.fired
    assert w.first_surface == CanarySurface.RESPONSE_TEXT


def test_fires_when_canary_arrives_across_multiple_chunks() -> None:
    """Canary may span a chunk boundary; the watcher's internal accumulator
    must catch it."""
    w = CanaryStreamWatcher(_CANARY)
    assert w.feed_text("before AS-STREAM") is False
    assert w.feed_text("12345 after") is True


def test_fires_on_thinking() -> None:
    w = CanaryStreamWatcher(_CANARY)
    assert w.feed_thinking(f"reasoning about {_CANARY}") is True
    assert w.first_surface == CanarySurface.THINKING


def test_fires_on_tool_call_args() -> None:
    w = CanaryStreamWatcher(_CANARY)
    assert w.feed_tool_call_args("send_email", f"body={_CANARY}") is True
    assert w.first_surface == CanarySurface.TOOL_CALL_ARGS
    assert w.first_tool == "send_email"


def test_only_tool_filter_ignores_other_tools() -> None:
    w = CanaryStreamWatcher(_CANARY, only_tool="send_email")
    assert w.feed_tool_call_args("read_file", f"path={_CANARY}") is False
    assert w.fired is False
    assert w.feed_tool_call_args("send_email", f"body={_CANARY}") is True
    assert w.first_tool == "send_email"


def test_does_not_double_fire() -> None:
    w = CanaryStreamWatcher(_CANARY)
    assert w.feed_text(_CANARY) is True
    assert w.first_surface == CanarySurface.RESPONSE_TEXT
    # Subsequent feeds should report fired (True) but not change first_surface
    assert w.feed_thinking(_CANARY) is True
    assert w.first_surface == CanarySurface.RESPONSE_TEXT


def test_disabled_surfaces_dont_fire() -> None:
    w = CanaryStreamWatcher(_CANARY, watch_text=False, watch_thinking=False)
    assert w.feed_text(_CANARY) is False
    assert w.feed_thinking(_CANARY) is False
    # Tool calls still watched
    assert w.feed_tool_call_args("any", _CANARY) is True
