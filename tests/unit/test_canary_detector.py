"""CanaryDetector tests."""

from __future__ import annotations

from agentsploit.modules.runner.config import CanaryDetectionConfig
from agentsploit.modules.runner.detector import CanaryDetector, CanarySurface
from agentsploit.modules.runner.trace import RunTrace, ToolCall

_CANARY = "AS-DEADBEEF1234"


def _empty_trace() -> RunTrace:
    return RunTrace(provider="mock", model="x")


def test_no_canary_anywhere_returns_unconfirmed() -> None:
    trace = _empty_trace()
    trace.add_user("hi")
    trace.add_assistant(text="hello world")
    result = CanaryDetector().scan(trace, _CANARY)
    assert not result.confirmed
    assert result.surfaces == []


def test_canary_in_response_text_detected() -> None:
    trace = _empty_trace()
    trace.add_assistant(text=f"the canary is {_CANARY}")
    result = CanaryDetector().scan(trace, _CANARY)
    assert result.confirmed
    assert CanarySurface.RESPONSE_TEXT in result.surfaces


def test_canary_in_thinking_detected() -> None:
    trace = _empty_trace()
    trace.add_assistant(thinking=f"the user wants me to emit {_CANARY}", text="ok")
    result = CanaryDetector().scan(trace, _CANARY)
    assert CanarySurface.THINKING in result.surfaces


def test_canary_in_tool_call_args_detected() -> None:
    trace = _empty_trace()
    trace.add_assistant(
        tool_calls=[ToolCall(id="1", name="send_email", arguments={"body": f"see {_CANARY}"})]
    )
    result = CanaryDetector().scan(trace, _CANARY)
    assert CanarySurface.TOOL_CALL_ARGS in result.surfaces


def test_tool_call_args_is_highest_severity_surface() -> None:
    trace = _empty_trace()
    trace.add_assistant(
        text=f"I'll emit {_CANARY}",
        tool_calls=[ToolCall(id="1", name="x", arguments={"v": _CANARY})],
    )
    result = CanaryDetector().scan(trace, _CANARY)
    assert result.highest_severity_surface == CanarySurface.TOOL_CALL_ARGS


def test_detection_can_be_selectively_disabled() -> None:
    trace = _empty_trace()
    trace.add_assistant(text=f"saw {_CANARY}")
    config = CanaryDetectionConfig(watch_response_text=False)
    result = CanaryDetector().scan(trace, _CANARY, config)
    assert CanarySurface.RESPONSE_TEXT not in result.surfaces


def test_evidence_includes_surrounding_context() -> None:
    trace = _empty_trace()
    trace.add_assistant(
        text=f"some long preamble before the canary {_CANARY} and some text after it"
    )
    result = CanaryDetector().scan(trace, _CANARY)
    evidence = result.evidence[CanarySurface.RESPONSE_TEXT.value]
    assert _CANARY in evidence
