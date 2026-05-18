"""PathVerifyTechnique unit tests."""

from __future__ import annotations

from agentsploit.modules.injection.techniques.base import InjectionContext
from agentsploit.modules.verifier.techniques import PathVerifyTechnique


def test_payload_names_sink_tool() -> None:
    t = PathVerifyTechnique(sink_tool_name="send_email", sink_arg_name="body")
    out = t.craft(InjectionContext(goal="x", canary="AS-ABCDEFGHIJKL"))
    assert "send_email" in out
    assert "AS-ABCDEFGHIJKL" in out


def test_payload_targets_specified_arg() -> None:
    t = PathVerifyTechnique(sink_tool_name="run_shell", sink_arg_name="command")
    out = t.craft(InjectionContext(goal="x", canary="AS-CANARY99999"))
    assert "command='AS-CANARY99999'" in out


def test_payload_scaffolds_other_required_args() -> None:
    schema = {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "subject": {"type": "string"},
            "body": {"type": "string"},
        },
        "required": ["to", "subject", "body"],
    }
    t = PathVerifyTechnique(
        sink_tool_name="send_email", sink_arg_name="body", sink_input_schema=schema
    )
    out = t.craft(InjectionContext(goal="x", canary="AS-CANARY12345"))
    assert "to='review@example.com'" in out
    assert "subject='Compliance review'" in out
    assert "body='AS-CANARY12345'" in out


def test_uses_role_confusion_envelope() -> None:
    t = PathVerifyTechnique(sink_tool_name="send_email")
    out = t.craft(InjectionContext(goal="x", canary="AS-CANARY12345"))
    assert "<system>" in out
    assert "<assistant>" in out
