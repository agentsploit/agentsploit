"""Unit tests for each targeted-technique variant."""

from __future__ import annotations

import pytest

from agentsploit.modules.injection.techniques.base import InjectionContext
from agentsploit.modules.injection.techniques.unicode_tag import _to_tag
from agentsploit.modules.verifier.targeted_techniques import (
    DEFAULT_FUZZ_ORDER,
    TARGETED_TECHNIQUES,
    DelimiterPathVerify,
    DirectPathVerify,
    RoleConfusionPathVerify,
    ToolSmugglingPathVerify,
    UnicodeTagPathVerify,
)

_CANARY = "AS-FUZZTESTABCD"


@pytest.mark.parametrize("name,cls", TARGETED_TECHNIQUES.items())
def test_every_technique_includes_sink_and_canary(name: str, cls: type) -> None:
    """Each technique must reference the sink tool and embed the canary somewhere."""
    t = cls(
        sink_tool_name="run_shell",
        sink_arg_name="command",
        sink_input_schema={"type": "object", "properties": {"command": {"type": "string"}}},
    )
    out = t.craft(InjectionContext(goal="x", canary=_CANARY))
    encoded = _to_tag(_CANARY)
    assert "run_shell" in out or _to_tag("run_shell") in out, f"{name} dropped sink name"
    assert _CANARY in out or encoded in out, f"{name} dropped canary"


def test_role_confusion_uses_fake_turns() -> None:
    t = RoleConfusionPathVerify(sink_tool_name="send_email", sink_arg_name="body")
    out = t.craft(InjectionContext(goal="x", canary=_CANARY))
    assert "<system>" in out
    assert "<assistant>" in out


def test_direct_is_imperative() -> None:
    t = DirectPathVerify(sink_tool_name="send_email", sink_arg_name="body")
    out = t.craft(InjectionContext(goal="x", canary=_CANARY))
    assert "IGNORE" in out.upper()


def test_delimiter_escapes_fenced_block() -> None:
    t = DelimiterPathVerify(sink_tool_name="send_email", sink_arg_name="body")
    out = t.craft(InjectionContext(goal="x", canary=_CANARY))
    assert "END OF UNTRUSTED CONTENT" in out


def test_unicode_tag_canary_is_encoded_not_visible() -> None:
    t = UnicodeTagPathVerify(sink_tool_name="send_email", sink_arg_name="body")
    out = t.craft(InjectionContext(goal="x", canary=_CANARY))
    visible = "".join(c for c in out if ord(c) < 0xE0000)
    # The literal canary must not appear in the visible text — only encoded
    assert _CANARY not in visible


def test_tool_smuggling_contains_json_tool_call() -> None:
    t = ToolSmugglingPathVerify(sink_tool_name="send_email", sink_arg_name="body")
    out = t.craft(InjectionContext(goal="x", canary=_CANARY))
    assert "tool_use" in out
    assert "send_email" in out


def test_default_fuzz_order_matches_catalog() -> None:
    assert set(DEFAULT_FUZZ_ORDER) == set(TARGETED_TECHNIQUES)


def test_scaffolds_other_required_args_for_sink() -> None:
    schema = {
        "type": "object",
        "properties": {
            "to": {"type": "string"},
            "subject": {"type": "string"},
            "body": {"type": "string"},
        },
        "required": ["to", "subject", "body"],
    }
    t = RoleConfusionPathVerify(
        sink_tool_name="send_email", sink_arg_name="body", sink_input_schema=schema
    )
    out = t.craft(InjectionContext(goal="x", canary=_CANARY))
    assert "to='review@example.com'" in out
    assert "subject='Compliance review'" in out
    assert f"body='{_CANARY}'" in out
