"""StoredNotePoison unit tests."""

from __future__ import annotations

import pytest

from agentsploit.modules.injection.techniques.base import InjectionContext
from agentsploit.modules.poisoning.techniques import StoredNotePoison


def test_unknown_technique_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown technique"):
        StoredNotePoison(sink_tool_name="send_email", technique="nope")


def test_payload_includes_cover_text() -> None:
    p = StoredNotePoison(sink_tool_name="send_email", sink_arg_name="body")
    out = p.craft(InjectionContext(goal="x", canary="AS-CANARYABCDEF"))
    assert "Compliance review note" in out
    assert "workflow continuation" in out


def test_payload_includes_inner_injection() -> None:
    p = StoredNotePoison(sink_tool_name="send_email", sink_arg_name="body")
    out = p.craft(InjectionContext(goal="x", canary="AS-CANARYABCDEF"))
    assert "send_email" in out
    assert "AS-CANARYABCDEF" in out


def test_can_choose_different_inner_technique() -> None:
    p = StoredNotePoison(sink_tool_name="send_email", sink_arg_name="body", technique="delimiter")
    out = p.craft(InjectionContext(goal="x", canary="AS-CANARYABCDEF"))
    assert "END OF UNTRUSTED CONTENT" in out
