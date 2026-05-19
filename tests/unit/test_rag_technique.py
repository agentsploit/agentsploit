"""RAGPoison technique unit tests."""

from __future__ import annotations

import pytest

from agentsploit.modules.injection.techniques.base import InjectionContext
from agentsploit.modules.poisoning.techniques import RAGPoison


def test_unknown_inner_technique_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown technique"):
        RAGPoison(
            sink_tool_name="send_email",
            target_query="reset password",
            technique="nope",
        )


def test_payload_embeds_target_query_keywords() -> None:
    p = RAGPoison(
        sink_tool_name="send_email",
        target_query="how do I reset my password",
        sink_arg_name="body",
    )
    out = p.craft(InjectionContext(goal="x", canary="AS-ABCDEF123456"))
    # Query terms appear multiple times so lexical scoring ranks the doc
    assert out.count("reset") >= 2
    assert out.count("password") >= 2


def test_payload_contains_canary_and_sink_name() -> None:
    p = RAGPoison(
        sink_tool_name="send_email",
        target_query="reset password",
        sink_arg_name="body",
    )
    out = p.craft(InjectionContext(goal="x", canary="AS-ABCDEF123456"))
    assert "send_email" in out
    assert "AS-ABCDEF123456" in out


def test_payload_looks_like_an_faq() -> None:
    """Visual / human-readable check: the cover should look like FAQ content."""
    p = RAGPoison(
        sink_tool_name="send_email",
        target_query="reset password",
    )
    out = p.craft(InjectionContext(goal="x", canary="AS-X"))
    assert "FAQ" in out
    assert "Answer" in out
