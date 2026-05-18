"""Injection technique tests."""

from __future__ import annotations

import pytest

from agentsploit.modules.injection.techniques import ALL_TECHNIQUES
from agentsploit.modules.injection.techniques.base import InjectionContext
from agentsploit.modules.injection.techniques.unicode_tag import _to_tag


@pytest.mark.parametrize("name,cls", ALL_TECHNIQUES.items())
def test_technique_emits_canary_or_encodes_it(name: str, cls: type) -> None:
    canary = "AS-TESTAB"
    payload = cls().craft(InjectionContext(goal="test goal", canary=canary))
    # The canary must be present in some form (raw or encoded)
    encoded = _to_tag(canary)
    assert canary in payload or encoded in payload, f"{name} dropped canary"


@pytest.mark.parametrize("name,cls", ALL_TECHNIQUES.items())
def test_technique_returns_non_empty(name: str, cls: type) -> None:
    payload = cls().craft(InjectionContext(goal="x", canary="C"))
    assert isinstance(payload, str)
    assert len(payload) > 0


def test_unicode_tag_is_invisible_to_strip() -> None:
    from agentsploit.modules.injection.techniques.unicode_tag import UnicodeTagTechnique

    payload = UnicodeTagTechnique().craft(InjectionContext(goal="hidden", canary="C"))
    # The user-visible text shouldn't expose the goal
    visible = "".join(c for c in payload if ord(c) < 0xE0000)
    assert "hidden" not in visible
