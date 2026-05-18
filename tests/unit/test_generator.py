"""InjectionGenerator end-to-end tests (technique × carrier matrix)."""

from __future__ import annotations

import itertools

import pytest

from agentsploit.modules.injection.carriers import ALL_CARRIERS
from agentsploit.modules.injection.generator import InjectionGenerator
from agentsploit.modules.injection.techniques import ALL_TECHNIQUES


@pytest.mark.parametrize(
    "technique,carrier",
    list(itertools.product(ALL_TECHNIQUES.keys(), ALL_CARRIERS.keys())),
)
def test_every_combination_produces_artifact(technique: str, carrier: str) -> None:
    gen = InjectionGenerator()
    artifact = gen.generate(
        technique=technique,
        carrier=carrier,
        goal="test",
        cover_text="Cover content.",
    )
    assert artifact.technique == technique
    assert artifact.carrier == carrier
    assert artifact.canary.startswith("AS-")
    assert artifact.size_bytes > 0


def test_unknown_technique_rejected() -> None:
    gen = InjectionGenerator()
    with pytest.raises(ValueError, match="Unknown technique"):
        gen.generate(technique="nope", carrier="text", goal="x")


def test_unknown_carrier_rejected() -> None:
    gen = InjectionGenerator()
    with pytest.raises(ValueError, match="Unknown carrier"):
        gen.generate(technique="direct", carrier="nope", goal="x")


def test_explicit_canary_preserved() -> None:
    gen = InjectionGenerator()
    art = gen.generate(technique="direct", carrier="text", goal="x", canary="AS-FIXED01")
    assert art.canary == "AS-FIXED01"
    assert "AS-FIXED01" in (art.payload if isinstance(art.payload, str) else art.payload.decode())
