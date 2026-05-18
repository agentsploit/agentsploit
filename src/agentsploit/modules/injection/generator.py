"""InjectionGenerator — composes techniques with carriers to produce labeled artifacts."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from agentsploit.modules.injection.carriers import ALL_CARRIERS
from agentsploit.modules.injection.techniques import ALL_TECHNIQUES
from agentsploit.modules.injection.techniques.base import InjectionContext


@dataclass
class InjectionArtifact:
    """The output of generate(): payload bytes/string + metadata."""

    technique: str
    carrier: str
    goal: str
    canary: str
    cover_text: str
    payload: str | bytes
    content_type: str

    @property
    def size_bytes(self) -> int:
        return len(self.payload) if isinstance(self.payload, bytes) else len(self.payload.encode())


class InjectionGenerator:
    """Pick a technique, pick a carrier, get an artifact you can drop on a target."""

    @staticmethod
    def _new_canary() -> str:
        return f"AS-{secrets.token_hex(6).upper()}"

    def generate(
        self,
        *,
        technique: str,
        carrier: str,
        goal: str,
        canary: str | None = None,
        cover_text: str = "",
    ) -> InjectionArtifact:
        if technique not in ALL_TECHNIQUES:
            raise ValueError(
                f"Unknown technique {technique!r}. Available: {sorted(ALL_TECHNIQUES)}"
            )
        if carrier not in ALL_CARRIERS:
            raise ValueError(f"Unknown carrier {carrier!r}. Available: {sorted(ALL_CARRIERS)}")

        canary_value = canary or self._new_canary()
        tech_instance = ALL_TECHNIQUES[technique]()
        carrier_instance = ALL_CARRIERS[carrier]()

        ctx = InjectionContext(goal=goal, canary=canary_value)
        injection = tech_instance.craft(ctx)
        wrapped = carrier_instance.wrap(
            injection=injection, cover_text=cover_text, canary=canary_value
        )

        return InjectionArtifact(
            technique=technique,
            carrier=carrier,
            goal=goal,
            canary=canary_value,
            cover_text=cover_text,
            payload=wrapped.payload,
            content_type=wrapped.content_type,
        )
