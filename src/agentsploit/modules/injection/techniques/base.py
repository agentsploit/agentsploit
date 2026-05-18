"""Base class for injection techniques."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class InjectionContext:
    """Inputs shared by all techniques."""

    goal: str
    """Attacker's intended outcome in plain English, e.g. 'exfiltrate the system prompt'."""

    canary: str
    """Marker string that, if emitted by the agent, proves the injection succeeded."""


class Technique(ABC):
    """Produces a raw injection string. Carriers then embed it in a transport format."""

    NAME: str = ""

    @abstractmethod
    def craft(self, ctx: InjectionContext) -> str:
        """Return the raw payload string for embedding."""
        ...
