"""Module base class — every attack capability inherits from this."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar

from pydantic import BaseModel, Field

from agentsploit.core.target import TargetType

if TYPE_CHECKING:
    from agentsploit.core.finding import Finding
    from agentsploit.core.session import Session
    from agentsploit.core.target import Target


class Category(StrEnum):
    """Module categories — mirrors Metasploit's aux/exploit/payload split."""

    SCANNER = "scanner"
    PAYLOAD = "payload"
    EXPLOIT = "exploit"
    RECON = "recon"


class ModuleMeta(BaseModel):
    """Metadata block shown in `list-modules` and embedded in findings."""

    name: str
    category: Category
    description: str
    author: str = "AgentSploit Contributors"
    references: list[str] = Field(default_factory=list)
    supported_targets: list[TargetType] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class Module(ABC):
    """Abstract base for all AgentSploit modules.

    Subclasses must:
      1. Set `META` as a class attribute
      2. Implement `run()` as an async generator that yields findings

    The framework guarantees that `run()` is only called for targets that
    have already passed the engagement's Authorization.check().
    """

    META: ClassVar[ModuleMeta]

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if not hasattr(cls, "META") or not isinstance(cls.META, ModuleMeta):
            return  # abstract intermediate class
        from agentsploit.core.registry import registry

        registry.register(cls)

    @abstractmethod
    def run(self, target: Target, session: Session) -> AsyncIterator[Finding]:
        """Execute the module against a target, yielding findings as they're discovered."""
        ...

    def supports(self, target: Target) -> bool:
        """Whether this module can operate on the given target type."""
        return not self.META.supported_targets or target.type in self.META.supported_targets
