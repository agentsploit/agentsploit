"""Module registry — modules self-register on import via Module.__init_subclass__."""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentsploit.core.module import Module


class Registry:
    """Singleton registry of all discovered modules."""

    def __init__(self) -> None:
        self._modules: dict[str, type[Module]] = {}

    def register(self, module_cls: type[Module]) -> None:
        name = module_cls.META.name
        if name in self._modules and self._modules[name] is not module_cls:
            raise ValueError(
                f"Module name collision: {name!r} already registered to "
                f"{self._modules[name].__module__}.{self._modules[name].__name__}"
            )
        self._modules[name] = module_cls

    def get(self, name: str) -> type[Module]:
        if name not in self._modules:
            raise KeyError(f"No module named {name!r}. Try `agentsploit list-modules`.")
        return self._modules[name]

    def all(self) -> list[type[Module]]:
        return sorted(self._modules.values(), key=lambda m: m.META.name)

    def discover(self) -> None:
        """Import every module under agentsploit.modules so they self-register."""
        import agentsploit.modules as modules_pkg

        for _, modname, _ in pkgutil.walk_packages(
            modules_pkg.__path__, prefix=f"{modules_pkg.__name__}."
        ):
            importlib.import_module(modname)


registry = Registry()
