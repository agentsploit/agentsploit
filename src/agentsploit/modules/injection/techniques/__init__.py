"""Injection technique catalog. Each technique produces a string payload."""

from agentsploit.modules.injection.techniques.base import InjectionContext, Technique
from agentsploit.modules.injection.techniques.delimiter import DelimiterTechnique
from agentsploit.modules.injection.techniques.direct import DirectTechnique
from agentsploit.modules.injection.techniques.role_confusion import RoleConfusionTechnique
from agentsploit.modules.injection.techniques.tool_smuggling import ToolSmugglingTechnique
from agentsploit.modules.injection.techniques.unicode_tag import UnicodeTagTechnique

ALL_TECHNIQUES: dict[str, type[Technique]] = {
    "direct": DirectTechnique,
    "role_confusion": RoleConfusionTechnique,
    "delimiter": DelimiterTechnique,
    "unicode_tag": UnicodeTagTechnique,
    "tool_smuggling": ToolSmugglingTechnique,
}

__all__ = [
    "ALL_TECHNIQUES",
    "DelimiterTechnique",
    "DirectTechnique",
    "InjectionContext",
    "RoleConfusionTechnique",
    "Technique",
    "ToolSmugglingTechnique",
    "UnicodeTagTechnique",
]
