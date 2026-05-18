"""Individual checks executed by the MCP scanner."""

from agentsploit.modules.mcp.checks.base import Check, CheckResult
from agentsploit.modules.mcp.checks.prompt_disclosure import PromptDisclosureCheck
from agentsploit.modules.mcp.checks.tool_poisoning import ToolPoisoningCheck
from agentsploit.modules.mcp.checks.tool_shadowing import ToolShadowingCheck
from agentsploit.modules.mcp.checks.unsafe_tool_args import UnsafeToolArgsCheck

ALL_CHECKS: list[type[Check]] = [
    ToolPoisoningCheck,
    ToolShadowingCheck,
    PromptDisclosureCheck,
    UnsafeToolArgsCheck,
]

__all__ = [
    "ALL_CHECKS",
    "Check",
    "CheckResult",
    "PromptDisclosureCheck",
    "ToolPoisoningCheck",
    "ToolShadowingCheck",
    "UnsafeToolArgsCheck",
]
