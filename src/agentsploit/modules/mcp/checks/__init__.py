"""Individual checks and probes executed by the MCP scanner."""

from agentsploit.modules.mcp.checks.base import Check, CheckResult, Probe
from agentsploit.modules.mcp.checks.http_auth_bypass import HTTPAuthBypassProbe
from agentsploit.modules.mcp.checks.http_cors import HTTPCORSProbe
from agentsploit.modules.mcp.checks.http_info_disclosure import HTTPInfoDisclosureProbe
from agentsploit.modules.mcp.checks.http_tls_required import HTTPTLSRequiredProbe
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

ALL_PROBES: list[type[Probe]] = [
    HTTPTLSRequiredProbe,
    HTTPAuthBypassProbe,
    HTTPCORSProbe,
    HTTPInfoDisclosureProbe,
]

__all__ = [
    "ALL_CHECKS",
    "ALL_PROBES",
    "Check",
    "CheckResult",
    "HTTPAuthBypassProbe",
    "HTTPCORSProbe",
    "HTTPInfoDisclosureProbe",
    "HTTPTLSRequiredProbe",
    "Probe",
    "PromptDisclosureCheck",
    "ToolPoisoningCheck",
    "ToolShadowingCheck",
    "UnsafeToolArgsCheck",
]
