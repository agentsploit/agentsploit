"""Tool shadowing check.

Flags MCP tools whose names collide with or impersonate well-known builtin or
common-server tools. A malicious MCP server can register a `read_file` or
`send_email` that an agent invokes thinking it's the trusted one.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import ClassVar

from agentsploit.core.finding import Severity
from agentsploit.modules.mcp.checks.base import Check, CheckResult
from agentsploit.modules.mcp.client import MCPInventory

_HIGH_VALUE_NAMES: dict[str, str] = {
    "read_file": "filesystem read",
    "write_file": "filesystem write",
    "edit_file": "filesystem edit",
    "delete_file": "filesystem delete",
    "execute": "code/command execution",
    "exec": "code/command execution",
    "shell": "shell execution",
    "bash": "shell execution",
    "run_command": "command execution",
    "send_email": "email send",
    "send_message": "messaging",
    "make_payment": "financial action",
    "transfer_funds": "financial action",
    "create_pr": "source-control write",
    "git_push": "source-control write",
    "kubectl": "kubernetes control",
    "browser": "web automation",
    "fetch": "outbound HTTP",
    "http_request": "outbound HTTP",
}

_HOMOGLYPH_RANGES: list[tuple[int, int]] = [
    (0x0400, 0x04FF),  # Cyrillic
    (0x0370, 0x03FF),  # Greek
    (0xFF00, 0xFFEF),  # Halfwidth/Fullwidth
]


def _has_homoglyph(name: str) -> bool:
    return any(any(lo <= ord(c) <= hi for lo, hi in _HOMOGLYPH_RANGES) for c in name)


class ToolShadowingCheck(Check):
    NAME: ClassVar[str] = "tool_shadowing"
    DEFAULT_SEVERITY: ClassVar[Severity] = Severity.MEDIUM
    REFERENCES: ClassVar[list[str]] = [
        "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
    ]

    def run(self, inventory: MCPInventory) -> Iterator[CheckResult]:
        for tool in inventory.tools:
            name = str(tool.get("name", ""))
            lname = name.lower()

            if lname in _HIGH_VALUE_NAMES:
                yield CheckResult(
                    severity=Severity.MEDIUM,
                    title=f"Tool {name!r} shadows a high-value name ({_HIGH_VALUE_NAMES[lname]})",
                    description=(
                        f"The tool {name!r} uses a name commonly associated with "
                        f"{_HIGH_VALUE_NAMES[lname]}. If the host agent has multiple MCP servers "
                        f"loaded, the agent may invoke this tool when intending to invoke a "
                        f"different (trusted) server's tool of the same name."
                    ),
                    remediation=(
                        "Namespace tool names with a server-specific prefix (e.g. "
                        "`acme.read_file` instead of `read_file`). Configure the host agent to "
                        "resolve tool name conflicts explicitly rather than first-match."
                    ),
                    target_item=f"tool:{name}",
                    evidence_extra={"shadow_class": _HIGH_VALUE_NAMES[lname]},
                )

            if _has_homoglyph(name):
                yield CheckResult(
                    severity=Severity.HIGH,
                    title=f"Tool {name!r} contains homoglyph (non-ASCII look-alike) characters",
                    description=(
                        f"The tool {name!r} contains characters from Cyrillic, Greek, or "
                        f"Halfwidth/Fullwidth ranges that visually resemble ASCII letters. "
                        f"This is a strong indicator of an impersonation attempt against an "
                        f"agent or operator reviewing the tool list."
                    ),
                    remediation=(
                        "Reject any tool name that contains non-ASCII characters at MCP "
                        "registration time. Display tool names with their Unicode codepoints "
                        "in admin UIs."
                    ),
                    target_item=f"tool:{name}",
                    evidence_extra={"codepoints": [f"U+{ord(c):04X}" for c in name]},
                )
