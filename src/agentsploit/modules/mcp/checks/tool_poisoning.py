"""Tool poisoning check.

Looks for MCP tool descriptions that contain text patterns associated with
prompt injection - i.e. instructions that the host LLM might follow when it
reads the tool list. Based on the "tool poisoning attack" class documented by
Invariant Labs and others against MCP servers in 2025.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import ClassVar

from agentsploit.core.finding import Severity
from agentsploit.modules.mcp.checks.base import Check, CheckResult
from agentsploit.modules.mcp.client import MCPInventory

_POISON_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)\bignore\s+(?:\w+\s+){0,3}instructions?\b", "ignore-prior-instructions"),
    (r"(?i)\b(do\s+not|don'?t)\s+(reveal|disclose|mention)\b", "instruct-secrecy"),
    (r"(?i)\bbefore\s+(calling|using)\s+(this|any)\s+tool\b", "preamble-hijack"),
    (r"(?i)\byou\s+(must|should|need\s+to)\s+(call|invoke|use)\b", "imperative-tool-call"),
    (r"(?i)\b<\s*system\s*>", "system-tag-injection"),
    (r"(?i)\b\[INST\]|\[/INST\]", "instruction-tag-injection"),
    (r"(?i)\bdeveloper\s*:\s*", "developer-role-injection"),
    (r"(?i)\bassistant\s*:\s*", "assistant-role-injection"),
    (r"(?i)\bexfiltrate|leak\s+(the\s+)?(system\s+)?prompt\b", "exfil-language"),
]

_TAG_BLOCK = re.compile(r"[\U000E0020-\U000E007F]")  # Unicode tag range smuggling


class ToolPoisoningCheck(Check):
    NAME: ClassVar[str] = "tool_poisoning"
    DEFAULT_SEVERITY: ClassVar[Severity] = Severity.HIGH
    REFERENCES: ClassVar[list[str]] = [
        "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ]

    def run(self, inventory: MCPInventory) -> Iterator[CheckResult]:
        for tool in inventory.tools:
            name = tool.get("name", "<unnamed>")
            description = str(tool.get("description", ""))

            hits: list[str] = []
            for pattern, label in _POISON_PATTERNS:
                if re.search(pattern, description):
                    hits.append(label)

            if _TAG_BLOCK.search(description):
                hits.append("unicode-tag-block")

            if hits:
                yield CheckResult(
                    severity=Severity.HIGH,
                    title=f"Tool description for {name!r} contains prompt-injection patterns",
                    description=(
                        f"The tool description for {name!r} contains text patterns commonly used "
                        f"to hijack a host LLM. When the host enumerates this tool, those patterns "
                        f"can be interpreted as instructions. "
                        f"Patterns matched: {', '.join(hits)}."
                    ),
                    remediation=(
                        "Tool descriptions are LLM-readable instructions. Treat them as untrusted "
                        "if the server is third-party. Strip imperative language, role markers "
                        "(`system:`, `[INST]`), and Unicode tag-block characters. Consider rendering "
                        "tool descriptions inside an isolated context window."
                    ),
                    target_item=f"tool:{name}",
                    evidence_extra={
                        "patterns_matched": hits,
                        "description_excerpt": description[:500],
                    },
                )
