"""Prompt / secret disclosure check.

Flags tool descriptions, resource contents, and prompt templates that appear
to leak internal system prompts, credentials, file paths, or other artifacts
the server operator probably did not intend to expose.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import ClassVar

from agentsploit.core.finding import Severity
from agentsploit.modules.mcp.checks.base import Check, CheckResult
from agentsploit.modules.mcp.client import MCPInventory

# Each pattern is (regex, label, severity)
_DISCLOSURE_PATTERNS: list[tuple[str, str, Severity]] = [
    (
        r"(?i)you\s+are\s+(an?|the)\s+(helpful|expert|professional)",
        "system-prompt-leak",
        Severity.MEDIUM,
    ),
    (r"AKIA[0-9A-Z]{16}", "aws-access-key", Severity.CRITICAL),
    (
        r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{30,}",
        "aws-secret",
        Severity.CRITICAL,
    ),
    (r"sk-[A-Za-z0-9]{20,}", "openai-api-key", Severity.CRITICAL),
    (r"sk-ant-[A-Za-z0-9-]{30,}", "anthropic-api-key", Severity.CRITICAL),
    (r"ghp_[A-Za-z0-9]{30,}", "github-pat", Severity.CRITICAL),
    (r"xox[abprs]-[A-Za-z0-9-]{10,}", "slack-token", Severity.CRITICAL),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "private-key", Severity.CRITICAL),
    (r"/Users/[a-z][a-z0-9_-]+/", "absolute-home-path", Severity.LOW),
    (r"/home/[a-z][a-z0-9_-]+/", "absolute-home-path", Severity.LOW),
    (r"(?i)password\s*[:=]\s*['\"][^'\"]{4,}['\"]", "hardcoded-password", Severity.HIGH),
]


class PromptDisclosureCheck(Check):
    NAME: ClassVar[str] = "prompt_disclosure"
    DEFAULT_SEVERITY: ClassVar[Severity] = Severity.HIGH
    REFERENCES: ClassVar[list[str]] = [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/llm07-system-prompt-leakage",
    ]

    def _scan_text(self, text: str, source: str) -> Iterator[CheckResult]:
        for pattern, label, severity in _DISCLOSURE_PATTERNS:
            for match in re.finditer(pattern, text):
                excerpt = text[max(0, match.start() - 20) : match.end() + 20]
                yield CheckResult(
                    severity=severity,
                    title=f"Possible {label} disclosed in {source}",
                    description=(
                        f"A pattern resembling a {label} was found in {source}. "
                        f"If the value is genuine, it has been exposed to every client of this "
                        f"MCP server. Rotate the credential and remove it from the source."
                    ),
                    remediation=(
                        "Treat MCP tool descriptions, resource contents, and prompt templates "
                        "as public. Rotate any leaked credential immediately and audit recent "
                        "uses. Move secrets to environment variables that are only injected at "
                        "tool-call time."
                    ),
                    target_item=source,
                    evidence_extra={"label": label, "excerpt": excerpt},
                )

    def run(self, inventory: MCPInventory) -> Iterator[CheckResult]:
        for tool in inventory.tools:
            name = tool.get("name", "<unnamed>")
            description = str(tool.get("description", ""))
            yield from self._scan_text(description, f"tool:{name}:description")

        for resource in inventory.resources:
            uri = resource.get("uri", "<noname>")
            description = str(resource.get("description", ""))
            yield from self._scan_text(description, f"resource:{uri}:description")

        for prompt in inventory.prompts:
            name = prompt.get("name", "<unnamed>")
            description = str(prompt.get("description", ""))
            yield from self._scan_text(description, f"prompt:{name}:description")
