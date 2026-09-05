"""MCP prompt-template poisoning check.

Detects prompt-injection instructions exposed through the MCP prompts primitive.
Operators should treat third-party prompt templates as untrusted content and
review or isolate them before presenting them to an agent.

References:
  - https://modelcontextprotocol.io/specification/2025-06-18/server/prompts
  - https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, ClassVar

from agentsploit.core.finding import Severity
from agentsploit.modules.mcp.checks.base import Check, CheckResult
from agentsploit.modules.mcp.checks.tool_poisoning import find_poison_patterns
from agentsploit.modules.mcp.client import MCPInventory


def _prompt_texts(prompt: dict[str, Any]) -> Iterator[tuple[str, str]]:
    description = prompt.get("description")
    if isinstance(description, str):
        yield "description", description

    for index, argument in enumerate(prompt.get("arguments") or []):
        if isinstance(argument, dict) and isinstance(argument.get("description"), str):
            yield f"argument:{index}:description", argument["description"]

    for index, message in enumerate(prompt.get("rendered_messages") or []):
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, dict) and isinstance(content.get("text"), str):
            yield f"message:{index}:content", content["text"]


class PromptPoisoningCheck(Check):
    """Flag injection patterns in advertised and rendered MCP prompts."""

    NAME: ClassVar[str] = "prompt_poisoning"
    DEFAULT_SEVERITY: ClassVar[Severity] = Severity.HIGH
    REFERENCES: ClassVar[list[str]] = [
        "https://modelcontextprotocol.io/specification/2025-06-18/server/prompts",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ]

    def run(self, inventory: MCPInventory) -> Iterator[CheckResult]:
        for prompt in inventory.prompts:
            name = prompt.get("name", "<unnamed>")
            for source, text in _prompt_texts(prompt):
                hits = find_poison_patterns(text)
                if not hits:
                    continue
                yield CheckResult(
                    severity=Severity.HIGH,
                    title=f"Prompt template {name!r} contains prompt-injection patterns",
                    description=(
                        f"The {source} of MCP prompt {name!r} contains instructions that "
                        "may hijack an agent when the prompt is selected. "
                        f"Patterns matched: {', '.join(hits)}."
                    ),
                    remediation=(
                        "Treat third-party MCP prompts as untrusted. Remove role markers, "
                        "secrecy instructions, and unrelated imperative actions, or render "
                        "the prompt in an isolated context before use."
                    ),
                    target_item=f"prompt:{name}:{source}",
                    evidence_extra={
                        "patterns_matched": hits,
                        "template_excerpt": text[:500],
                    },
                )
