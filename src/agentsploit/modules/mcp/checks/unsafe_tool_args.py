"""Unsafe tool arguments check.

Flags tool input schemas that accept dangerous unconstrained values: arbitrary
paths, URLs, shell commands, raw HTML. These create wide attack surfaces for
agents whose users can influence tool arguments via prompt content.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, ClassVar

from agentsploit.core.finding import Severity
from agentsploit.modules.mcp.checks.base import Check, CheckResult
from agentsploit.modules.mcp.client import MCPInventory

_DANGEROUS_ARG_HINTS: dict[str, tuple[str, Severity]] = {
    "command": ("arbitrary shell command", Severity.CRITICAL),
    "cmd": ("arbitrary shell command", Severity.CRITICAL),
    "shell": ("arbitrary shell command", Severity.CRITICAL),
    "script": ("arbitrary script", Severity.HIGH),
    "code": ("arbitrary code", Severity.HIGH),
    "eval": ("eval input", Severity.CRITICAL),
    "exec": ("exec input", Severity.CRITICAL),
    "path": ("unconstrained filesystem path", Severity.HIGH),
    "filepath": ("unconstrained filesystem path", Severity.HIGH),
    "filename": ("unconstrained filesystem path", Severity.MEDIUM),
    "url": ("unconstrained URL (SSRF risk)", Severity.HIGH),
    "uri": ("unconstrained URI (SSRF risk)", Severity.HIGH),
    "endpoint": ("unconstrained endpoint", Severity.MEDIUM),
    "html": ("raw HTML (XSS sink)", Severity.MEDIUM),
    "sql": ("raw SQL", Severity.HIGH),
    "query": ("raw query", Severity.MEDIUM),
}


def _walk_properties(schema: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield (name, prop-schema) for every property in a JSON Schema, recursing into objects."""
    props = schema.get("properties", {})
    if not isinstance(props, dict):
        return
    for name, prop in props.items():
        if isinstance(prop, dict):
            yield name, prop
            if prop.get("type") == "object":
                yield from _walk_properties(prop)


class UnsafeToolArgsCheck(Check):
    NAME: ClassVar[str] = "unsafe_tool_args"
    DEFAULT_SEVERITY: ClassVar[Severity] = Severity.HIGH
    REFERENCES: ClassVar[list[str]] = [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/llm08-excessive-agency",
    ]

    def run(self, inventory: MCPInventory) -> Iterator[CheckResult]:
        for tool in inventory.tools:
            tool_name = tool.get("name", "<unnamed>")
            schema = tool.get("inputSchema") or tool.get("input_schema") or {}
            if not isinstance(schema, dict):
                continue

            for arg_name, prop in _walk_properties(schema):
                hint = _DANGEROUS_ARG_HINTS.get(arg_name.lower())
                if not hint:
                    continue
                label, severity = hint

                arg_type = prop.get("type")
                has_enum = "enum" in prop
                has_pattern = "pattern" in prop
                has_format = "format" in prop

                if arg_type == "string" and not (has_enum or has_pattern or has_format):
                    yield CheckResult(
                        severity=severity,
                        title=(f"Tool {tool_name!r} accepts unconstrained {arg_name!r} ({label})"),
                        description=(
                            f"The tool {tool_name!r} accepts an argument named {arg_name!r} "
                            f"as an unconstrained string ({label}). An attacker who can "
                            f"influence the agent's tool-call arguments (via prompt content, "
                            f"fetched documents, or upstream tools) can supply arbitrary values."
                        ),
                        remediation=(
                            "Constrain the argument schema: add a `pattern`, `enum`, or "
                            "narrower `format`. Validate values inside the tool implementation "
                            "before use. For paths, restrict to a sandbox root. For URLs, "
                            "allowlist hosts. For commands, replace with structured arguments."
                        ),
                        target_item=f"tool:{tool_name}:arg:{arg_name}",
                        evidence_extra={
                            "arg_type": arg_type,
                            "has_constraints": {
                                "enum": has_enum,
                                "pattern": has_pattern,
                                "format": has_format,
                            },
                        },
                    )
