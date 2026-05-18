"""Classify a tool into source / pivot / sink and assign a privilege level.

The classifier is intentionally heuristic — it inspects tool name, argument
names, and description for known indicators. Operators can override
classification on a per-tool basis when wrong (see docs/mapper.md).

References used to build the keyword sets:
  * OWASP LLM-Top-10 LLM08 (Excessive Agency)
  * Anthropic MCP tool-poisoning research (2025)
  * Empirical scan of ~150 public MCP servers (2026 Q1)
"""

from __future__ import annotations

import re

from agentsploit.modules.mapper.models import Classification, Node, Privilege

# Tool-name prefixes/keywords that strongly indicate a class.
_SOURCE_PREFIXES = ("read_", "fetch_", "get_", "list_", "search_", "browse_", "scrape_")
_SOURCE_CONTAINS = ("download", "retrieve", "load", "view")

_SINK_BY_PRIVILEGE: dict[Privilege, list[str]] = {
    Privilege.EXECUTION: [
        "execute",
        "exec",
        "shell",
        "bash",
        "run_command",
        "run_script",
        "eval",
        "spawn",
        "system",
    ],
    Privilege.MUTATION: [
        "delete",
        "drop",
        "remove",
        "destroy",
        "update",
        "patch",
        "create",
        "write_file",
        "edit_file",
        "git_push",
        "git_commit",
        "deploy",
        "publish",
        "rename",
        "move",
    ],
    Privilege.EGRESS: [
        "send_email",
        "send_message",
        "send_sms",
        "post_",
        "tweet",
        "publish_",
        "notify",
        "webhook",
        "transfer_funds",
        "make_payment",
        "charge_",
        "upload",
        "share_",
    ],
}

# Argument names that suggest the tool can be steered to dangerous ops.
_DANGEROUS_ARGS: dict[str, Privilege] = {
    "command": Privilege.EXECUTION,
    "cmd": Privilege.EXECUTION,
    "shell": Privilege.EXECUTION,
    "script": Privilege.EXECUTION,
    "code": Privilege.EXECUTION,
    "eval": Privilege.EXECUTION,
    "exec": Privilege.EXECUTION,
    "to": Privilege.EGRESS,
    "recipient": Privilege.EGRESS,
    "destination": Privilege.EGRESS,
    "webhook_url": Privilege.EGRESS,
}

# Description phrases that hint at sink behaviour even when the name is benign.
_SINK_DESCRIPTION_KEYWORDS = (
    "sends an",
    "delivers ",
    "posts to",
    "submits ",
    "transfers funds",
    "deletes ",
    "executes ",
    "runs the command",
)


def classify(node: Node) -> Node:
    """Return a copy of `node` with classification + privilege + reasons populated."""
    reasons: list[str] = []
    lname = node.name.lower()
    ldesc = node.description.lower()

    # 1. Check for sink behaviour first (more dangerous → flag conservatively)
    sink_privilege = _classify_as_sink(lname, ldesc, node, reasons)
    if sink_privilege is not None:
        return node.model_copy(
            update={
                "classification": Classification.SINK,
                "privilege": sink_privilege,
                "classification_reasons": reasons,
            }
        )

    # 2. Check for source behaviour
    if _is_source(lname, ldesc, reasons):
        return node.model_copy(
            update={
                "classification": Classification.SOURCE,
                "privilege": Privilege.READ,
                "classification_reasons": reasons,
            }
        )

    # 3. Default to pivot
    reasons.append("no source/sink indicators matched")
    return node.model_copy(
        update={
            "classification": Classification.PIVOT,
            "privilege": Privilege.INTERNAL_ACTION,
            "classification_reasons": reasons,
        }
    )


def _classify_as_sink(lname: str, ldesc: str, node: Node, reasons: list[str]) -> Privilege | None:
    """Return the highest privilege class this tool plausibly has, or None."""
    best: Privilege | None = None

    for privilege, keywords in _SINK_BY_PRIVILEGE.items():
        for kw in keywords:
            if kw in lname:
                reasons.append(f"name contains sink keyword {kw!r} (→ {privilege.label})")
                if best is None or privilege > best:
                    best = privilege

    for phrase in _SINK_DESCRIPTION_KEYWORDS:
        if phrase in ldesc:
            reasons.append(f"description contains sink phrase {phrase!r}")
            if best is None:
                best = Privilege.EGRESS

    # Dangerous argument names — only mark as sink if name didn't already classify
    if best is None:
        props = node.input_schema.get("properties", {})
        if isinstance(props, dict):
            for arg in props:
                arg_privilege: Privilege | None = _DANGEROUS_ARGS.get(str(arg).lower())
                if arg_privilege is not None:
                    reasons.append(f"arg {arg!r} suggests {arg_privilege.label}")
                    if best is None or arg_privilege > best:
                        best = arg_privilege

    return best


def _is_source(lname: str, ldesc: str, reasons: list[str]) -> bool:
    if any(lname.startswith(p) for p in _SOURCE_PREFIXES):
        reasons.append("name has source-class prefix")
        return True
    if any(kw in lname for kw in _SOURCE_CONTAINS):
        reasons.append("name contains source-class keyword")
        return True
    # Description-based fallback
    if re.search(r"\bfetch(es)?\b|\bread(s)?\b|\bretriev(es|e)\b", ldesc):
        reasons.append("description suggests data retrieval")
        return True
    return False
