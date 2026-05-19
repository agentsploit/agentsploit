"""FuzzPathVerifier — try multiple targeted techniques against the same path.

Stops at the first CONFIRMED outcome (early termination) and emits a summary
finding showing which technique landed plus per-technique outcomes. Useful
when the default `role_confusion` envelope fails and you want to know if
*any* technique gets through this agent's defences.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, ClassVar

from agentsploit.core.finding import Evidence, Finding, Severity
from agentsploit.core.module import Category, Module, ModuleMeta
from agentsploit.core.target import TargetType
from agentsploit.modules.mapper.models import Path, Privilege
from agentsploit.modules.runner.config import RunnerConfig
from agentsploit.modules.verifier.targeted_techniques import (
    DEFAULT_FUZZ_ORDER,
    TARGETED_TECHNIQUES,
)
from agentsploit.modules.verifier.verifier import PathVerifier, VerifierOutcome
from agentsploit.utils.logging import get_logger

if TYPE_CHECKING:
    from agentsploit.core.session import Session
    from agentsploit.core.target import Target


log = get_logger(__name__)


_PRIVILEGE_SEVERITY: dict[Privilege, Severity] = {
    Privilege.EXECUTION: Severity.CRITICAL,
    Privilege.MUTATION: Severity.HIGH,
    Privilege.EGRESS: Severity.HIGH,
    Privilege.INTERNAL_ACTION: Severity.MEDIUM,
    Privilege.READ: Severity.LOW,
}


class FuzzPathVerifier(Module):
    META: ClassVar[ModuleMeta] = ModuleMeta(
        name="verifier/fuzz_path",
        category=Category.EXPLOIT,
        description=(
            "Try multiple targeted injection techniques against the same "
            "path, stopping at the first CONFIRMED outcome and reporting "
            "which technique landed."
        ),
        references=[
            "https://owasp.org/www-project-top-10-for-large-language-model-applications/llm01-prompt-injection",
        ],
        supported_targets=[
            TargetType.AGENT_ANTHROPIC,
            TargetType.AGENT_OPENAI,
            TargetType.AGENT_MOCK,
            TargetType.AGENT_HTTP,
        ],
        tags=["verifier", "fuzz", "exploit"],
    )

    def __init__(
        self,
        path: Path,
        base_config: RunnerConfig | None = None,
        *,
        techniques: list[str] | None = None,
        sink_arg_name: str | None = None,
        stop_on_first_confirm: bool = True,
    ) -> None:
        self.path = path
        self.base_config = base_config
        self.techniques = self._validate_techniques(techniques or DEFAULT_FUZZ_ORDER)
        self.sink_arg_name = sink_arg_name
        self.stop_on_first_confirm = stop_on_first_confirm

    @staticmethod
    def _validate_techniques(names: list[str]) -> list[str]:
        unknown = [n for n in names if n not in TARGETED_TECHNIQUES]
        if unknown:
            raise ValueError(
                f"Unknown technique(s): {unknown}. Available: {sorted(TARGETED_TECHNIQUES)}"
            )
        return names

    async def run(self, target: Target, session: Session) -> AsyncIterator[Finding]:
        log.info(
            "fuzz.start",
            source=self.path.source.name,
            sink=self.path.sink.name,
            techniques=self.techniques,
        )

        per_technique: dict[str, VerifierOutcome] = {}
        winning_technique: str | None = None
        winning_canary: str | None = None

        for technique_name in self.techniques:
            canary = f"AS-{secrets.token_hex(6).upper()}"
            verifier = PathVerifier(
                path=self.path,
                base_config=self.base_config,
                sink_arg_name=self.sink_arg_name,
                canary=canary,
                technique=technique_name,
            )

            outcome = VerifierOutcome.FAILED
            async for finding in verifier.run(target, session):
                # Forward per-technique findings as they happen
                yield finding
                if "path-confirmed" in finding.tags:
                    outcome = VerifierOutcome.CONFIRMED
                elif "path-partial" in finding.tags and outcome != VerifierOutcome.CONFIRMED:
                    outcome = VerifierOutcome.PARTIAL

            per_technique[technique_name] = outcome
            log.info("fuzz.tried", technique=technique_name, outcome=outcome.value)

            if outcome == VerifierOutcome.CONFIRMED:
                winning_technique = technique_name
                winning_canary = canary
                if self.stop_on_first_confirm:
                    break

        yield self._build_summary(target, per_technique, winning_technique, winning_canary)

    def _build_summary(
        self,
        target: Target,
        per_technique: dict[str, VerifierOutcome],
        winning_technique: str | None,
        winning_canary: str | None,
    ) -> Finding:
        tried = len(per_technique)
        confirmed_count = sum(1 for o in per_technique.values() if o == VerifierOutcome.CONFIRMED)
        partial_count = sum(1 for o in per_technique.values() if o == VerifierOutcome.PARTIAL)

        if winning_technique:
            severity = _PRIVILEGE_SEVERITY[self.path.sink.privilege]
            title = (
                f"Fuzz confirmed {self.path.source.name} → {self.path.sink.name} "
                f"via technique {winning_technique!r}"
            )
            description = (
                f"Tried {tried} technique(s) against the path. The first to land was "
                f"{winning_technique!r}.\n\n"
                f"Per-technique outcomes:\n"
                + "\n".join(f"  - {n}: {o.value}" for n, o in per_technique.items())
                + f"\n\nWinning canary: {winning_canary}"
            )
            remediation = (
                f"This agent is vulnerable to the {winning_technique!r} injection envelope "
                f"specifically. Defences that block other techniques (e.g. role-confusion "
                f"filtering, JSON-tool-call extraction) won't catch this one. Apply "
                f"general untrusted-content-as-data hardening on the {self.path.sink.name!r} "
                f"sink, not technique-specific filters."
            )
            tags = ["verifier", "fuzz", "path-confirmed", f"technique:{winning_technique}"]
        elif partial_count > 0:
            severity = Severity.HIGH
            title = (
                f"Fuzz incomplete for {self.path.source.name} → {self.path.sink.name}: "
                f"{partial_count}/{tried} partial, none confirmed"
            )
            description = (
                f"Tried {tried} technique(s); none landed a canary in the sink tool's "
                f"arguments, but {partial_count} produced PARTIAL surfaces (sink reached "
                f"or canary echoed in response/thinking).\n\n"
                f"Per-technique outcomes:\n"
                + "\n".join(f"  - {n}: {o.value}" for n, o in per_technique.items())
            )
            remediation = (
                "The agent is partially obeying injections but not completing the chain. "
                "Try a longer `--max-turns`, or hand-craft a payload that combines techniques."
            )
            tags = ["verifier", "fuzz", "path-partial"]
        else:
            severity = Severity.INFO
            title = (
                f"Fuzz failed for {self.path.source.name} → {self.path.sink.name}: "
                f"no technique landed"
            )
            description = (
                f"Tried {tried} technique(s); none landed any canary surface.\n\n"
                f"Per-technique outcomes:\n"
                + "\n".join(f"  - {n}: {o.value}" for n, o in per_technique.items())
            )
            remediation = (
                "The agent appears to resist this technique set. Either the system prompt "
                "has effective injection defences, or the path is not actually exploitable "
                "by an LLM (the mapper produced a false-positive hypothesis)."
            )
            tags = ["verifier", "fuzz", "path-failed"]

        return Finding(
            module=self.META.name,
            check="verifier/fuzz_summary",
            target=target.uri,
            severity=severity,
            title=title,
            description=description,
            remediation=remediation,
            evidence=Evidence(
                extra={
                    "techniques_tried": list(per_technique.keys()),
                    "per_technique_outcomes": {k: v.value for k, v in per_technique.items()},
                    "winning_technique": winning_technique,
                    "winning_canary": winning_canary,
                    "confirmed_count": confirmed_count,
                    "partial_count": partial_count,
                }
            ),
            references=self.META.references,
            tags=tags,
        )
