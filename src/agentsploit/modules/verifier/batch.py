"""BatchPathVerifier - run PathVerifier across every interesting path in a graph.

Concurrency-controlled, deduplicated by (source, sink), and emits both per-
path findings and an aggregate summary. Useful when you have a freshly-built
permission graph and want to know which mapper hypotheses survive contact
with a real agent.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

from agentsploit.core.finding import Evidence, Finding, Severity
from agentsploit.core.module import Category, Module, ModuleMeta
from agentsploit.core.target import TargetType
from agentsploit.modules.mapper.models import Graph, Path, Privilege
from agentsploit.modules.mapper.paths import find_all_paths
from agentsploit.modules.runner.config import RunnerConfig
from agentsploit.modules.verifier.verifier import PathVerifier, VerifierOutcome
from agentsploit.utils.logging import get_logger

if TYPE_CHECKING:
    from agentsploit.core.session import Session
    from agentsploit.core.target import Target


log = get_logger(__name__)


@dataclass
class _PathResult:
    path: Path
    outcome: VerifierOutcome | None
    findings: list[Finding]
    error: str | None = None


class BatchPathVerifier(Module):
    META: ClassVar[ModuleMeta] = ModuleMeta(
        name="verifier/batch",
        category=Category.EXPLOIT,
        description=(
            "Run PathVerifier across every source→sink path in a permission "
            "graph (deduplicated by endpoint pair), with concurrency control "
            "and an aggregate confirmation-rate summary."
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
        tags=["verifier", "batch", "exploit"],
    )

    def __init__(
        self,
        graph: Graph,
        *,
        base_config: RunnerConfig | None = None,
        max_path_length: int = 4,
        min_sink_privilege: Privilege = Privilege.EGRESS,
        max_paths: int | None = None,
        parallel: int = 2,
        fuzz: bool = False,
        fuzz_techniques: list[str] | None = None,
    ) -> None:
        self.graph = graph
        self.base_config = base_config
        self.max_path_length = max_path_length
        self.min_sink_privilege = min_sink_privilege
        self.max_paths = max_paths
        self.parallel = max(1, parallel)
        self.fuzz = fuzz
        self.fuzz_techniques = fuzz_techniques

    async def run(self, target: Target, session: Session) -> AsyncIterator[Finding]:
        all_paths = find_all_paths(
            self.graph,
            max_length=self.max_path_length,
            min_privilege=self.min_sink_privilege,
        )
        unique_paths = _dedupe_by_endpoints(all_paths)
        if self.max_paths is not None:
            unique_paths = unique_paths[: self.max_paths]

        log.info(
            "batch_verify.start",
            total_paths=len(all_paths),
            unique_endpoint_pairs=len(unique_paths),
            parallel=self.parallel,
        )

        if not unique_paths:
            yield Finding(
                module=self.META.name,
                check="verifier/batch_no_paths",
                target=target.uri,
                severity=Severity.INFO,
                title="No paths to verify",
                description=(
                    f"The graph contains no source→sink path at or above "
                    f"{self.min_sink_privilege.label!r} privilege within "
                    f"{self.max_path_length} hops."
                ),
                remediation=(
                    "Build the graph against more targets, lower --min-privilege, "
                    "or raise --max-length."
                ),
                tags=["verifier", "batch", "no-paths"],
            )
            return

        results = await self._run_all(unique_paths, target, session)

        for result in results:
            for finding in result.findings:
                yield finding

        yield self._build_summary(target, results)

    async def _run_all(
        self, paths: list[Path], target: Target, session: Session
    ) -> list[_PathResult]:
        sem = asyncio.Semaphore(self.parallel)

        async def _run_one(path: Path) -> _PathResult:
            async with sem:
                if self.fuzz:
                    from agentsploit.modules.verifier.fuzzer import FuzzPathVerifier

                    module: Module = FuzzPathVerifier(
                        path=path,
                        base_config=self.base_config,
                        techniques=self.fuzz_techniques,
                    )
                else:
                    module = PathVerifier(path=path, base_config=self.base_config)
                findings: list[Finding] = []
                try:
                    async for f in module.run(target, session):
                        findings.append(f)
                except Exception as e:
                    log.warning("batch_verify.path_failed", path=path.render(), error=str(e))
                    return _PathResult(path=path, outcome=None, findings=[], error=str(e))

                outcome = _classify_findings(findings)
                return _PathResult(path=path, outcome=outcome, findings=findings)

        tasks = [_run_one(p) for p in paths]
        return list(await asyncio.gather(*tasks))

    def _build_summary(self, target: Target, results: list[_PathResult]) -> Finding:
        total = len(results)
        confirmed = sum(1 for r in results if r.outcome == VerifierOutcome.CONFIRMED)
        partial = sum(1 for r in results if r.outcome == VerifierOutcome.PARTIAL)
        failed = sum(1 for r in results if r.outcome == VerifierOutcome.FAILED)
        errored = sum(1 for r in results if r.outcome is None)
        rate = (confirmed / total * 100.0) if total else 0.0

        top_confirmed = [
            r.path.render() for r in results if r.outcome == VerifierOutcome.CONFIRMED
        ][:10]

        severity = Severity.CRITICAL if confirmed else Severity.INFO

        return Finding(
            module=self.META.name,
            check="verifier/batch_summary",
            target=target.uri,
            severity=severity,
            title=(
                f"Batch path verification: {confirmed}/{total} confirmed "
                f"({rate:.0f}% confirmation rate)"
            ),
            description=(
                f"Verified {total} unique source-sink path(s) across the graph.\n\n"
                f"  Confirmed: {confirmed}\n"
                f"  Partial:   {partial}\n"
                f"  Failed:    {failed}\n"
                f"  Errored:   {errored}\n\n"
                + (
                    "Top confirmed paths:\n" + "\n".join(f"  - {p}" for p in top_confirmed)
                    if top_confirmed
                    else "No paths confirmed in this batch."
                )
            ),
            remediation=(
                "For each CONFIRMED path, treat it as a proven exploit and apply "
                "the remediation from its per-path finding. PARTIAL paths warrant "
                "payload tuning before re-running. FAILED paths may indicate "
                "effective injection defences on this agent/system-prompt combo."
            ),
            evidence=Evidence(
                extra={
                    "total_paths_tested": total,
                    "confirmed": confirmed,
                    "partial": partial,
                    "failed": failed,
                    "errored": errored,
                    "confirmation_rate_pct": rate,
                    "top_confirmed_paths": top_confirmed,
                }
            ),
            references=self.META.references,
            tags=["verifier", "batch", "summary"],
        )


# --------------------------------------------------------------------- helpers


def _dedupe_by_endpoints(paths: list[Path]) -> list[Path]:
    """Keep one path per (source.id, sink.id) pair - the shortest by edge count,
    then by total weight."""
    best: dict[tuple[str, str], Path] = {}
    for p in paths:
        key = (p.source.id, p.sink.id)
        existing = best.get(key)
        if existing is None:
            best[key] = p
            continue
        if (p.length, p.total_weight) < (existing.length, existing.total_weight):
            best[key] = p
    # Stable order: by severity score desc, then source name, then sink name
    return sorted(
        best.values(),
        key=lambda p: (-p.severity_score, p.source.name, p.sink.name),
    )


def _classify_findings(findings: list[Finding]) -> VerifierOutcome:
    """Reduce a verifier's per-path findings to a single outcome label."""
    for f in findings:
        if "path-confirmed" in f.tags:
            return VerifierOutcome.CONFIRMED
    for f in findings:
        if "path-partial" in f.tags:
            return VerifierOutcome.PARTIAL
    return VerifierOutcome.FAILED
