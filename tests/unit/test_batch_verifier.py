"""BatchPathVerifier dedupe + aggregation unit tests."""

from __future__ import annotations

from agentsploit.core.finding import Finding, Severity
from agentsploit.modules.mapper.models import (
    Classification,
    Edge,
    Node,
    Path,
    Privilege,
)
from agentsploit.modules.verifier.batch import (
    _classify_findings,
    _dedupe_by_endpoints,
)
from agentsploit.modules.verifier.verifier import VerifierOutcome


def _src(name: str, server: str = "srv-a") -> Node:
    return Node(
        id=f"{server}::{name}",
        server_uri=server,
        name=name,
        description="",
        classification=Classification.SOURCE,
        privilege=Privilege.READ,
    )


def _sink(name: str, privilege: Privilege = Privilege.EGRESS, server: str = "srv-b") -> Node:
    return Node(
        id=f"{server}::{name}",
        server_uri=server,
        name=name,
        description="",
        classification=Classification.SINK,
        privilege=privilege,
    )


def _pivot(name: str, server: str = "srv-x") -> Node:
    return Node(
        id=f"{server}::{name}",
        server_uri=server,
        name=name,
        description="",
        classification=Classification.PIVOT,
        privilege=Privilege.INTERNAL_ACTION,
    )


def _path(*nodes: Node, weight: float = 1.0) -> Path:
    from itertools import pairwise

    edges = [Edge(src=a.id, dst=b.id, weight=weight) for a, b in pairwise(nodes)]
    return Path(nodes=list(nodes), edges=edges, total_weight=weight * len(edges))


def test_dedupe_keeps_shortest_path_per_endpoint_pair() -> None:
    src = _src("read_email")
    sink = _sink("send_email")
    pivot = _pivot("cache")

    direct = _path(src, sink, weight=2.0)  # length 1
    via_pivot = _path(src, pivot, sink, weight=1.0)  # length 2

    deduped = _dedupe_by_endpoints([direct, via_pivot, direct])
    # Same (source, sink) pair → one entry, the shorter one
    assert len(deduped) == 1
    assert deduped[0].length == 1


def test_dedupe_keeps_lower_weight_when_lengths_equal() -> None:
    src = _src("read_email")
    sink = _sink("send_email")
    heavy = _path(src, sink, weight=10.0)
    light = _path(src, sink, weight=1.0)
    deduped = _dedupe_by_endpoints([heavy, light])
    assert deduped[0].total_weight == 1.0


def test_dedupe_keeps_distinct_endpoint_pairs() -> None:
    src = _src("read_email")
    s1 = _sink("send_email")
    s2 = _sink("git_push", privilege=Privilege.MUTATION)
    deduped = _dedupe_by_endpoints([_path(src, s1), _path(src, s2)])
    assert len(deduped) == 2


def test_dedupe_sorts_by_severity_score_desc() -> None:
    src = _src("read_email")
    egress = _sink("send_email", privilege=Privilege.EGRESS)
    execution = _sink("run_shell", privilege=Privilege.EXECUTION)
    deduped = _dedupe_by_endpoints([_path(src, egress), _path(src, execution)])
    # Execution sink should come first (higher severity_score)
    assert deduped[0].sink.privilege == Privilege.EXECUTION


def _finding(*tags: str) -> Finding:
    return Finding(
        module="verifier/path",
        check="verifier/test",
        target="t",
        severity=Severity.INFO,
        title="",
        description="",
        remediation="",
        tags=list(tags),
    )


def test_classify_confirmed_when_any_finding_has_tag() -> None:
    findings = [_finding("verifier"), _finding("verifier", "path-confirmed")]
    assert _classify_findings(findings) == VerifierOutcome.CONFIRMED


def test_classify_partial_when_no_confirmed_but_partial_present() -> None:
    findings = [_finding("verifier", "path-partial")]
    assert _classify_findings(findings) == VerifierOutcome.PARTIAL


def test_classify_failed_otherwise() -> None:
    findings = [_finding("verifier", "path-failed")]
    assert _classify_findings(findings) == VerifierOutcome.FAILED


def test_classify_failed_for_empty_findings() -> None:
    assert _classify_findings([]) == VerifierOutcome.FAILED
