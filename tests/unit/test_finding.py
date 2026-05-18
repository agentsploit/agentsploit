"""Finding model tests."""

from __future__ import annotations

from agentsploit.core import Finding, Severity


def _make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "module": "mcp/scanner",
        "check": "tool_poisoning",
        "target": "stdio://./server.py",
        "severity": Severity.HIGH,
        "title": "Tool poisoning detected",
        "description": "...",
        "remediation": "...",
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_severity_ordering() -> None:
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_severity_label() -> None:
    assert Severity.CRITICAL.label == "critical"


def test_fingerprint_stable() -> None:
    a = _make_finding()
    b = _make_finding()
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_changes_with_title() -> None:
    a = _make_finding(title="A")
    b = _make_finding(title="B")
    assert a.fingerprint() != b.fingerprint()
