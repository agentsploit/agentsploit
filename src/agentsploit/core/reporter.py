"""Output reporters - turn a session's findings into JSON, SARIF, or Rich console output."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentsploit.core.finding import Severity

if TYPE_CHECKING:
    from agentsploit.core.session import Session


_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.INFO: "dim",
    Severity.LOW: "blue",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "magenta",
    Severity.CRITICAL: "bold red",
}


class Reporter(ABC):
    """Base reporter interface."""

    @abstractmethod
    def emit(self, session: Session) -> None: ...


class RichReporter(Reporter):
    """Human-readable console output using Rich."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def emit(self, session: Session) -> None:
        if not session.findings:
            self.console.print(
                Panel(
                    "[green]No findings.[/green]\n"
                    f"Engagement: [bold]{session.authorization.engagement_id}[/bold]\n"
                    f"Session:    [bold]{session.id}[/bold]",
                    title="AgentSploit",
                    border_style="green",
                )
            )
            return

        table = Table(title=f"Findings - {session.authorization.engagement_id} / {session.id}")
        table.add_column("Sev", justify="center")
        table.add_column("Module")
        table.add_column("Check")
        table.add_column("Target", overflow="fold")
        table.add_column("Title", overflow="fold")

        for f in sorted(session.findings, key=lambda x: -x.severity):
            table.add_row(
                f"[{_SEVERITY_STYLE[f.severity]}]{f.severity.label.upper()}[/]",
                f.module,
                f.check,
                f.target,
                f.title,
            )

        self.console.print(table)


class JSONReporter(Reporter):
    """Machine-readable JSON output to a file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def emit(self, session: Session) -> None:
        data: dict[str, Any] = {
            "session_id": session.id,
            "engagement_id": session.authorization.engagement_id,
            "authorized_by": session.authorization.authorized_by,
            "auth_hash": session.authorization.source_hash,
            "findings": [f.model_dump(mode="json") for f in session.findings],
        }
        self.path.write_text(json.dumps(data, indent=2))


class SARIFReporter(Reporter):
    """SARIF 2.1.0 output for integration with code-scanning tooling."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def emit(self, session: Session) -> None:
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for f in session.findings:
            rule_id = f"{f.module}/{f.check}"
            rules.setdefault(
                rule_id,
                {
                    "id": rule_id,
                    "name": f.check,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "helpUri": f.references[0] if f.references else "",
                    "defaultConfiguration": {"level": self._sarif_level(f.severity)},
                },
            )
            results.append(
                {
                    "ruleId": rule_id,
                    "level": self._sarif_level(f.severity),
                    "message": {"text": f.description},
                    "properties": {
                        "target": f.target,
                        "severity": f.severity.label,
                        "tags": f.tags,
                        "fingerprint": f.fingerprint(),
                    },
                    "partialFingerprints": {"primary": f.fingerprint()},
                }
            )

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "agentsploit",
                            "informationUri": "https://github.com/agentsploit/agentsploit",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    "properties": {
                        "engagement_id": session.authorization.engagement_id,
                        "session_id": session.id,
                        "auth_hash": session.authorization.source_hash,
                    },
                }
            ],
        }
        self.path.write_text(json.dumps(sarif, indent=2))

    @staticmethod
    def _sarif_level(severity: Severity) -> str:
        if severity >= Severity.HIGH:
            return "error"
        if severity == Severity.MEDIUM:
            return "warning"
        return "note"
