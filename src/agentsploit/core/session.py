"""Engagement session - groups findings with the authorization that produced them."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, Field

from agentsploit.core.authorization import Authorization
from agentsploit.core.finding import Finding


class Session(BaseModel):
    """A single engagement session.

    Owns the authorization, accumulates findings, and persists artifacts under
    `output_dir/engagements/<engagement_id>/<session_id>/`.
    """

    id: str = Field(default_factory=lambda: f"sess-{uuid4().hex[:8]}")
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    authorization: Authorization
    findings: list[Finding] = Field(default_factory=list)
    output_dir: Path = Field(default_factory=lambda: Path.cwd() / "engagements")

    model_config = {"arbitrary_types_allowed": True}

    @property
    def artifact_dir(self) -> Path:
        d = self.output_dir / self.authorization.engagement_id / self.id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def add(self, finding: Finding) -> None:
        finding.evidence.extra.setdefault("auth_hash", self.authorization.source_hash)
        finding.evidence.extra.setdefault("engagement_id", self.authorization.engagement_id)
        finding.evidence.extra.setdefault("session_id", self.id)
        self.findings.append(finding)

    def persist(self) -> Path:
        """Write the session manifest + findings to disk; return the manifest path."""
        manifest = self.artifact_dir / "session.json"
        blob = json.dumps(
            {
                "session_id": self.id,
                "engagement_id": self.authorization.engagement_id,
                "authorized_by": self.authorization.authorized_by,
                "auth_hash": self.authorization.source_hash,
                "started_at": self.started_at.isoformat(),
                "finished_at": datetime.now(UTC).isoformat(),
                "finding_count": len(self.findings),
                "findings": [f.model_dump(mode="json") for f in self.findings],
            },
            indent=2,
            ensure_ascii=False,
        )
        manifest.write_text(blob, encoding="utf-8")
        return manifest
