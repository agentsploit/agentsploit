"""Finding model - the unit of output produced by every check."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(IntEnum):
    """Severity ordering matches CVSS qualitative bands."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()


class Evidence(BaseModel):
    """Concrete evidence collected to support a finding."""

    request: str | None = None
    response: str | None = None
    artifact_path: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """A single security finding produced by a check."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    module: str
    check: str
    target: str
    severity: Severity

    title: str
    description: str
    remediation: str
    references: list[str] = Field(default_factory=list)

    evidence: Evidence = Field(default_factory=Evidence)
    tags: list[str] = Field(default_factory=list)

    def fingerprint(self) -> str:
        """Stable hash used to dedupe findings across runs."""
        key = f"{self.module}|{self.check}|{self.target}|{self.title}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]
