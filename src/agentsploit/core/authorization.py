"""Authorization model - runtime-enforced engagement scope."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml
from pydantic import BaseModel, Field, field_validator


class AuthorizationError(Exception):
    """Raised when a target is outside the authorized engagement scope."""


class Authorization(BaseModel):
    """Engagement-scoped authorization.

    Loaded from a YAML file at the start of every scan; targets are matched
    against `targets` (allowlist) and `forbidden` (denylist) globs before
    any network or process I/O happens.
    """

    authorized_by: str
    authorized_at: datetime
    valid_until: datetime
    engagement_id: str = Field(default_factory=lambda: f"eng-{uuid4().hex[:8]}")
    scope_notes: str = ""
    targets: list[str]
    forbidden: list[str] = Field(default_factory=list)

    _source_path: Path | None = None
    _source_hash: str | None = None

    @field_validator("targets")
    @classmethod
    def _targets_non_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("`targets` must contain at least one pattern")
        return v

    @classmethod
    def load(cls, path: str | Path) -> Authorization:
        """Load an authorization file from disk."""
        p = Path(path).resolve()
        raw_bytes = p.read_bytes()
        data: dict[str, Any] = yaml.safe_load(raw_bytes)
        auth = cls.model_validate(data)
        auth._source_path = p
        auth._source_hash = hashlib.sha256(raw_bytes).hexdigest()
        return auth

    def save(self, path: str | Path) -> None:
        """Write an authorization file to disk.

        Writes with `newline="\\n"` so the on-disk bytes are stable across
        operating systems (Windows would otherwise translate `\\n` to
        `\\r\\n`, producing a different file and a different
        ``source_hash`` than ``load()`` would compute on read-back).
        """
        p = Path(path).resolve()
        data = self.model_dump(mode="json")
        text = yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
        with p.open("w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        # Re-hash from the file bytes so save+load round-trip the same hash on
        # every OS, even if the local FS rewrote anything.
        self._source_path = p
        self._source_hash = hashlib.sha256(p.read_bytes()).hexdigest()

    @property
    def source_hash(self) -> str:
        """SHA-256 of the source file, included in every finding for audit."""
        return self._source_hash or "unsaved"

    def check(self, target_uri: str) -> None:
        """Raise AuthorizationError if the target is out of scope.

        Order of checks:
          1. Expiry
          2. Forbidden patterns (always deny if matched)
          3. Allowed patterns (must match at least one)
        """
        now = datetime.now(UTC)
        if now > self.valid_until:
            raise AuthorizationError(
                f"Authorization expired at {self.valid_until.isoformat()} "
                f"(now {now.isoformat()}). Renew with a fresh authorization file."
            )

        for pattern in self.forbidden:
            if fnmatch(target_uri, pattern):
                raise AuthorizationError(
                    f"Target {target_uri!r} matches forbidden pattern {pattern!r}; "
                    f"refusing to scan."
                )

        for pattern in self.targets:
            if fnmatch(target_uri, pattern):
                return

        raise AuthorizationError(
            f"Target {target_uri!r} not in authorized scope. Allowed patterns: {self.targets}"
        )


class TrainingAuth(Authorization):
    """Restricted authorization for `--training` mode.

    Accepts only the bundled vulnerable fixture and localhost targets.
    Cannot be loaded from a file; constructed in-memory only.
    """

    def __init__(self) -> None:
        super().__init__(
            authorized_by="agentsploit-training-mode",
            authorized_at=datetime.now(UTC),
            valid_until=datetime.now(UTC).replace(year=9999),
            engagement_id="training",
            scope_notes="Training mode: bundled fixture and localhost targets only.",
            targets=[
                "stdio://*tests/fixtures/vulnerable_mcp*",
                "stdio://*tests/fixtures/vulnerable_sink_mcp*",
                "stdio://*tests/fixtures/vulnerable_http_mcp*",
                "stdio://*tests/fixtures/benign_mcp*",
                "stdio://*vulnerable_mcp*",
                "stdio://*vulnerable_sink_mcp*",
                "stdio://*vulnerable_http_mcp*",
                "stdio://*benign_mcp*",
                "agent+mock://*",
                "http://localhost*",
                "http://127.0.0.1*",
                "mcp+http://localhost*",
                "mcp+http://127.0.0.1*",
            ],
            forbidden=[],
        )
        self._source_hash = "training-mode"
