"""Authentication credentials for MCP HTTP/SSE transports.

Kept deliberately separate from the engagement Authorization model:
  - `core.Authorization` = which targets you're allowed to touch (scope)
  - `mcp.auth.Credentials` = how you prove identity to the target itself

Auth credentials are passed via CLI flags (`--header`, `--auth-bearer`,
`--auth-env`) or environment variables, never stored in the YAML scope file.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Credentials:
    """How to authenticate to an MCP server. All fields optional."""

    headers: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None
    verify_tls: bool = True
    timeout_seconds: float = 30.0

    def merged_headers(self) -> dict[str, str]:
        merged = dict(self.headers)
        if self.bearer_token and "Authorization" not in merged:
            merged["Authorization"] = f"Bearer {self.bearer_token}"
        merged.setdefault("User-Agent", "agentsploit/0.2.0")
        return merged

    @classmethod
    def from_cli(
        cls,
        *,
        headers: list[str] | None = None,
        bearer_token: str | None = None,
        bearer_env: str | None = None,
        insecure: bool = False,
        timeout: float = 30.0,
    ) -> Credentials:
        """Build credentials from CLI options.

        `headers` is a list of "Key:Value" strings, as repeated `--header` flags.
        `bearer_env` resolves the token from an environment variable.
        """
        parsed_headers: dict[str, str] = {}
        for raw in headers or []:
            if ":" not in raw:
                raise ValueError(f"Invalid header {raw!r}; expected 'Key: Value' format")
            k, _, v = raw.partition(":")
            parsed_headers[k.strip()] = v.strip()

        resolved_token = bearer_token
        if bearer_env:
            resolved_token = os.environ.get(bearer_env)
            if resolved_token is None:
                raise ValueError(f"Environment variable {bearer_env!r} is not set")

        return cls(
            headers=parsed_headers,
            bearer_token=resolved_token,
            verify_tls=not insecure,
            timeout_seconds=timeout,
        )
