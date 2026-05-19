# Writing modules

A module is a Python class that subclasses `agentsploit.core.Module`, declares a `META: ModuleMeta`, and implements `run()` as an async generator yielding `Finding` objects.

## Minimal module

```python
# src/agentsploit/modules/example/scanner.py
from collections.abc import AsyncIterator
from typing import ClassVar

from agentsploit.core import (
    Category, Evidence, Finding, Module, ModuleMeta,
    Session, Severity, Target, TargetType,
)


class ExampleScanner(Module):
    META: ClassVar[ModuleMeta] = ModuleMeta(
        name="example/scanner",
        category=Category.SCANNER,
        description="One-line summary of what this checks.",
        references=["https://example.com/disclosure"],
        supported_targets=[TargetType.MCP_STDIO],
        tags=["example"],
    )

    async def run(self, target: Target, session: Session) -> AsyncIterator[Finding]:
        # ... do your check ...
        yield Finding(
            module=self.META.name,
            check="example/specific_check",
            target=target.uri,
            severity=Severity.MEDIUM,
            title="Short, scannable title",
            description="Full prose explanation a reviewer can act on.",
            remediation="Concrete, actionable fix.",
            references=self.META.references,
            evidence=Evidence(extra={"key": "value"}),
            tags=["example", "specific_check"],
        )
```

The class is registered automatically via `Module.__init_subclass__`. Discovery happens on first CLI invocation via `Registry.discover()`.

## Checklist for new modules

- [ ] **Authorization-aware:** never make network or process calls outside what `Authorization.check()` has approved (the framework guarantees this for `Target`, but if you fan out to *other* hosts, re-check each one).
- [ ] **No 0-days:** only ship checks for publicly disclosed and ideally CVE-assigned issues.
- [ ] **Self-contained docstring:** vulnerability class, references, remediation in the file's module docstring.
- [ ] **References:** include the original advisory, CVE, or research blog post in `META.references` and in any `Finding.references`.
- [ ] **Unit tests:** every check gets a positive (vulnerable input → finding) and negative (clean input → no finding) case.
- [ ] **Integration test (if applicable):** if the module needs a server fixture, add one under `tests/fixtures/` and write an integration test that runs the module against it.
- [ ] **Update `docs/modules.md`** with the new entry.

## Severity guide

| Severity | Use when |
|---|---|
| `INFO` | Informational discovery (e.g. inventory output) |
| `LOW` | Minor disclosure or hardening miss with no direct attack path |
| `MEDIUM` | Real weakness requiring chaining or operator misconfiguration |
| `HIGH` | Direct exploitation by an untrusted upstream content source |
| `CRITICAL` | Confirmed credential disclosure or trivial unauthorized action |

## Async I/O conventions

- Modules are async; the runtime uses `asyncio.run()` once per CLI invocation.
- Use `httpx.AsyncClient` for HTTP, not `requests`.
- Use the official `mcp` SDK for MCP, not raw JSON-RPC.
- If a module is CPU-bound and has no I/O, declare an `async def run(...)` that yields synchronously - that's fine.

## What lives in `Evidence`

Anything a reviewer would want to see to triage the finding:

- `request` / `response`: the request you sent and the response you got, redacted as needed.
- `artifact_path`: path to a binary artifact (e.g. generated PDF) under `session.artifact_dir`.
- `extra`: free-form dict - patterns matched, codepoints, etc.

The framework auto-stamps `auth_hash`, `engagement_id`, and `session_id` into `evidence.extra` when `session.add(finding)` is called.
