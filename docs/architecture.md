# Architecture

AgentSploit is a plugin-based framework for testing AI agents and MCP servers. The design borrows from Metasploit (module categories), Burp Suite (target + session model), and modern Python tooling (typer + pydantic + structlog).

## High-level shape

```
┌─────────────────────────────────────────────────────────┐
│ CLI (typer)                                             │
│   scan / generate / list-modules / init-auth / version  │
└──────────────────┬──────────────────────────────────────┘
                   │
        ┌──────────▼────────────┐
        │  Session              │  ─────►  Reporter
        │   + Authorization     │            (rich / json / sarif)
        │   + Findings          │
        └──────────┬────────────┘
                   │
        ┌──────────▼────────────┐
        │  Registry             │  ◄── Module.__init_subclass__
        │   (modules by name)   │      (plugins self-register)
        └──────────┬────────────┘
                   │
        ┌──────────▼────────────────────────────┐
        │  Modules                              │
        │   ├─ mcp/scanner   (4 checks)         │
        │   └─ injection/generator              │
        │        ├─ 5 techniques                │
        │        └─ 6 carriers                  │
        └───────────────────────────────────────┘
```

## Core abstractions (`agentsploit.core`)

| Class | Role |
|---|---|
| `Module` | Abstract base - every attack capability is a subclass; `run()` yields findings |
| `ModuleMeta` | Static metadata (name, category, references, supported target types) |
| `Target` | Parsed URI + inferred `TargetType` |
| `Authorization` | YAML-loaded engagement scope; enforced via `check()` before every scan |
| `TrainingAuth` | Restricted in-memory authorization for `--training` mode |
| `Session` | Engagement context: owns authorization, accumulates findings, persists artifacts |
| `Finding` / `Evidence` / `Severity` | Output unit; SARIF-compatible |
| `Registry` | Singleton mapping module name → class; populated by `Module.__init_subclass__` |
| `Reporter` | `RichReporter`, `JSONReporter`, `SARIFReporter` |

## Authorization model

Authorization is enforced **at the CLI boundary**, before any I/O. Three layers:

1. **Source.** Either a YAML file (`--auth`) or `TrainingAuth` (`--training`).
2. **Expiry.** `valid_until` is checked first.
3. **Pattern match.** `forbidden` globs (always deny) then `targets` globs (must match).

The source file's SHA-256 is recorded in every finding's evidence for audit traceability.

## Module discovery

`Registry.discover()` walks `agentsploit.modules.*` with `pkgutil.walk_packages` and imports every submodule. Each `Module` subclass calls `registry.register(cls)` in `__init_subclass__`, so importing is registration. This means:

- Third-party modules work - install a package that drops files into the namespace and they appear in `list-modules`.
- No central registry file to maintain.

## Module categories

| Category | Purpose | v0.1 module |
|---|---|---|
| `scanner` | Read-only enumeration + analysis | `mcp/scanner` |
| `payload` | Generates artifacts that exploit a class of weakness | `injection/generator` (technically a sub-API, see below) |
| `exploit` | Active exploitation (multi-step, may modify state) | (v0.2+) |
| `recon` | Out-of-band intelligence gathering | (v0.2+) |

## The injection generator

The payload generator does not implement `Module` directly because it's compositional - it's a (technique × carrier) factory invoked from `agentsploit generate injection`. Future versions may expose a `Module` wrapper for batch generation against a finding feed.

```
InjectionContext (goal, canary)
       │
       ▼
Technique.craft() ──► raw injection string
       │
       ▼
Carrier.wrap()    ──► CarrierOutput (bytes | str + content-type)
       │
       ▼
InjectionArtifact (written to disk by CLI)
```

The canary is the load-bearing observability primitive: a unique, random marker (`AS-XXXXXX`) embedded in every payload. If you see the canary surface in the target agent's outputs, logs, or downstream effects, the injection landed.

## Output formats

- **Rich console** - interactive use, severity-coloured table.
- **JSON** - structured, machine-readable; matches `Finding.model_dump()` shape.
- **SARIF 2.1.0** - code-scanning standard; consumable by GitHub Code Scanning, Defender for Cloud, etc.

## Extension points

| To add | Where |
|---|---|
| A new MCP check | `src/agentsploit/modules/mcp/checks/<name>.py` + register in `checks/__init__.py:ALL_CHECKS` |
| A new injection technique | `src/agentsploit/modules/injection/techniques/<name>.py` + register in `techniques/__init__.py:ALL_TECHNIQUES` |
| A new carrier | `src/agentsploit/modules/injection/carriers/<name>.py` + register in `carriers/__init__.py:ALL_CARRIERS` |
| A new top-level module (e.g. permission-graph mapper) | `src/agentsploit/modules/<name>/` - subclass `Module`, set `META`, implement `run()` |
| A new transport | `src/agentsploit/modules/mcp/client.py` + new `TargetType` value |
