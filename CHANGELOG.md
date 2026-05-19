# Changelog

All notable changes to AgentSploit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-05-18

First stable release. No new attack capabilities — instead this release is
all polish, packaging, and interoperability work that promises the public
API is stable and the SARIF output is interchange-grade.

### Added

- **`docs/getting-started.md`** — guided 10-minute pipeline tour with the
  bundled fixtures, no API keys or auth YAML required
- **`docs/cli-reference.md`** — complete CLI cheatsheet covering every
  subcommand, flag, URI scheme, and exit code
- **`docs/sarif.md`** — SARIF 2.1.0 integration guide with a copy-pasteable
  GitHub Code Scanning workflow + severity-mapping table
- **Benign MCP fixture** (`tests/fixtures/benign_mcp/`) — a well-engineered
  reference server with narrow schemas, plain descriptions, namespaced
  tool names. Used by the new smoke test that proves the scanner doesn't
  false-positive on non-vulnerable targets.
- **`tests/integration/test_sarif_schema.py`** — validates every SARIF
  output against the official 2.1.0 JSON Schema. v1.0 guarantees this
  passes for every release.
- README status badges (1.0 stable, Python, license, SARIF)
- `jsonschema>=4.23.0` to dev dependencies (powers the SARIF audit test)

### Changed

- `pyproject.toml` classifier bumped to `Development Status :: 5 - Production/Stable`
- **`SECURITY.md`** rewritten with concrete SLAs (72 h ack, 7 d triage, 30
  d HIGH/CRITICAL fix, 60 d MEDIUM fix), supported-versions table
  reflecting 1.0, and a Hall of Fame for credited reporters
- **Release workflow** (`.github/workflows/release.yml`) now gates publish
  on the full quality suite (ruff + mypy + pytest), wheel-installs into a
  clean venv as a smoke check, and uses PyPI Trusted Publishing
  attestations
- `TrainingAuth` extended to allow the benign fixture

### Verified

- 230+ tests pass across unit + integration suites
- mypy strict-mode clean on all source files
- ruff lint + format clean
- SARIF output validates against the official 2.1.0 JSON Schema
- `uv build` + fresh-venv install + `agentsploit version` works end-to-end
- Scanner produces zero non-INFO findings against the benign fixture
  (no false positives)

## [0.9.0] - 2026-05-18

### Added

- **OpenAIAdapter** — drives OpenAI Chat Completions with native tool use
  until the agent stops calling tools. Handles the JSON-string-encoded
  `function.arguments` quirk and the `tool` role follow-up shape.
- **GenericHTTPAdapter** — POSTs to a configurable HTTP endpoint with
  OpenAI-shaped request/response. Bearer auth via `api_key_env`, extra
  headers via the new `RunnerConfig.headers` field. Override
  `_build_request_body` / `_parse_response` for non-OpenAI shapes.
- `RunnerConfig.headers: dict[str, str]` — extra HTTP headers (HTTP
  providers only)
- `get_adapter("openai")` and `get_adapter("http")` registered
- `examples/agent-openai.yaml` and `examples/agent-http.yaml`
- Custom-adapter authoring guide in `docs/runner.md`
- `openai>=1.50.0` runtime dep
- Unit tests for both adapters using `httpx.MockTransport`

### Changed

- Adapter catalog in `docs/runner.md` rewritten as a table covering all
  four providers
- README v0.3 section updated to reflect 4 adapters

## [0.8.0] - 2026-05-18

### Added

- **Memory poisoning** — the first multi-phase attack module. Attacker
  controls shared storage in phase 1; victim agent retrieves the
  poisoned content in a separate phase 2 run and is steered into a
  sink-tool call carrying the canary.
- `poisoning.MemoryStore` ABC + `InMemoryNoteStore` impl with
  write/read counters for evidence
- `poisoning.build_save_note_tool` / `build_read_note_tool` factories —
  store-backed MockTool variants that mutate the shared store via the
  new on_call hook
- `poisoning.StoredNotePoison` — wraps any v0.7 targeted technique in
  note-flavoured cover text so retrieved content looks plausible
- `poisoning.MemoryPoisoner` Module — owns the store, simulates the
  attacker write directly (the half not under test), runs the victim
  agent for real, scopes detection to the sink tool, emits one of:
    `CONFIRMED`       — victim called sink with canary (severity tied
                        to sink privilege)
    `PARTIAL`         — note retrieved but canary didn't surface in sink
    `NOT_RETRIEVED`   — note stored but victim never read it
    `NOT_STORED`      — attacker write failed (setup issue)
- CLI: `agentsploit poison verify --sink-tool <name> [--sink-arg X]
  [--sink-privilege X] [--technique X] [--store-key X]`
- `MockTool.on_call` callback hook — lets a single tool's response
  depend on its tool-call arguments. Both runner adapters now thread
  arguments through `render_response`.
- `docs/poisoning.md` covering the threat model, outcomes,
  defender-actionable remediation pattern, and the v0.9 RAG extension path

### Changed

- README sectioned with poisoning as v0.8 capability
- `MockTool.render_response(payload)` → `render_response(payload, arguments=None)`
  to support arg-aware behaviour. Existing callers still work since
  `arguments` is optional.

## [0.7.0] - 2026-05-18

### Added

- **Technique fuzzing across paths** — when one injection envelope fails,
  automatically try the others until something lands
- `verifier.targeted_techniques` catalog with 5 variants of the path-
  targeted injection, each wrapping the same "call <sink> with <canary>
  in <arg>" instruction in a different envelope:
    `role_confusion`  — fake <system>/<assistant> turns (v0.5 default)
    `direct`          — bare imperative
    `delimiter`       — escape from a fenced content block
    `unicode_tag`     — invisible U+E0000 tag-block smuggling
    `tool_smuggling`  — embed plausible-looking tool_call JSON
- `verifier.FuzzPathVerifier` Module that iterates techniques against a
  single path, stops at first CONFIRMED (configurable), and emits a
  summary finding showing the winning technique + per-technique outcomes
- `verifier.PathVerifier(... technique="...")` — pick one of the 5
  variants explicitly. Defaults to `role_confusion` for back-compat.
- `verifier.BatchPathVerifier(fuzz=True, fuzz_techniques=[...])` — run
  the fuzzer on every path in the graph
- CLI:
    * `agentsploit verify fuzz-path --from <s> --to <k>
      [--techniques <list>] [--no-early-stop]`
    * `agentsploit verify all-paths --fuzz [--techniques <list>]`
- Every per-path finding now carries a `technique:<name>` tag and a
  `technique` field in evidence — so triage tools can see which
  envelope produced each finding
- `docs/verifier.md` extended with the fuzzing workflow and the
  defender-actionable interpretation of which technique wins
- `verifier.techniques.PathVerifyTechnique` retained as a back-compat
  alias for `RoleConfusionPathVerify`

## [0.6.0] - 2026-05-18

### Added

- **Batch path verification** — `agentsploit verify all-paths` runs the
  v0.5 verifier across every source→sink path in a permission graph in
  one command, with concurrency control, deduplication, and an aggregate
  summary
- `verifier.BatchPathVerifier` Module: dedupes paths by `(source, sink)`
  pair (keeping shortest), parallelises up to `--parallel` runs (default
  2) via `asyncio.Semaphore`, isolates per-path errors so one failure
  doesn't kill the batch
- `--max-paths` cap for cost control on large graphs
- Aggregate `verifier/batch_summary` finding: confirmed/partial/failed/
  errored counts + confirmation-rate percentage + top 10 confirmed
  paths. CRITICAL severity when any path was confirmed.
- CLI: `agentsploit verify all-paths --graph <file> [--min-privilege X]
  [--max-paths N] [--parallel N] [--agent <cfg>]`

### Changed

- `docs/verifier.md` extended with the batch workflow + mock-pre-filter
  pattern (cheap triage before spending real LLM tokens)

## [0.5.0] - 2026-05-18

### Added

- **Path verifier** — closes the loop between the v0.4 mapper and the v0.3
  runner. Takes a mapper-inferred path and proves whether it's exploitable
  end-to-end by driving a path-targeted payload through a real or mock agent
- `verifier.PathVerifyTechnique` — targeted injection parameterised by
  `(sink_tool_name, sink_arg_name, sink_input_schema)`. Wraps a
  role-confusion envelope around an instruction to invoke the sink with
  the canary in a specific argument, and scaffolds the sink's other
  required args with plausible fillers.
- `verifier.synth_runner_config` — turns a `Path` plus base settings
  into a `RunnerConfig` whose mock tools mirror the path: source becomes
  the payload-bearing tool, sink becomes a passive observer tool,
  intermediate pivots are exposed for realism.
- `verifier.PathVerifier` Module emitting three outcome classes with
  severity tied to sink privilege:
    `CONFIRMED` — sink called with canary in args (CRITICAL/HIGH)
    `PARTIAL`   — sink reached or canary surfaced elsewhere (HIGH)
    `FAILED`    — no canary surface anywhere (INFO)
- `CanaryDetector.scan(..., only_tool=...)` — scopes the TOOL_CALL_ARGS
  surface to a specific tool name so "canary in sink args" is provable
  rather than just "canary somewhere in tool calls"
- MockAgentAdapter v0.5: now parses instructions of the form
  `call \`<tool>\` with arguments: k='v', …` and obeys them if the tool
  is registered. Makes the mock agent a faithful test fixture for chain
  completion without needing an LLM in the loop.
- CLI: `agentsploit verify path --graph <file> --from <tool> --to <tool>`
  with optional `--agent <config>` (defaults to mock for self-tests)
- `docs/verifier.md` covering outcomes, the pipeline, and hygiene

### Changed

- README sectioned with verifier as v0.5 capability

## [0.4.0] - 2026-05-18

### Added

- **Permission graph mapper** — BloodHound-style cross-server attack-path
  discovery for agent tool chains
- `mapper.Graph`, `Node`, `Edge`, `Path` pydantic models with stable IDs
  (`<server-uri>::<tool-name>`)
- `mapper.Classification` (source/pivot/sink/unknown) and `mapper.Privilege`
  (READ → INTERNAL_ACTION → EGRESS → MUTATION → EXECUTION)
- Heuristic classifier: name prefixes, sink-keyword sets, dangerous arg
  names (`command`, `to`, `shell`, …), description phrase matching
- Edge inference combining three signals:
    1. destination input-arg name appears in source description (strongest)
    2. shared pivot tokens between descriptions (`url`, `path`, `body`, …)
    3. source → sink baseline (weakest)
- Pathfinder: simple-path DFS up to `max_length` with `min_privilege` filter,
  Dijkstra-based shortest-path between named tools
- Exporters: JSON (lossless), GraphViz DOT, Mermaid (renders in GitHub MD)
- `mapper/permission_graph` Module emitting one INFO `mapper/built` finding
  plus one path finding per discovered route, with severity tied to sink
  privilege (EXECUTION → CRITICAL, MUTATION/EGRESS → HIGH)
- CLI: `agentsploit map build --targets ./targets.yaml` and
  `agentsploit map export --graph <file> --format mermaid|dot|json`
- Second vulnerable MCP fixture (`vulnerable_sink_mcp`) with sink-class
  tools (`send_email`, `git_push`, `run_shell`, `cache_summary`) that pairs
  with the existing source fixture to produce known cross-server paths
- `docs/mapper.md` and `examples/map-targets.yaml`

### Changed

- README sectioned with mapper as v0.4 capability

## [0.3.0] - 2026-05-18

### Added

- **Live agent runner** — drive an injection payload through a real LLM agent
  and confirm exploitation by detecting canary surface in the agent's outputs
- `runner.RunTrace` — adapter-agnostic transcript model (messages, tool calls,
  tool results, thinking, errors)
- `runner.MockTool` — tool definition the runner exposes to the agent; exactly
  one tool per run holds the payload
- `runner.CanaryDetector` with three surfaces:
  - `TOOL_CALL_ARGS` (CRITICAL — agent acted on the injection)
  - `RESPONSE_TEXT` (HIGH — agent obeyed instructions)
  - `THINKING` (MEDIUM — model processed but didn't act)
- `runner.RunnerConfig` — YAML-loadable agent configuration with provider,
  model, system prompt, trigger prompt, mock tools, max turns, timeout
- `runner.adapters.AgentAdapter` ABC + two concrete adapters:
  - **AnthropicAdapter** — real Claude tool-use via the Anthropic SDK
  - **MockAgentAdapter** — deterministic agent for tests and demos
- `runner/injection` module that orchestrates payload → agent → detection
  and emits one finding per canary surface, with the full trace persisted
  to the engagement artifact directory
- CLI: `agentsploit run injection --payload <file> --canary <AS-...> --agent
  <config.yaml>` with the same `--auth`/`--training` enforcement as `scan`
- Target types: `AGENT_ANTHROPIC`, `AGENT_OPENAI`, `AGENT_MOCK` + URI schemes
  `agent+anthropic://`, `agent+openai://`, `agent+mock://`
- `examples/agent-anthropic.yaml`, `examples/agent-mock.yaml`
- `docs/runner.md` with pipeline, severity, config, and operational hygiene

### Changed

- Added `anthropic>=0.45.0` as a runtime dependency

## [0.2.0] - 2026-05-18

### Added

- Streamable HTTP MCP transport (`mcp.client.streamable_http`)
- SSE MCP transport (`mcp.client.sse`)
- Authentication abstraction (`Credentials`): custom headers, bearer tokens (literal or from env var), TLS verification toggle, configurable timeout
- `Probe` base class for async HTTP-only checks (alongside the existing sync `Check`)
- Four new HTTP probes:
  - `http_tls_required` — flags non-loopback MCP served over plain HTTP
  - `http_info_disclosure` — flags Server / X-Powered-By / X-Runtime headers
  - `http_cors` — detects wildcard origin, origin reflection, and the wildcard-with-credentials specification violation
  - `http_auth_bypass` — when credentials are supplied, retries the `initialize` call without them and flags successes
- CLI flags on `scan mcp`: `--header/-H`, `--auth-bearer`, `--auth-bearer-env`, `--insecure`, `--timeout`
- Public helper `client.http_url_from_target()` for raw-HTTP probes
- Bundled vulnerable HTTP MCP server fixture (`tests/fixtures/vulnerable_http_mcp/server.py`) with deliberate CORS, header, auth, and plaintext-HTTP issues

### Changed

- `MCPScanner.__init__` now accepts `credentials: Credentials | None`
- `inventory()` and `open_session()` accept an optional `Credentials`
- `mcp.scanner` `supported_targets` now includes all three transport types

## [0.1.0] - 2026-05-17

Initial alpha release.

### Added

- Plugin-based module framework (`agentsploit.core`)
- Authorization model with YAML scope files, glob target matching, expiry enforcement, and training mode
- Engagement sessions with persistent finding logs and SARIF / JSON / Rich-console reporters
- CLI commands: `scan`, `generate`, `list-modules`, `init-auth`, `version`
- MCP scanner module with four checks: `tool_poisoning`, `tool_shadowing`, `prompt_disclosure`, `unsafe_tool_args`
- Indirect prompt injection generator with five techniques (`direct`, `role_confusion`, `delimiter`, `unicode_tag`, `tool_smuggling`) and six carriers (`text`, `markdown`, `html`, `pdf`, `email`, `ical`)
- Bundled vulnerable MCP server for safe self-testing
- Test suite (unit + integration)
- GitHub Actions CI (lint, type-check, test, coverage)
