# Changelog

All notable changes to AgentSploit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
