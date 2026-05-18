# Changelog

All notable changes to AgentSploit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
