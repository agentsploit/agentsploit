# Changelog

All notable changes to AgentSploit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
