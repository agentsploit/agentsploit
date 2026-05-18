# Changelog

All notable changes to AgentSploit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
