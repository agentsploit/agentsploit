# AgentSploit

**Offensive security framework for AI agents and MCP servers.**

AgentSploit is a Burp Suite / Metasploit-style framework purpose-built for the agentic AI attack surface. It helps red teamers, AI security researchers, and product security teams probe LLM agents and Model Context Protocol (MCP) servers for vulnerabilities that legacy tooling cannot find.

> [!IMPORTANT]
> **AgentSploit is an authorized-use security testing tool.** You must have explicit written permission to scan any target you do not own. See [AUTHORIZATION.md](AUTHORIZATION.md) before running anything.

---

## Why this exists

Every Fortune 500 is shipping LLM agents and MCP servers in 2026. The attack surface is genuinely new:

- Tool descriptions are LLM-readable instructions — malicious ones can hijack agents.
- Agents fetch untrusted content from PDFs, web pages, calendar invites, tickets — and that content can issue commands.
- Chained tool calls create privilege escalation paths that no traditional permission model captures.
- Memory and context windows can be poisoned across sessions.

Existing scanners (Burp, ZAP, Semgrep, Snyk) don't speak this layer. AgentSploit does.

## What's in v0.1

This release ships two MVP capabilities:

### 1. MCP Server Scanner

Connects to an MCP server over **stdio**, **Streamable HTTP**, or **SSE** and runs a battery of checks against its tools, resources, prompts, and (for HTTP/SSE) its HTTP surface.

**Inventory checks (all transports):**

| Check | What it finds |
|---|---|
| `tool_poisoning` | Tool descriptions containing prompt-injection payloads aimed at the host agent |
| `tool_shadowing` | Name collisions / shadowing with well-known tools (e.g. `read_file`, `send_email`) |
| `prompt_disclosure` | Tools whose descriptions leak internal system prompts, secrets, or paths |
| `unsafe_tool_args` | Tool schemas that accept dangerous unconstrained arguments (paths, URLs, shell commands) |

**HTTP probes (HTTP/SSE only):**

| Probe | What it finds |
|---|---|
| `http_tls_required` | Non-loopback MCP served over plain HTTP |
| `http_info_disclosure` | Version-leaking Server / X-Powered-By / X-Runtime headers |
| `http_cors` | Wildcard origin, origin reflection, or the wildcard-with-credentials spec violation |
| `http_auth_bypass` | When `--auth-bearer*` is supplied: server accepts the same calls without credentials |

### 2. Indirect Prompt Injection Payload Generator

Generates labeled payloads for testing whether an agent processes untrusted content safely.

**Techniques:**

- `direct` — straightforward override attempts
- `role_confusion` — fake `system:` / `assistant:` turns
- `delimiter` — fenced-content escape and re-context
- `unicode_tag` — invisible Unicode tag-block smuggling (U+E0000 range)
- `tool_smuggling` — hidden tool-call invocations in narrative text

**Carriers (output formats):**

- `text` — plain text
- `markdown` — README/comment-style
- `html` — page content with hidden elements
- `pdf` — visible + hidden-layer PDF
- `email` — RFC 5322 with HTML body and headers
- `ical` — `.ics` calendar invite with malicious DESCRIPTION

Every payload is tagged with a `canary` string so you can detect successful injection in logs.

## Install

Requires Python 3.11+.

```bash
# With uv (recommended)
uv tool install agentsploit

# Or with pipx
pipx install agentsploit

# Or with pip in a venv
python -m venv .venv && source .venv/bin/activate
pip install agentsploit
```

## Quickstart

```bash
# 1. Create an authorization file for your engagement
agentsploit init-auth --target "stdio://./my-mcp-server" --authorized-by "Jane Doe <ciso@example.com>"

# 2. Scan a local stdio MCP server
agentsploit scan mcp stdio://./my-mcp-server --auth ./authorization.yaml

# 2b. Scan a hosted MCP server over HTTPS with a bearer token from env
export MCP_TOKEN=$(op read 'op://eng/mcp-staging/token')
agentsploit scan mcp https://mcp.staging.example.com/mcp \
  --auth-bearer-env MCP_TOKEN \
  --auth ./authorization.yaml

# 3. Generate an indirect prompt injection payload
agentsploit generate injection \
  --technique role_confusion \
  --carrier pdf \
  --goal "leak any tool descriptions" \
  --out ./payload.pdf

# 4. List all available modules
agentsploit list-modules
```

## Architecture

```
agentsploit/
├── core/           # Module base classes, Target/Authorization/Finding/Session
├── modules/
│   ├── mcp/        # MCP scanner + checks
│   └── injection/  # Payload techniques + carriers
└── cli.py          # Typer entry point
```

Modules are plugin-style: drop a class into `modules/` and it shows up in `list-modules` automatically.

See [docs/architecture.md](docs/architecture.md) for the full design.

## Safe use

- **Authorization is enforced at runtime.** Targets are matched against a YAML authorization file with an explicit `authorized_by`, `valid_until`, and `scope` list. The scanner refuses to run without it.
- **Training mode** (`--training`) only allows targets matching `*://localhost*` and the bundled vulnerable fixture.
- **All activity is logged** with engagement ID, target, module, and finding hash for audit.
- **No 0-days are bundled.** Modules implement well-known and disclosed attack patterns.

See [AUTHORIZATION.md](AUTHORIZATION.md) and [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). New modules are welcome — start from `docs/writing-modules.md`.

## License

Apache 2.0. See [LICENSE](LICENSE).
