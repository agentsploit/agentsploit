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

### 3. Live Agent Runner (v0.3)

Takes a generated payload + an agent config and drives the payload through a real LLM. If the canary surfaces in the agent's response, tool calls, or thinking trace, the injection is **confirmed exploitable** — a CRITICAL/HIGH finding with the full trace persisted for audit.

| Surface | Severity | Meaning |
|---|---|---|
| `canary_tool_call_args` | CRITICAL | Agent forwarded the canary into a tool — confirmed exfil capability |
| `canary_response_text` | HIGH | Agent quoted the canary back — confirmed instruction-following |
| `canary_thinking` | MEDIUM | Canary appeared in extended-thinking but the agent didn't act on it |
| `no_surface` | INFO | Payload drove cleanly through but didn't land |

**Adapters in v0.3:** `anthropic` (real Claude tool-use), `mock` (deterministic, for tests). OpenAI + generic HTTP land in v0.4. See [docs/runner.md](docs/runner.md).

### 4. Permission Graph Mapper (v0.4)

Enumerates tools across multiple MCP servers, classifies each by privilege (source / pivot / sink), infers data-flow edges, and finds attack paths from low-trust sources to high-impact sinks. BloodHound for tool chains.

```bash
agentsploit map build --targets ./examples/map-targets.yaml --auth ./auth.yaml
agentsploit map export --graph ./engagements/<id>/<sid>/permission_graph.json -f mermaid -o graph.md
```

| Sink privilege | Severity |
|---|---|
| `EXECUTION` (`run_command`, `eval`) | CRITICAL |
| `MUTATION` (`git_push`, `delete_*`) | HIGH |
| `EGRESS` (`send_email`, `webhook`) | HIGH |

A path finding is a *testable hypothesis* — pair it with the v0.5 verifier to confirm exploitability end-to-end. See [docs/mapper.md](docs/mapper.md).

### 5. Path Verifier (v0.5)

Closes the loop on the mapper. Take any mapper-inferred path, drive a path-targeted payload through a real or mock agent, and prove whether the chain actually completes.

```bash
agentsploit verify path \
  --graph ./engagements/<id>/<sid>/permission_graph.json \
  --from read_file --to send_email \
  --training         # or --agent ./agent-anthropic.yaml --auth ./auth.yaml
```

| Outcome | Meaning | Severity |
|---|---|---|
| `CONFIRMED` | Sink tool was called with the canary in its arguments | Tied to sink privilege (EXEC → CRITICAL) |
| `PARTIAL` | Sink reached or canary surfaced elsewhere, but chain incomplete | HIGH |
| `FAILED` | No canary surface anywhere | INFO |

A CONFIRMED finding moves a mapper hypothesis from "plausible attack path" to "proven exploit." See [docs/verifier.md](docs/verifier.md).

### 6. Batch Path Verification (v0.6)

Drive the verifier across every path in a graph in one command — typical workflow is to triage against the cheap mock agent first, then re-run only the confirmations against the real model.

```bash
# Cheap triage pass (free, instant)
agentsploit verify all-paths --graph ./.../permission_graph.json --training

# Real-model pass on the same graph
agentsploit verify all-paths --graph ./.../permission_graph.json \
  --agent ./agent-anthropic.yaml --auth ./auth.yaml \
  --parallel 3 --max-paths 20
```

Deduplicates by `(source, sink)` pair, parallelises with rate-limit-aware concurrency, isolates per-path errors, and emits an aggregate `batch_summary` finding with the confirmation-rate percentage. See [docs/verifier.md](docs/verifier.md#batch-verification-verify-all-paths-v06).

### 7. Technique Fuzzing (v0.7)

The default verifier uses one injection envelope (`role_confusion`). v0.7 adds four more — `direct`, `delimiter`, `unicode_tag`, `tool_smuggling` — and a fuzzer that tries them in sequence until one lands. Knowing *which* envelope wins tells defenders what their injection filter missed.

```bash
# Single-path fuzz
agentsploit verify fuzz-path --graph ./.../permission_graph.json \
  --from read_file --to send_email --training

# Batch fuzz — every path × every technique, with early termination per path
agentsploit verify all-paths --graph ./.../permission_graph.json \
  --fuzz --techniques role_confusion,delimiter,unicode_tag \
  --parallel 3 --training
```

| Technique | Defender takeaway when this lands |
|---|---|
| `role_confusion` | Chat-template filter doesn't catch fake `<system>` turns |
| `delimiter` | Untrusted content boundaries aren't enforced |
| `unicode_tag` | Defence strips printable ASCII but not U+E0000 tag block |
| `tool_smuggling` | Agent runtime parses JSON tool-call syntax out of narrative text |
| `direct` | No prompt-injection defence in place at all |

See [docs/verifier.md](docs/verifier.md#technique-fuzzing-v07).

### 8. Memory Poisoning (v0.8)

The first multi-phase attack module. Attacker plants a crafted note in shared agent storage; a separate victim agent run retrieves the note and is steered into invoking a sink tool with the attacker's canary. The remediation pattern this catches: agents that treat retrieved storage content as instructions, not data.

```bash
# Verify a memory-poisoning attack against the mock agent (free, instant)
agentsploit poison verify \
  --sink-tool send_email --sink-arg body \
  --sink-privilege egress \
  --training

# Against real Claude
agentsploit poison verify \
  --sink-tool send_email --sink-arg body \
  --agent ./agent-anthropic.yaml --auth ./auth.yaml
```

| Outcome | Meaning | Severity |
|---|---|---|
| `CONFIRMED` | Victim called sink with canary in args | Tied to sink privilege (EXEC → CRITICAL) |
| `PARTIAL` | Note retrieved but canary didn't surface in sink | HIGH |
| `NOT_RETRIEVED` | Note stored but victim never read it | INFO |
| `NOT_STORED` | Attacker write failed | INFO |

See [docs/poisoning.md](docs/poisoning.md).

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
