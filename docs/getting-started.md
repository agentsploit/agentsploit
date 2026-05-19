# Getting started

A 10-minute tour of AgentSploit. By the end you'll have run every major capability against the bundled fixtures without needing API keys, an authorization YAML, or a real target.

## Install

```bash
# Recommended - installs the `agentsploit` CLI globally without polluting your env
uv tool install agentsploit

# Or via pipx
pipx install agentsploit

# Or in a project venv
python -m venv .venv && source .venv/bin/activate
pip install agentsploit
```

Verify:

```bash
agentsploit version
# agentsploit 1.0.0
```

## Tour the pipeline (all against bundled fixtures, no API keys)

### 1. Scan a single MCP server

```bash
git clone https://github.com/desledishant10/agentsploit.git
cd agentsploit

agentsploit scan mcp \
  "stdio://$(pwd)/tests/fixtures/vulnerable_mcp/server.py" \
  --training
```

You'll see a Rich-formatted table of findings: tool-poisoning, tool-shadowing, prompt-disclosure, and unsafe-argument issues across the four bundled tools.

### 2. Generate a payload

```bash
agentsploit generate injection \
  --technique unicode_tag \
  --carrier pdf \
  --goal "leak the system prompt" \
  --out /tmp/payload.pdf
```

The PDF looks like a routine compliance review document. The actual instruction is invisible (Unicode tag-block encoded) but tokenizes inside most LLMs.

### 3. Drive the payload through a (mock) agent

```bash
agentsploit run injection \
  --payload /tmp/payload.pdf \
  --canary $(grep -o 'AS-[A-F0-9]*' <(agentsploit generate injection --carrier text -g x 2>&1) | head -1) \
  --agent ./examples/agent-mock.yaml \
  --training
```

Easier: regenerate with an explicit canary:

```bash
agentsploit generate injection -t unicode_tag -c pdf -g x \
  --canary AS-DEMOCANARYAB --out /tmp/payload.pdf
agentsploit run injection \
  --payload /tmp/payload.pdf --canary AS-DEMOCANARYAB \
  --agent ./examples/agent-mock.yaml --training
```

The mock agent reads the PDF, sees the hidden instruction, and emits the canary - `HIGH` confirmed prompt-injection finding.

### 4. Map cross-server permission graph

```bash
agentsploit map build \
  --targets ./examples/map-targets.yaml \
  --training
```

You'll get an aggregate graph + one finding per source→sink path. Export for visualisation:

```bash
GRAPH=$(ls -t engagements/training/sess-*/permission_graph.json | head -1)
agentsploit map export --graph "$GRAPH" --format mermaid > graph.md
# paste graph.md contents into a GitHub PR to render the graph inline
```

### 5. Verify a specific path

```bash
agentsploit verify path \
  --graph "$GRAPH" \
  --from read_file --to run_shell \
  --training
```

`CRITICAL` confirmed exploitable path - the canary surfaces in the sink tool's call arguments.

### 6. Batch-verify every path

```bash
agentsploit verify all-paths \
  --graph "$GRAPH" \
  --parallel 4 \
  --training
```

One command, every (source, sink) pair tested. Aggregate summary with the confirmation rate.

### 7. Fuzz techniques across a path

```bash
agentsploit verify fuzz-path \
  --graph "$GRAPH" \
  --from read_file --to run_shell \
  --training
```

Tries all 5 targeted-injection envelopes (role_confusion, direct, delimiter, unicode_tag, tool_smuggling) and reports which one landed first.

### 8. Memory poisoning

```bash
agentsploit poison verify \
  --sink-tool send_email --sink-arg body \
  --sink-privilege egress \
  --training
```

Two-phase attack: attacker plants a poisoned note in shared storage, victim agent reads it later and is steered into the sink. `CRITICAL` if confirmed.

## Going from fixtures to real targets

Once you've completed the tour, scaffold a real engagement directory in one command:

```bash
agentsploit init engagement-2026-q2/ \
  --authorized-by "Jane <jane@example.com>" \
  --engagement-id rt-2026-q2-mcp-audit \
  --valid-days 30
```

This creates a complete starter kit:

| File | Purpose |
|---|---|
| `authorization.yaml` | Scope file enforced at the CLI boundary on every run |
| `agent-anthropic.yaml` | Claude config (default) |
| `agent-openai.yaml` | OpenAI Chat Completions config |
| `agent-http.yaml` | Custom HTTP agent config |
| `map-targets.yaml` | List of MCP servers to enumerate together |
| `README.md` | Engagement-specific workflow cheatsheet |
| `.gitignore` | Excludes the `engagements/` output dir |

Edit `authorization.yaml` to add real target URIs, set the API key for whichever provider you'll use, then run any command from the tour above with `--auth ./authorization.yaml --agent ./agent-<provider>.yaml` instead of `--training`.

> If you only want to generate the authorization file (not the whole engagement directory), use the lower-level `agentsploit init-auth` instead. See [AUTHORIZATION.md](../AUTHORIZATION.md).

## Output formats

Every command supports `--format json` or `--format sarif --out findings.sarif`:

- **JSON**: lossless export of every finding for tooling integration
- **SARIF 2.1.0**: GitHub Code Scanning, Defender for Cloud, etc. See [docs/sarif.md](sarif.md).

## What to read next

| You want to… | Read |
|---|---|
| Understand the architecture | [docs/architecture.md](architecture.md) |
| Write a new check or module | [docs/writing-modules.md](writing-modules.md) |
| Configure agent/auth credentials | [docs/authentication.md](authentication.md) |
| Choose a transport for an MCP target | [docs/transports.md](transports.md) |
| Understand the permission graph mapper | [docs/mapper.md](mapper.md) |
| Run the live agent runner / verifier | [docs/runner.md](runner.md), [docs/verifier.md](verifier.md) |
| Run memory-poisoning attacks | [docs/poisoning.md](poisoning.md) |
| Upload findings to GitHub Code Scanning | [docs/sarif.md](sarif.md) |
| Look up a specific CLI flag | [docs/cli-reference.md](cli-reference.md) |
