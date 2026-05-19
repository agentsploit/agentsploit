# CLI reference

Complete CLI surface as of v1.0.0. For interactive help, every subcommand accepts `--help`.

## Top-level

```
agentsploit [--verbose|-v] <subcommand> ...
```

| Subcommand | Purpose |
|---|---|
| `version` | Print the AgentSploit version |
| `list-modules` | List every registered module |
| `init-auth` | Generate an authorization YAML for an engagement |
| `scan mcp` | Scan an MCP server (stdio/HTTP/SSE) |
| `generate injection` | Generate an indirect prompt-injection payload |
| `run injection` | Drive a generated payload through a live agent |
| `map build` | Build the cross-server permission graph |
| `map export` | Export a built graph to DOT/Mermaid/JSON |
| `verify path` | Verify a single mapper-inferred path against a live agent |
| `verify all-paths` | Batch-verify every path in a graph |
| `verify fuzz-path` | Try multiple injection techniques against one path |
| `poison verify` | Two-phase memory-poisoning attack against an agent |

---

## Global flags

| Flag | Where | Effect |
|---|---|---|
| `--verbose`, `-v` | top-level | Verbose structured logging to stderr |
| `--training` | scan / run / map / verify / poison | Use restricted training-mode auth (bundled fixtures + localhost only) - no `--auth` file required |
| `--auth <path>` | scan / run / map / verify / poison | Authorization YAML defining engagement scope |
| `--format`, `-f` | scan / run / map build / verify / poison | `rich` \| `json` \| `sarif` |
| `--out`, `-o` | (with `--format json|sarif`) | Required output path |

---

## `init-auth`

Generate an engagement-scoped authorization file.

```bash
agentsploit init-auth \
  --target "stdio://./my-mcp-server" \
  --target "https://mcp.staging.example.com/mcp" \
  --authorized-by "Jane Doe <ciso@example.com>" \
  --engagement-id "rt-2026-q2-mcp-audit" \
  --valid-days 30 \
  --scope-notes "Q2 red-team engagement, ticket SEC-1234" \
  --forbidden "*production*" \
  --out ./authorization.yaml
```

---

## `scan mcp`

```bash
agentsploit scan mcp <TARGET-URI> \
  [--auth <yaml>] [--training] \
  [--check <name>] ... \
  [--header "Key: Value"] ... \
  [--auth-bearer <token>] [--auth-bearer-env <NAME>] \
  [--insecure] [--timeout <seconds>] \
  [--format <fmt>] [--out <path>]
```

URI schemes: `stdio://`, `http://`, `https://`, `mcp+http://`, `mcp+https://`, `sse://`, `mcp+sse://`.

---

## `generate injection`

```bash
agentsploit generate injection \
  --technique <direct|role_confusion|delimiter|unicode_tag|tool_smuggling> \
  --carrier   <text|markdown|html|pdf|email|ical> \
  --goal      "leak the system prompt" \
  [--canary AS-XXXXXX] \
  [--cover-text "Quarterly compliance review."] \
  --out ./payload.<ext>
```

---

## `run injection`

```bash
agentsploit run injection \
  --payload ./payload.pdf \
  --canary AS-XXXXXX \
  --agent ./agent.yaml \
  [--auth <yaml>] [--training] \
  [--format <fmt>] [--out <path>]
```

---

## `map build`

```bash
agentsploit map build \
  --targets ./map-targets.yaml \
  [--auth <yaml>] [--training] \
  [--header "Key: Value"] ... \
  [--auth-bearer-env NAME] [--insecure] [--timeout 30] \
  [--max-length 4] \
  [--min-privilege read|internal_action|egress|mutation|execution] \
  [--format <fmt>] [--out <path>]
```

## `map export`

```bash
agentsploit map export \
  --graph ./permission_graph.json \
  --format dot|mermaid|json \
  [--out ./graph.dot]
```

---

## `verify path`

```bash
agentsploit verify path \
  --graph ./permission_graph.json \
  --from <tool-name> --to <tool-name> \
  [--agent ./agent.yaml] [--training] \
  [--sink-arg <name>] \
  [--format <fmt>] [--out <path>]
```

## `verify all-paths`

```bash
agentsploit verify all-paths \
  --graph ./permission_graph.json \
  [--agent ./agent.yaml] [--training] \
  [--min-privilege egress] [--max-length 4] [--max-paths 20] \
  [--parallel 2] \
  [--fuzz] [--techniques role_confusion,delimiter,unicode_tag] \
  [--format <fmt>] [--out <path>]
```

## `verify fuzz-path`

```bash
agentsploit verify fuzz-path \
  --graph ./permission_graph.json \
  --from <tool-name> --to <tool-name> \
  [--agent ./agent.yaml] [--training] \
  [--techniques role_confusion,direct,delimiter,unicode_tag,tool_smuggling] \
  [--sink-arg <name>] [--no-early-stop] \
  [--format <fmt>] [--out <path>]
```

---

## `poison verify`

```bash
agentsploit poison verify \
  --sink-tool <tool-name> \
  [--sink-arg body] \
  [--sink-privilege egress|mutation|execution|internal_action] \
  [--agent ./agent.yaml] [--training] \
  [--technique role_confusion|direct|delimiter|unicode_tag|tool_smuggling] \
  [--store-key <key>] [--canary <AS-...>] \
  [--format <fmt>] [--out <path>]
```

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No CRITICAL/HIGH findings |
| 1 | At least one CRITICAL/HIGH finding (or operational error) |
| 2 | Authorization denied - target out of scope |

Use exit codes to gate CI/CD pipelines.
