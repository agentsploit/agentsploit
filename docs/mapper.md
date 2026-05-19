# Permission graph mapper

The mapper enumerates tools across multiple MCP servers, classifies each by privilege, and finds attack paths from low-trust **sources** to high-impact **sinks**. Think BloodHound, but for the cross-server tool chain that an agent with access to several MCP servers can compose.

## Concepts

### Node classification

Every tool is one of:

| Class | What it does | Examples |
|---|---|---|
| **source** | Pulls untrusted content (entry point for injection) | `read_email`, `fetch_url`, `read_file`, `search_web` |
| **pivot** | Transforms or stores data within trust boundary | `summarize`, `cache_*`, `format_*` |
| **sink** | Externally-visible action (the goal of an attack) | `send_email`, `git_push`, `run_command` |
| **unknown** | Could not classify with high confidence | (rare) |

### Sink privilege

When a tool is a sink, the mapper also assigns a privilege class - this drives finding severity:

| Privilege | Severity | Examples |
|---|---|---|
| `EXECUTION` | CRITICAL | `run_command`, `eval`, `exec`, `shell` |
| `MUTATION` | HIGH | `delete_*`, `git_push`, `write_file`, `deploy` |
| `EGRESS` | HIGH | `send_email`, `webhook`, `post_*`, `transfer_funds` |
| `INTERNAL_ACTION` | MEDIUM | (other non-read sinks) |
| `READ` | LOW | (sources) |

### Edges

The mapper infers an edge `A → B` when:

- `A`'s description mentions one of `B`'s input argument names (strongest signal)
- `A` and `B` share "pivot" tokens in their descriptions (`url`, `path`, `email`, `content`, …)
- `A` is a source and `B` is a sink (baseline relay-path signal)

MCP doesn't define output schemas, so edge inference is heuristic - operators can override classifications when wrong.

### Paths

A path is a sequence `source → 0+ pivots → sink`. The mapper reports every simple path up to `--max-length` hops whose sink privilege is ≥ `--min-privilege`. Paths are sorted by **severity score** (sink privilege × constant − path length): higher-impact sinks closer to the source rank first.

## CLI

```bash
# 1. Build the graph and report risky paths
agentsploit map build \
  --targets ./examples/map-targets.yaml \
  --auth ./authorization.yaml

# 2. Export the persisted graph for visualization
agentsploit map export \
  --graph ./engagements/<id>/<session>/permission_graph.json \
  --format mermaid \
  --out ./graph.md

# 3. Render with graphviz
agentsploit map export \
  --graph ./engagements/<id>/<session>/permission_graph.json \
  --format dot \
  --out ./graph.dot
dot -Tsvg ./graph.dot -o ./graph.svg
```

## Map config (targets YAML)

```yaml
targets:
  - "stdio://./servers/email-mcp.py"
  - "stdio://./servers/shell-mcp.py"
  - "https://mcp.staging.example.com/mcp"
```

The map config only lists URIs. Authentication for HTTP/SSE targets is supplied via the same `--header`/`--auth-bearer-env`/`--insecure` flags as `scan mcp` - one credential set applies to every target in the run.

## Pairing with the runner

The mapper's output is a *hypothesis space*: "here are the paths an attacker could plausibly chain." Use the runner to **verify** any path:

1. Note the source tool of an interesting path (e.g. `read_email`)
2. Configure a runner with that source's behaviour as the payload-bearing mock tool
3. `agentsploit run injection` against an agent that has both ends of the chain
4. If the canary surfaces in a tool call to the *sink*, the path is real

A confirmed path moves the finding from "inferred" to "exploitable" - same severity scale as the v0.3 runner findings.

## Operator overrides

The classifier is heuristic. When it gets a tool wrong, the persisted `permission_graph.json` is editable - just change the `classification` and `privilege` fields and re-run `map export` and `map query`. We plan to add a YAML override file in v0.5.

## What the mapper is not

- **Not exhaustive.** It only reasons about edges between tools you scan. If your agent also has built-in tools (Claude's `bash`, OpenAI's `code_interpreter`, etc.) the mapper won't see them.
- **Not a proof.** A path is a *hypothesis* an attacker could plausibly exploit. Confirm with the runner before reporting externally.
- **Not real-time.** The graph is a snapshot. Re-run after the target's tool registry changes.
