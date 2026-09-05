# MCP survey harness

Reproducible, **execution-free** survey of published open-source MCP tool
definitions, powering the "I scanned N open-source MCP servers" disclosure post.

It clones public repos, statically extracts each server's tool definitions from
Python source (via `ast` — nothing is run), builds an AgentSploit
`MCPInventory`, and runs AgentSploit's **real** inventory checks over it.

## Safety / ethics

- Reads **public source code only**. Never connects to a third-party host, never
  executes a scanned server, never sends traffic anywhere.
- Findings are *candidates from published code*, not confirmations that a live
  agent acts on them.
- Before naming any project in a writeup, open a private advisory / email the
  maintainer and give them time. Prefer aggregate/anonymized numbers otherwise.

## Usage

Run with the AgentSploit venv so `import agentsploit` resolves:

```bash
PY=~/Tools/agentsploit/.venv/bin/python

$PY survey.py selftest      # validate the pipeline on the bundled fixture
$PY survey.py collect       # clone repos in servers.yaml -> manifests/*.json
$PY survey.py scan          # run agentsploit checks -> out/findings*.json
$PY survey.py aggregate     # roll up -> out/aggregate.md (paste into the post)
$PY survey.py surface       # source/sink capability map -> out/surface.md
```

`aggregate` reports the raw check findings (hand-review — many are benign).
`surface` is the stronger, honest cut: it labels each tool as an untrusted-
content **source** and/or a high-impact **sink**, and counts how many servers
put both in one context (a *potential* source->sink chain — not a confirmed
data-flow). This is heuristic capability classification, not proof.

Edit `servers.yaml` to choose targets. Start with a handful, **hand-review the
manifests in `manifests/`** (spot-check that names/descriptions look right),
then widen to the reproducible set you'll name in the writeup. Re-clone with
`collect --refresh`.

Outputs:
- `manifests/<server>.json` — extracted tools + an `extraction` block (tool
  count, method mix, how many schemas were partial, parse errors).
- `out/findings/<server>.json` and `out/findings.json` — per-check findings.
- `out/aggregate.md` — the numbers + table for the disclosure post.

## What it detects

The four transport-agnostic inventory checks, straight from AgentSploit:
`tool_poisoning`, `tool_shadowing`, `unsafe_tool_args`, `prompt_disclosure`.
(The HTTP probes — CORS, auth-bypass, TLS, header disclosure — need a live
connection and are intentionally out of scope here.)

## Extraction coverage & limitations

Static extraction handles the two dominant Python patterns:

- `Tool(name=..., description=..., inputSchema={...})` call literals, including
  `name`/`description` given as members of a same-file `str`/`Enum` (e.g.
  `GitTools.STATUS`), which are resolved to their string values.
- `@mcp.tool()` / `@server.tool()` decorated functions (name from the function
  or a `name=` kwarg; description from a `description=` kwarg or the docstring;
  a rough `inputSchema` inferred from annotated params).

Known gaps — **these bias counts DOWNWARD, so treat results as a lower bound:**

- **Pydantic schemas** (`inputSchema=SomeModel.model_json_schema()`) can't be
  resolved statically, so such tools carry no schema and `unsafe_tool_args`
  won't fire on them (`schema_partial: true` in the manifest flags this). Their
  name/description still feed the other three checks.
- **Enums defined in another file** aren't resolved (same-file only).
- **Non-Python servers** (TypeScript, Go, …) are not extracted at all.
- Checks are **pattern-based**: they find known classes, and some
  `tool_poisoning` hits are verbose-but-benign. Hand-review before publishing.

### Want authoritative schemas / full coverage for a given server?

Run AgentSploit live against a **locally-launched** copy (it connects, calls
`list_tools()`, and gets fully-resolved schemas — no static guessing):

```bash
# from a local checkout you trust, in an isolated env
agentsploit scan mcp stdio://./path/to/server --auth ./authorization.yaml -f json -o live.json
```

That executes the server, so only do it for code you've reviewed, ideally in a
sandbox/VM. This harness deliberately avoids that to stay execution-free.
