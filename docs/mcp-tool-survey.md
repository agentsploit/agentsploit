# What 800 tools across 13 MCP servers say about the agentic attack surface

> Method note. Numbers are from a survey of 13 popular Python MCP servers (plus
> the reference-servers repo), run with the reproducible harness in
> [`examples/mcp-survey/`](../examples/mcp-survey). Everything below is from
> **public source code** — no server was connected to or executed. The
> capability labels are heuristic (see caveats); this writeup deliberately does
> **not** call anything a vulnerability.

MCP has a few hundred open-source servers now, each handing an agent a set of
tools. I got curious about the *shape* of that surface — not "is server X
exploitable" but "what does the average tool actually let an agent do, and how
often do the dangerous ingredients sit next to each other?" So I statically
extracted the tool definitions from the **top Python MCP servers by GitHub
stars** and ran [AgentSploit](https://github.com/agentsploit/agentsploit)'s
inventory checks plus a source/sink classifier over them. **806 tools, 13
servers.** Reproducible harness at the bottom.

## Finding 1: tool descriptions are already full of instructions to the model

Tool descriptions are LLM-readable text, and the "tool poisoning" attack class
assumes an attacker can smuggle instructions into them. What the survey shows is
that **legitimate servers already write descriptions as imperative instructions
to the agent.** Real, entirely benign examples from AWS's servers:

> "Before using this tool, provide a 1-3 sentence explanation…"
> "MANDATORY: Explain any data in clear, human-readable format."
> "🔴 PREREQUISITE: Before calling this tool, you MUST first call `…`"

These are good-faith usage guidelines. But they're indistinguishable, at the
text level, from an injected `IGNORE ALL PREVIOUS INSTRUCTIONS`. A pattern-based
scanner (including AgentSploit's) flags both — I hand-reviewed every hit, and in
these popular servers they were **all benign**. That's the actual finding: there
is no clean signal separating a benign imperative description from a malicious
one, because the ecosystem uses the injection channel as a feature.

## Finding 2: sources and sinks live in the same context, everywhere

I labeled each tool by capability:

- **source** — looks like it ingests external/untrusted content (takes a
  `url`/`uri`/`path`/`document` arg, or is a `fetch`/`read`/`search`/`crawl`).
- **sink** — looks like a high-impact action (an `exec`/`run`/`query`/`write`/
  `send`/`delete`, or takes a `command`/`query`/`code` arg).

Across 806 tools:

| | count |
|---|---|
| untrusted-content **sources** | 98 |
| high-impact **sinks** | 246 |
| tools that are **both** (ingest *and* act) | **24** |
| servers exposing >=1 source **and** >=1 sink in one context | **6 / 13** |

The 24 "both" tools are the sharpest edge: a single tool that will pull in a
URL/file *and* run a query or command is a one-call source→sink bridge if the
content it pulls is attacker-controlled — e.g. `search_table(url)` that also
takes a `query`, `create_remote_issue_link(url)`, or `upload_attachment(file_path)`.
And 6 of 13 servers put sources and sinks in the same agent context with nothing
marking one as untrusted or the other as dangerous. (The harness prints the full
bridge list; hand-review it — a few, like an OAuth `CreateTokenWithIAM`, are
weak matches.)

## Finding 3: the sinks are wide open

Of the sink tools, dozens take a raw string with **no `enum`, `pattern`, or
`format` constraint** — `executeQuery(query)`, `run_opencypher_query(query)`,
`read_documentation(url)`. That's by design; it's also exactly the unconstrained
sink that turns "the agent read a poisoned page" into "the agent ran attacker
SQL."

## This is not a list of vulnerabilities

None of the above is a bug in these servers. A source→sink chain only becomes an
exploit when (a) untrusted input actually reaches a source and (b) the agent
bridges it to a sink — both are properties of how the server is *deployed and
composed*, not of the code. Confirming a real chain needs a live agent (that's
what AgentSploit's permission-graph mapper and canary runner are for; out of
scope for a static survey).

## What actually helps

- Treat third-party tool descriptions as untrusted input to your host prompt;
  render them in an isolated context.
- Constrain sink args (`enum`/`pattern`/`format`) instead of raw strings.
- Don't co-locate untrusted-content sources with high-impact sinks in one
  agent's tool set without an isolation/confirmation boundary.

## Reproduce it

```bash
git clone https://github.com/agentsploit/agentsploit && cd agentsploit
pip install -e .
cd examples/mcp-survey            # edit servers.yaml to pick targets
python survey.py collect          # static extraction from public source
python survey.py scan             # agentsploit inventory checks
python survey.py aggregate        # findings table
python survey.py surface          # source/sink classification
```

## Caveats

- Labels are heuristic: sources are limited to external-content signals
  (`url`/`uri`/`path`/`document` args, `fetch`/`crawl`/`scrape` names), matching
  is token-based, but it's still a capability guess, not a data-flow. Counts are
  "could plausibly be"; the robust part is the *shape* — most servers mix
  ingestion and action, and 24 tools do both in one call.
- Static extraction misses Pydantic-schema args, cross-file enums, custom tool
  frameworks (e.g. serena extracted 0), and every non-Python server, so tool
  counts are a lower bound.
- Pattern-based checks flag benign text; I hand-reviewed, and this post reports
  the reviewed conclusion, not the raw count.

Tool is Apache-2.0: https://github.com/agentsploit/agentsploit — check ideas and
PRs welcome.
