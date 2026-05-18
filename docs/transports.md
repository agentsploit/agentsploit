# Transports

AgentSploit speaks three MCP transports as of v0.2: **stdio**, **HTTP** (Streamable), and **SSE**.

## Picking a URI scheme

| Scheme | Transport | When to use |
|---|---|---|
| `stdio://<command>` | Local subprocess over stdin/stdout | Local development MCP servers, testing the bundled fixture, anything you can run as a child process |
| `http://host:port[/path]` | Streamable HTTP | Default for hosted MCP servers (current spec) |
| `https://host:port[/path]` | Streamable HTTPS | Production hosted MCP servers (recommended) |
| `mcp+http://...` | Streamable HTTP | Same as plain `http://`, but explicitly opts into MCP semantics. Useful when the host also serves non-MCP routes |
| `mcp+https://...` | Streamable HTTPS | Explicit-scheme equivalent of `https://` |
| `sse://host:port/path` | Server-Sent Events | Older MCP transport. Still used by some clients/servers |
| `mcp+sse://host:port/path` | SSE | Explicit-scheme equivalent of `sse://` |

## Examples

```bash
# Local stdio
agentsploit scan mcp stdio://./my-server.py --training

# HTTP MCP, no auth (e.g. internal staging)
agentsploit scan mcp https://mcp.staging.example.com/mcp --auth ./auth.yaml

# HTTP MCP with bearer token from env var (recommended)
export STAGING_TOKEN=...
agentsploit scan mcp https://mcp.staging.example.com/mcp \
  --auth-bearer-env STAGING_TOKEN \
  --auth ./auth.yaml

# HTTP MCP with custom tenant header + skip TLS for an internal CA
agentsploit scan mcp https://mcp.internal.local/mcp \
  -H "X-Tenant: acme" \
  -H "X-Request-ID: scan-001" \
  --auth-bearer-env INTERNAL_TOKEN \
  --insecure \
  --auth ./auth.yaml

# SSE transport
agentsploit scan mcp sse://stream.example.com/sse --auth ./auth.yaml
```

## What runs for each transport

| Capability | stdio | HTTP | SSE |
|---|---|---|---|
| `tool_poisoning` | yes | yes | yes |
| `tool_shadowing` | yes | yes | yes |
| `prompt_disclosure` | yes | yes | yes |
| `unsafe_tool_args` | yes | yes | yes |
| `http_tls_required` | — | yes | yes |
| `http_info_disclosure` | — | yes | yes |
| `http_cors` | — | yes | yes |
| `http_auth_bypass` | — | yes (needs `--auth-bearer*`) | yes (needs `--auth-bearer*`) |

The four "inventory" checks are transport-agnostic — they run whenever the scanner can successfully enumerate the server. The HTTP probes only run for HTTP and SSE targets.

## Authorization vs authentication

Two unrelated concepts that share the word "auth":

- **Authorization** (`--auth ./authorization.yaml` or `--training`) defines which targets you are *permitted* to scan. Enforced at the CLI before any network or process I/O. See [AUTHORIZATION.md](../AUTHORIZATION.md).
- **Authentication** (`--auth-bearer`, `--auth-bearer-env`, `--header`) is how AgentSploit proves identity *to the target server*. See [authentication.md](authentication.md).

Authorization files do **not** contain authentication credentials. Keep them separate.
