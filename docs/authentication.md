# Authentication

How AgentSploit authenticates to an MCP server. This is separate from the engagement authorization file, which controls *which targets* you're allowed to touch - see [AUTHORIZATION.md](../AUTHORIZATION.md) and [transports.md](transports.md).

## CLI flags

All flags apply to the `scan mcp` command for HTTP/SSE targets. They have no effect on stdio.

| Flag | Purpose |
|---|---|
| `--auth-bearer <token>` | Send `Authorization: Bearer <token>` |
| `--auth-bearer-env <NAME>` | Read the token from environment variable `NAME` (recommended over literal) |
| `--header "Key: Value"` (or `-H`) | Add an arbitrary header. Repeatable. |
| `--insecure` | Skip TLS certificate verification (e.g. for internal CAs in testing) |
| `--timeout <seconds>` | HTTP read timeout. Default 30. |

## Patterns

### Bearer token from env

```bash
export STAGING_TOKEN=$(op read 'op://Engineering/MCP Staging/credential')
agentsploit scan mcp https://mcp.staging.example.com/mcp \
  --auth-bearer-env STAGING_TOKEN \
  --auth ./auth.yaml
```

### Custom headers (multi-tenant, request IDs, API keys)

```bash
agentsploit scan mcp https://mcp.example.com/mcp \
  -H "X-Api-Key: $API_KEY" \
  -H "X-Tenant: acme" \
  -H "X-Request-ID: rt-2026-q2-001" \
  --auth ./auth.yaml
```

### Internal CA / self-signed cert

```bash
agentsploit scan mcp https://mcp.internal.local/mcp \
  --auth-bearer-env INTERNAL_TOKEN \
  --insecure \
  --auth ./auth.yaml
```

`--insecure` is intended for testing internal infrastructure where you control the CA. Don't use it against the public internet.

## Auth and the `http_auth_bypass` probe

When you supply credentials via any of the above flags, AgentSploit will also retry the MCP `initialize` request *without* those credentials. If the unauthenticated request succeeds, you get an `http_auth_bypass` finding at CRITICAL severity.

If you don't supply credentials, the probe is skipped - there's no baseline to compare against, so "no auth required" might be the intended behaviour.

## What AgentSploit never does

- Reads credentials from your `authorization.yaml` (that file is for scope, not secrets)
- Logs the value of a bearer token (it's masked in evidence)
- Reuses credentials across targets in the same session

## Threat-modelling the credential surface

Credentials sit in three places during a scan:

1. **Process environment** when you use `--auth-bearer-env` - visible to anything that can read `/proc/<pid>/environ` (root, the same UID under most policies)
2. **Argv** when you use `--auth-bearer <literal>` - visible to anyone who can `ps`. Avoid in shared environments.
3. **httpx in-memory** - held for the duration of the scan, then dropped when the client exits

Prefer `--auth-bearer-env` over literal `--auth-bearer` for non-trivial environments.
