# Authorization & Safe Use

AgentSploit is an offensive security tool. Running it against systems you do not own or do not have written authorization to test may violate laws including the U.S. Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent statutes worldwide.

This document describes the authorization model the tool enforces, and your obligations as an operator.

## The authorization file

Every `scan` invocation requires an authorization YAML. Example:

```yaml
# authorization.yaml
authorized_by: "Jane Doe <ciso@example.com>"
authorized_at: "2026-05-17T10:00:00Z"
valid_until: "2026-06-17T23:59:59Z"

engagement_id: "rt-2026-q2-mcp-audit"
scope_notes: |
  Authorized red team engagement against internal MCP servers
  documented in ticket SEC-1234. No production data exfiltration.

targets:
  - "stdio://./internal-mcp-server"
  - "http://mcp.staging.internal.example.com:*"
  - "http://localhost:*"

forbidden:
  - "*production*"
  - "*prod.example.com*"
```

### How matching works

- `targets` is a list of glob patterns. The target URI must match at least one.
- `forbidden` is checked first. If the target URI matches any pattern, the scan is refused even if it also matches `targets`.
- `valid_until` is enforced. Expired authorization is refused.
- Patterns use `fnmatch` semantics (`*`, `?`, `[seq]`).

### Generating an authorization file

```bash
agentsploit init-auth \
  --target "stdio://./my-mcp-server" \
  --authorized-by "Jane Doe <ciso@example.com>" \
  --engagement-id "rt-2026-q2-mcp-audit" \
  --valid-days 30 \
  --out ./authorization.yaml
```

## Training mode

For learning AgentSploit without an engagement:

```bash
agentsploit scan mcp stdio://./tests/fixtures/vulnerable_mcp/server.py --training
```

`--training` accepts the bundled vulnerable fixture and any `localhost` target only. No authorization file required.

## Operator obligations

By using AgentSploit you agree to:

1. **Only scan targets you own or have explicit, time-bounded, written authorization to test.** Verbal permission is not sufficient.
2. **Keep the authorization file with the engagement records.** AgentSploit writes its hash into every finding for traceability.
3. **Do not bypass the authorization check.** Modifying the source to skip the check is a license violation.
4. **Disclose findings responsibly.** If you discover a vulnerability in a third-party MCP server during authorized testing, follow that vendor's coordinated disclosure policy.
5. **Do not use AgentSploit for harassment, fraud, unauthorized access, or any criminal purpose.**

## Reporting misuse

If you become aware of AgentSploit being used outside its intended purpose, report it to the project maintainers via the channel in [SECURITY.md](SECURITY.md).

## Legal disclaimer

AgentSploit is provided "AS IS" under the Apache 2.0 license. The authors and contributors disclaim all warranties and accept no liability for misuse. Operators are solely responsible for compliance with applicable laws.
