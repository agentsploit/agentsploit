# SARIF integration

AgentSploit emits [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) — the Static Analysis Results Interchange Format — for every command that produces findings. SARIF is the industry-standard format consumed by GitHub Code Scanning, Microsoft Defender for Cloud, Sonatype, and most enterprise findings-management platforms.

> v1.0 guarantee: every release's SARIF output validates clean against the official 2.1.0 JSON Schema. The check is enforced in CI via `tests/integration/test_sarif_schema.py`.

## Producing SARIF

Add `--format sarif --out <path>` to any command:

```bash
agentsploit scan mcp <target> --auth ./auth.yaml \
  --format sarif --out scan.sarif

agentsploit map build --targets ./targets.yaml --auth ./auth.yaml \
  --format sarif --out map.sarif

agentsploit verify all-paths --graph ./graph.json --auth ./auth.yaml \
  --format sarif --out verify.sarif
```

## What's in the SARIF

| SARIF field | AgentSploit source |
|---|---|
| `runs[0].tool.driver.name` | Always `"agentsploit"` |
| `runs[0].tool.driver.informationUri` | https://github.com/agentsploit/agentsploit |
| `runs[0].tool.driver.rules[]` | One per unique `(module, check)` pair |
| `rule.id` | `<module>/<check>` (e.g. `mcp/scanner/tool_poisoning`) |
| `rule.shortDescription.text` | Finding title |
| `rule.fullDescription.text` | Finding description |
| `rule.helpUri` | First reference URL on the finding (OWASP LLM-Top-10 link, CVE, blog post) |
| `rule.defaultConfiguration.level` | SARIF level — see severity mapping below |
| `runs[0].results[]` | One per finding |
| `result.ruleId` | Same as above |
| `result.message.text` | Finding description |
| `result.level` | SARIF level for this specific finding |
| `result.partialFingerprints.primary` | Stable dedup hash (see below) |
| `result.properties.target` | Target URI |
| `result.properties.severity` | AgentSploit severity label (info/low/medium/high/critical) |
| `result.properties.tags` | Finding tags (module name, technique, category, …) |
| `result.properties.fingerprint` | Same as `partialFingerprints.primary` |
| `runs[0].properties.engagement_id` | From the authorization YAML |
| `runs[0].properties.session_id` | Per-invocation session ID |
| `runs[0].properties.auth_hash` | SHA-256 of the authorization YAML — audit trail |

## Severity mapping

SARIF defines four levels: `none`, `note`, `warning`, `error`. AgentSploit maps its five-level severity scale:

| AgentSploit severity | SARIF level | Typical example |
|---|---|---|
| `CRITICAL` | `error` | Confirmed exploitable execution sink |
| `HIGH` | `error` | Confirmed egress, unauth-bypass on production |
| `MEDIUM` | `warning` | CORS wildcard, tool shadowing |
| `LOW` | `note` | Verbose Server header, absolute-path disclosure |
| `INFO` | `note` | Inventory + transport diagnostics |

## Stable fingerprints

Every finding has a deterministic fingerprint derived from `(module, check, target, title)`. SARIF consumers use this for **deduplication across runs** — if the same finding reappears in tomorrow's scan, GitHub Code Scanning won't open a new alert.

```python
# from src/agentsploit/core/finding.py
def fingerprint(self) -> str:
    key = f"{self.module}|{self.check}|{self.target}|{self.title}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]
```

This is exposed in SARIF as both `partialFingerprints.primary` and `properties.fingerprint`.

## Uploading to GitHub Code Scanning

```yaml
# .github/workflows/agentsploit.yml
name: AgentSploit scan

on:
  pull_request:
  schedule:
    - cron: "0 6 * * 1"  # weekly

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # required for SARIF upload
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4

      - name: Install AgentSploit
        run: uv tool install agentsploit

      - name: Scan MCP server
        env:
          MCP_TOKEN: ${{ secrets.MCP_TOKEN }}
        run: |
          agentsploit scan mcp https://mcp.staging.example.com/mcp \
            --auth-bearer-env MCP_TOKEN \
            --auth ./.agentsploit/authorization.yaml \
            --format sarif --out scan.sarif || true   # don't fail the job on findings

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan.sarif
          category: agentsploit-mcp
```

After the first run, findings appear under **Security → Code scanning** in the repo. Subsequent runs auto-dedupe via the fingerprints; resolved findings auto-close.

## Validating SARIF locally

```bash
# Install the SARIF SDK validator
pip install sarif-tools

# Validate your output
sarif validate ./scan.sarif

# Or use the schema directly
pip install jsonschema
curl -O https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json
python -c "import json, jsonschema; jsonschema.validate(json.load(open('scan.sarif')), json.load(open('sarif-schema-2.1.0.json')))"
```

## What AgentSploit doesn't emit (yet)

- **`locations`** — SARIF supports file/line location for findings. AgentSploit findings target *services* (MCP servers, agent endpoints), not source files, so we leave `locations` empty. If you want them populated for static analysis of MCP server source code, that's a v1.1 feature request.
- **`fixes`** — programmatic patch suggestions. Our `remediation` text is human-readable only.
- **Code-flow traces** — AgentSploit's traces (runner / poisoner) are persisted as separate JSON artifacts, not embedded in SARIF.
