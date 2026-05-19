# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| 0.x | best-effort fixes for critical issues; upgrade to 1.0 recommended |

When 1.1 ships, support for 1.0.x continues for 6 months from the 1.1 release date. The current supported window is always documented in this file.

## Reporting a vulnerability in AgentSploit itself

A vulnerability in AgentSploit (the framework, not a target it scans) means: a way to make AgentSploit harm a target *outside its authorised scope*, exfiltrate secrets from an operator, execute arbitrary code on the operator's machine, or any other behaviour that breaks the security model documented in [AUTHORIZATION.md](AUTHORIZATION.md).

**Report privately** via:

- **GitHub Security Advisories** (preferred): https://github.com/desledishant10/agentsploit/security/advisories/new
- **Email**: security@agentsploit.dev (PGP key in [`docs/pgp-public-key.asc`](docs/pgp-public-key.asc) — TODO before 1.1)

Please include:

- The affected version (`agentsploit version`)
- A minimal reproduction (command + expected vs actual behaviour)
- The impact you observed (what got compromised)
- Any suggested remediation

### SLA

| Action | Target |
|---|---|
| Initial acknowledgement | within **72 hours** of report |
| Severity triage + CVSS score | within **7 days** of report |
| Fix for HIGH/CRITICAL severity | within **30 days** of triage |
| Fix for MEDIUM severity | within **60 days** of triage |
| Public advisory + patch release | coordinated with reporter |

Reporters who responsibly disclose receive credit in the GitHub Security Advisory unless they request anonymity.

## Reporting a vulnerability *found by* AgentSploit (in a third-party target)

If AgentSploit's scanner / verifier / poisoner produces a finding against a third-party MCP server or agent runtime, follow **that vendor's** responsible-disclosure policy. AgentSploit maintainers are not the right channel for vendor disclosures and will not coordinate them on your behalf.

Recommended timeline (modeled on Google Project Zero and CERT/CC):

1. Notify the vendor with the finding and a reproduction
2. Give 90 days for a fix before public disclosure
3. Coordinate the disclosure date with the vendor
4. Publish a write-up only after the vendor has shipped a fix or the deadline has passed

AgentSploit's own bundled fixtures (`tests/fixtures/vulnerable_mcp/`, etc.) are intentionally vulnerable for testing — findings against them do not warrant disclosure.

## Out of scope

The following are explicitly out of scope for AgentSploit's vulnerability disclosure process:

- Findings produced by running AgentSploit against itself or its bundled vulnerable fixtures (intentional)
- Anything that requires the operator to disable the authorisation check (`Authorization.check()`)
- Anything that requires running AgentSploit with elevated/root privileges
- Issues in transitive dependencies — report those upstream
- Theoretical issues without a reproduction
- Findings against models / providers (Claude, OpenAI, etc.) — report those to the respective provider

## Hall of fame

Reporters credited in security advisories are listed here. (None yet — first reporter gets the top spot.)
