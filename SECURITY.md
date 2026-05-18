# Security Policy

## Supported versions

AgentSploit is in alpha. Only the latest minor release receives security fixes.

| Version | Supported |
|---|---|
| 0.1.x | yes |
| < 0.1 | no |

## Reporting a vulnerability in AgentSploit

If you discover a vulnerability in AgentSploit itself (the framework, not in a target it scans), please report it privately:

- **GitHub Security Advisories:** https://github.com/agentsploit/agentsploit/security/advisories/new
- **Email:** security@agentsploit.dev (PGP key in repository)

Please include:

- The affected version
- A minimal reproduction
- The impact you observed
- Any suggested remediation

We aim to acknowledge within 72 hours and ship a fix within 30 days for high-severity issues.

## Reporting a vulnerability found by AgentSploit

If AgentSploit's scanner produces a finding against a third-party MCP server or agent runtime, follow that vendor's responsible disclosure policy. AgentSploit maintainers are not the right channel for vendor disclosures.

Recommended timeline (modeled on Google Project Zero / CERT/CC):

- Notify the vendor with the finding and reproduction steps
- Give 90 days for a fix before public disclosure
- Coordinate the disclosure date with the vendor
- Publish a write-up only after the vendor has shipped a fix or the deadline has passed

## Out of scope for AgentSploit's own security

The following are explicitly out of scope for AgentSploit's bug bounty / disclosure process:

- Findings produced by running AgentSploit against itself or its bundled vulnerable fixture (these are intentional)
- Anything that requires the operator to disable the authorization check
- Anything that requires running AgentSploit with elevated/root privileges
