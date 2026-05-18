# Contributing to AgentSploit

Thanks for your interest. AgentSploit is a community offensive security tool — contributions of new modules, checks, payload techniques, and carriers are especially welcome.

## Ground rules

1. **No 0-days.** AgentSploit only ships modules for vulnerabilities that have been responsibly disclosed and either fixed or assigned a CVE. If you're researching a novel vulnerability, follow the disclosure path in [SECURITY.md](SECURITY.md) before opening a PR.
2. **No targeting of specific real systems.** Generic checks for misconfiguration classes are welcome; "checks" that exploit a specific company's deployment are not.
3. **Authorization-first.** All scanning code must route through `Authorization.check()` — never bypass it.
4. **Apache 2.0.** All contributions are licensed under Apache 2.0. You agree to the Developer Certificate of Origin by signing your commits (`git commit -s`).

## Dev setup

```bash
git clone https://github.com/agentsploit/agentsploit
cd agentsploit
uv sync --all-extras
uv run pytest
```

## Project layout

See [docs/architecture.md](docs/architecture.md) for the architecture overview and [docs/writing-modules.md](docs/writing-modules.md) for the module authoring guide.

## Submitting a change

1. Open an issue first for non-trivial changes
2. Fork, branch, write the code with tests
3. Run `uv run ruff check . && uv run mypy src && uv run pytest`
4. Open a PR with a clear description and a reference to the issue
5. Sign your commits (`git commit -s`)

## Module submission checklist

- [ ] New module/check has a docstring describing the vuln class and remediation
- [ ] References (CVE, blog post, advisory) included
- [ ] Unit test for the check logic
- [ ] Integration test against the bundled vulnerable fixture (if applicable)
- [ ] README updated if it adds a new capability category

## Code style

- Ruff for linting and formatting (`ruff format && ruff check`)
- mypy in strict mode
- Type hints on all public APIs
- Async-first for I/O modules
