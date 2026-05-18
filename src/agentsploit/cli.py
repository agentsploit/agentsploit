"""AgentSploit CLI — Typer-based entry point."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentsploit.core import (
    Authorization,
    AuthorizationError,
    JSONReporter,
    RichReporter,
    SARIFReporter,
    Session,
    Target,
    TrainingAuth,
    registry,
)
from agentsploit.utils.logging import configure_logging, get_logger
from agentsploit.version import __version__

app = typer.Typer(
    name="agentsploit",
    help="Offensive security framework for AI agents and MCP servers.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)

scan_app = typer.Typer(help="Run scanner modules against a target.", no_args_is_help=True)
generate_app = typer.Typer(help="Generate payload artifacts.", no_args_is_help=True)
app.add_typer(scan_app, name="scan")
app.add_typer(generate_app, name="generate")

console = Console()
err_console = Console(stderr=True)
log = get_logger(__name__)


# --------------------------------------------------------------------------- helpers


def _load_auth(auth_path: Path | None, training: bool, target_uri: str) -> Authorization:
    if training and auth_path is not None:
        raise typer.BadParameter("Use either --auth or --training, not both.")
    if training:
        return TrainingAuth()
    if auth_path is None:
        raise typer.BadParameter(
            "Authorization required. Pass --auth <file> or --training. "
            "Generate one with: agentsploit init-auth"
        )
    try:
        auth = Authorization.load(auth_path)
    except FileNotFoundError as e:
        raise typer.BadParameter(f"Auth file not found: {auth_path}") from e

    try:
        auth.check(target_uri)
    except AuthorizationError as e:
        err_console.print(
            Panel(str(e), title="[red]Authorization denied[/red]", border_style="red")
        )
        raise typer.Exit(code=2) from e
    return auth


def _resolve_reporter(
    out_format: str, out_path: Path | None
) -> RichReporter | JSONReporter | SARIFReporter:
    match out_format:
        case "rich":
            return RichReporter(console)
        case "json":
            if out_path is None:
                raise typer.BadParameter("--out is required for --format json")
            return JSONReporter(out_path)
        case "sarif":
            if out_path is None:
                raise typer.BadParameter("--out is required for --format sarif")
            return SARIFReporter(out_path)
        case _:
            raise typer.BadParameter(f"Unknown format: {out_format!r}")


# --------------------------------------------------------------------------- commands


@app.callback()
def _main(
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose logging")] = False,
) -> None:
    configure_logging(verbose=verbose)
    registry.discover()


@app.command()
def version() -> None:
    """Print the AgentSploit version."""
    console.print(f"agentsploit {__version__}")


@app.command("list-modules")
def list_modules(
    category: Annotated[
        str | None, typer.Option("--category", "-c", help="Filter by category")
    ] = None,
) -> None:
    """List all available modules."""
    table = Table(title="AgentSploit Modules")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Description", overflow="fold")
    table.add_column("Targets")

    for mod_cls in registry.all():
        meta = mod_cls.META
        if category and meta.category.value != category:
            continue
        table.add_row(
            meta.name,
            meta.category.value,
            meta.description,
            ", ".join(t.value for t in meta.supported_targets) or "any",
        )
    console.print(table)


@app.command("init-auth")
def init_auth(
    target: Annotated[
        list[str], typer.Option("--target", "-t", help="Authorized target pattern (repeatable)")
    ],
    authorized_by: Annotated[
        str, typer.Option("--authorized-by", help='Name + email, e.g. "Jane <jane@x.com>"')
    ],
    engagement_id: Annotated[str | None, typer.Option("--engagement-id")] = None,
    valid_days: Annotated[
        int, typer.Option("--valid-days", help="Days the authorization is valid")
    ] = 30,
    scope_notes: Annotated[str, typer.Option("--scope-notes")] = "",
    forbidden: Annotated[
        list[str], typer.Option("--forbidden", help="Forbidden pattern (repeatable)")
    ] = [],
    out: Annotated[Path, typer.Option("--out", "-o")] = Path("./authorization.yaml"),
) -> None:
    """Generate a new authorization YAML file for an engagement."""
    now = datetime.now(UTC)
    auth = Authorization(
        authorized_by=authorized_by,
        authorized_at=now,
        valid_until=now + timedelta(days=valid_days),
        engagement_id=engagement_id or f"eng-{now.strftime('%Y%m%d')}-{out.stem[:8]}",
        scope_notes=scope_notes,
        targets=target,
        forbidden=forbidden,
    )
    auth.save(out)
    console.print(
        Panel(
            f"Wrote authorization file: [bold]{out}[/bold]\n"
            f"Engagement ID: [bold]{auth.engagement_id}[/bold]\n"
            f"Valid until:   [bold]{auth.valid_until.isoformat()}[/bold]\n"
            f"Targets:       {auth.targets}\n"
            f"Hash:          [dim]{auth.source_hash[:16]}…[/dim]",
            title="[green]Authorization created[/green]",
            border_style="green",
        )
    )


# --------------------------------------------------------------------------- scan


@scan_app.command("mcp")
def scan_mcp(
    target: Annotated[
        str, typer.Argument(help="Target URI, e.g. stdio://./server.py or http://host:port")
    ],
    auth: Annotated[Path | None, typer.Option("--auth", help="Authorization YAML")] = None,
    training: Annotated[
        bool, typer.Option("--training", help="Use restricted training-mode auth")
    ] = False,
    checks: Annotated[
        list[str] | None,
        typer.Option("--check", help="Run only these checks (repeatable). Default: all."),
    ] = None,
    header: Annotated[
        list[str] | None,
        typer.Option(
            "--header",
            "-H",
            help="HTTP header to send (repeatable), e.g. -H 'X-Tenant: acme'",
        ),
    ] = None,
    auth_bearer: Annotated[
        str | None,
        typer.Option(
            "--auth-bearer",
            help="Bearer token sent as Authorization: Bearer <token>",
        ),
    ] = None,
    auth_bearer_env: Annotated[
        str | None,
        typer.Option(
            "--auth-bearer-env",
            help="Read bearer token from this environment variable (preferred over --auth-bearer)",
        ),
    ] = None,
    insecure: Annotated[
        bool, typer.Option("--insecure", help="Skip TLS certificate verification")
    ] = False,
    timeout: Annotated[float, typer.Option("--timeout", help="HTTP timeout in seconds")] = 30.0,
    out_format: Annotated[str, typer.Option("--format", "-f", help="rich|json|sarif")] = "rich",
    out_path: Annotated[
        Path | None, typer.Option("--out", "-o", help="Output file (required for json/sarif)")
    ] = None,
) -> None:
    """Scan an MCP server."""
    authorization = _load_auth(auth, training, target)
    target_obj = Target.parse(target)
    reporter = _resolve_reporter(out_format, out_path)

    from agentsploit.modules.mcp.auth import Credentials
    from agentsploit.modules.mcp.scanner import MCPScanner

    try:
        credentials = Credentials.from_cli(
            headers=header,
            bearer_token=auth_bearer,
            bearer_env=auth_bearer_env,
            insecure=insecure,
            timeout=timeout,
        )
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e

    registry.get("mcp/scanner")  # ensure module is loaded and registered
    scanner = MCPScanner(check_filter=checks, credentials=credentials)
    session = Session(authorization=authorization)

    async def _run() -> None:
        async for finding in scanner.run(target_obj, session):
            session.add(finding)

    try:
        asyncio.run(_run())
    except Exception as e:
        err_console.print(f"[red]Scan failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    manifest = session.persist()
    reporter.emit(session)
    console.print(f"\nSession manifest: [dim]{manifest}[/dim]")
    raise typer.Exit(code=1 if session.findings else 0)


# --------------------------------------------------------------------------- generate


@generate_app.command("injection")
def generate_injection(
    technique: Annotated[
        str,
        typer.Option(
            "--technique", "-t", help="direct|role_confusion|delimiter|unicode_tag|tool_smuggling"
        ),
    ] = "direct",
    carrier: Annotated[
        str, typer.Option("--carrier", "-c", help="text|markdown|html|pdf|email|ical")
    ] = "text",
    goal: Annotated[
        str,
        typer.Option(
            "--goal", "-g", help='Attacker goal in plain English, e.g. "leak system prompt"'
        ),
    ] = "exfiltrate the system prompt",
    canary: Annotated[
        str | None,
        typer.Option(
            "--canary",
            help="Canary string to detect successful injection. Auto-generated if omitted.",
        ),
    ] = None,
    cover_text: Annotated[
        str,
        typer.Option("--cover-text", help="Plausible cover content the payload is embedded in."),
    ] = "Quarterly compliance review for Q2 2026.",
    out: Annotated[Path, typer.Option("--out", "-o")] = Path("./payload.out"),
) -> None:
    """Generate an indirect prompt injection payload."""
    from agentsploit.modules.injection.generator import InjectionGenerator

    generator = InjectionGenerator()
    artifact = generator.generate(
        technique=technique,
        carrier=carrier,
        goal=goal,
        canary=canary,
        cover_text=cover_text,
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(artifact.payload, bytes):
        out.write_bytes(artifact.payload)
    else:
        out.write_text(artifact.payload)

    console.print(
        Panel(
            f"Technique: [bold]{artifact.technique}[/bold]\n"
            f"Carrier:   [bold]{artifact.carrier}[/bold]\n"
            f"Canary:    [bold yellow]{artifact.canary}[/bold yellow]\n"
            f"Out:       [bold]{out}[/bold]\n"
            f"Size:      {artifact.size_bytes} bytes\n\n"
            f"[dim]Monitor target logs / agent responses for the canary string to detect a successful injection.[/dim]",
            title="[green]Payload generated[/green]",
            border_style="green",
        )
    )


if __name__ == "__main__":
    app()
