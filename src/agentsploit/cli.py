"""AgentSploit CLI - Typer-based entry point."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer

if TYPE_CHECKING:
    from agentsploit.modules.mapper.models import Path as MapperPath
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
run_app = typer.Typer(
    help="Drive a payload through a live agent and confirm exploitation.",
    no_args_is_help=True,
)
map_app = typer.Typer(
    help="Build and query the cross-server permission graph.",
    no_args_is_help=True,
)
verify_app = typer.Typer(
    help="Verify a mapper-inferred path by driving it through a live agent.",
    no_args_is_help=True,
)
poison_app = typer.Typer(
    help="Multi-phase memory-poisoning attacks against agents with shared storage.",
    no_args_is_help=True,
)
app.add_typer(scan_app, name="scan")
app.add_typer(generate_app, name="generate")
app.add_typer(run_app, name="run")
app.add_typer(map_app, name="map")
app.add_typer(verify_app, name="verify")
app.add_typer(poison_app, name="poison")

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


@app.command("init")
def init_engagement(
    directory: Annotated[
        Path,
        typer.Argument(
            help="Target directory to scaffold (created if missing).",
        ),
    ],
    authorized_by: Annotated[
        str,
        typer.Option(
            "--authorized-by",
            help='Name + email recorded in authorization.yaml, e.g. "Jane <jane@x.com>"',
        ),
    ] = "Operator <ops@example.com>",
    engagement_id: Annotated[
        str | None,
        typer.Option("--engagement-id", help="Engagement identifier (default: auto-generated)"),
    ] = None,
    valid_days: Annotated[
        int, typer.Option("--valid-days", help="Days the authorization stays valid")
    ] = 30,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            help="Overwrite an existing non-empty directory",
        ),
    ] = False,
) -> None:
    """Scaffold a new engagement directory with all the YAML configs you need."""
    from agentsploit.scaffolder import ScaffoldError, scaffold_engagement

    try:
        written = scaffold_engagement(
            target_dir=directory,
            authorized_by=authorized_by,
            engagement_id=engagement_id,
            valid_days=valid_days,
            force=force,
        )
    except ScaffoldError as e:
        raise typer.BadParameter(str(e)) from e

    file_list = "\n".join(f"  - {p.name}" for p in written)
    console.print(
        Panel(
            f"Scaffolded engagement at: [bold]{directory.resolve()}[/bold]\n"
            f"Files written:\n{file_list}\n\n"
            "[bold]Next steps:[/bold]\n"
            "  1. Edit `authorization.yaml` to add real target URIs\n"
            "  2. Pick an agent config (anthropic/openai/http) and set the API key in env\n"
            "  3. Edit `map-targets.yaml` with the MCP servers you'll enumerate\n"
            "  4. Read the generated `README.md` for the standard pipeline\n",
            title="[green]Engagement scaffolded[/green]",
            border_style="green",
        )
    )


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


# --------------------------------------------------------------------------- run


@run_app.command("injection")
def run_injection(
    payload: Annotated[
        Path,
        typer.Option(
            "--payload", "-p", help="Path to a payload file generated by `generate injection`"
        ),
    ],
    canary: Annotated[
        str, typer.Option("--canary", help="Canary string embedded in the payload (case-sensitive)")
    ],
    agent_config: Annotated[
        Path,
        typer.Option("--agent", "-a", help="Agent YAML config (provider, model, prompts, tools)"),
    ],
    auth: Annotated[Path | None, typer.Option("--auth", help="Authorization YAML")] = None,
    training: Annotated[
        bool, typer.Option("--training", help="Use restricted training-mode auth")
    ] = False,
    out_format: Annotated[str, typer.Option("--format", "-f", help="rich|json|sarif")] = "rich",
    out_path: Annotated[
        Path | None, typer.Option("--out", "-o", help="Output file (required for json/sarif)")
    ] = None,
) -> None:
    """Drive a payload through a live agent and confirm exploitation."""
    from agentsploit.modules.runner.config import RunnerConfig
    from agentsploit.modules.runner.runner import InjectionRunner

    try:
        config = RunnerConfig.load(agent_config)
    except Exception as e:
        raise typer.BadParameter(f"Failed to load agent config: {e}") from e

    target_uri = config.target_uri()
    authorization = _load_auth(auth, training, target_uri)
    target_obj = Target.parse(target_uri)
    reporter = _resolve_reporter(out_format, out_path)

    # Read payload - bytes for binary carriers (PDF), text otherwise
    raw = payload.read_bytes()
    try:
        payload_str = raw.decode("utf-8")
    except UnicodeDecodeError:
        payload_str = raw.decode("utf-8", errors="replace")

    runner = InjectionRunner(config=config, payload=payload_str, canary=canary)
    session = Session(authorization=authorization)

    async def _run() -> None:
        async for finding in runner.run(target_obj, session):
            session.add(finding)

    try:
        asyncio.run(_run())
    except Exception as e:
        err_console.print(f"[red]Run failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    manifest = session.persist()
    reporter.emit(session)
    console.print(f"\nSession manifest: [dim]{manifest}[/dim]")

    confirmed = any("confirmed-injection" in f.tags for f in session.findings)
    raise typer.Exit(code=1 if confirmed else 0)


# --------------------------------------------------------------------------- map


def _load_map_targets(path: Path) -> list[str]:
    import yaml

    data = yaml.safe_load(path.read_bytes())
    if not isinstance(data, dict) or "targets" not in data:
        raise typer.BadParameter(f"{path}: expected a YAML doc with a top-level `targets:` list")
    targets = data["targets"]
    if not isinstance(targets, list) or not targets:
        raise typer.BadParameter(f"{path}: `targets` must be a non-empty list")
    return [str(t) for t in targets]


@map_app.command("build")
def map_build(
    targets: Annotated[
        Path,
        typer.Option(
            "--targets",
            "-t",
            help="YAML file with a `targets:` list of MCP URIs to enumerate",
        ),
    ],
    auth: Annotated[Path | None, typer.Option("--auth", help="Authorization YAML")] = None,
    training: Annotated[
        bool, typer.Option("--training", help="Use restricted training-mode auth")
    ] = False,
    auth_bearer_env: Annotated[
        str | None,
        typer.Option(
            "--auth-bearer-env",
            help="Env var name for bearer token applied to every target (HTTP/SSE)",
        ),
    ] = None,
    header: Annotated[
        list[str] | None, typer.Option("--header", "-H", help="HTTP header (repeatable)")
    ] = None,
    insecure: Annotated[bool, typer.Option("--insecure")] = False,
    timeout: Annotated[float, typer.Option("--timeout")] = 30.0,
    max_length: Annotated[int, typer.Option("--max-length", help="Max path length in hops")] = 4,
    min_privilege: Annotated[
        str,
        typer.Option(
            "--min-privilege",
            help="Lowest sink privilege to report: read|internal_action|egress|mutation|execution",
        ),
    ] = "egress",
    out_format: Annotated[str, typer.Option("--format", "-f", help="rich|json|sarif")] = "rich",
    out_path: Annotated[
        Path | None, typer.Option("--out", "-o", help="Output file (required for json/sarif)")
    ] = None,
) -> None:
    """Enumerate every target, classify tools, infer edges, report risky paths."""
    from agentsploit.modules.mapper.mapper import PermissionMapper
    from agentsploit.modules.mapper.models import Privilege
    from agentsploit.modules.mcp.auth import Credentials

    target_uris = _load_map_targets(targets)

    # The "authorization target" for the map operation is a synthetic URI
    # listing the targets. We require every one of them to be in scope.
    authorization = _load_auth(auth, training, target_uris[0])
    for uri in target_uris[1:]:
        try:
            authorization.check(uri)
        except Exception as e:
            err_console.print(
                Panel(str(e), title="[red]Authorization denied[/red]", border_style="red")
            )
            raise typer.Exit(code=2) from e

    try:
        priv = Privilege[min_privilege.upper()]
    except KeyError as e:
        raise typer.BadParameter(
            f"Unknown privilege {min_privilege!r}. Use one of: {[p.label for p in Privilege]}"
        ) from e

    try:
        credentials = Credentials.from_cli(
            headers=header,
            bearer_env=auth_bearer_env,
            insecure=insecure,
            timeout=timeout,
        )
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e

    reporter = _resolve_reporter(out_format, out_path)
    mapper = PermissionMapper(
        target_uris=target_uris,
        credentials=credentials,
        max_path_length=max_length,
        min_sink_privilege=priv,
    )
    session = Session(authorization=authorization)
    target_obj = Target.parse(target_uris[0])

    async def _run() -> None:
        async for finding in mapper.run(target_obj, session):
            session.add(finding)

    try:
        asyncio.run(_run())
    except Exception as e:
        err_console.print(f"[red]Map build failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    manifest = session.persist()
    reporter.emit(session)
    console.print(f"\nSession manifest: [dim]{manifest}[/dim]")

    risky = any(f.severity >= 2 and "path" in f.tags for f in session.findings)
    raise typer.Exit(code=1 if risky else 0)


@map_app.command("export")
def map_export(
    graph_file: Annotated[
        Path,
        typer.Option(
            "--graph", "-g", help="Path to a permission_graph.json produced by `map build`"
        ),
    ],
    fmt: Annotated[str, typer.Option("--format", "-f", help="dot|mermaid|json")] = "mermaid",
    out: Annotated[
        Path | None, typer.Option("--out", "-o", help="Write to file (default stdout)")
    ] = None,
) -> None:
    """Export a built graph to graphviz DOT, Mermaid, or JSON."""
    import json as _json

    from agentsploit.modules.mapper.exporter import to_dot, to_json, to_mermaid
    from agentsploit.modules.mapper.models import Graph

    raw = _json.loads(graph_file.read_text())
    graph = Graph.model_validate(raw)

    match fmt:
        case "dot":
            rendered = to_dot(graph)
        case "mermaid":
            rendered = to_mermaid(graph)
        case "json":
            rendered = to_json(graph)
        case _:
            raise typer.BadParameter(f"Unknown format {fmt!r}. Use dot|mermaid|json.")

    if out is None:
        console.print(rendered)
    else:
        out.write_text(rendered)
        console.print(f"Wrote {fmt} graph to [bold]{out}[/bold]")


# --------------------------------------------------------------------------- verify


def _resolve_path_in_graph(graph_file: Path, from_tool: str, to_tool: str) -> MapperPath:
    """Load a persisted graph and return the shortest path between two tool names."""
    import json as _json

    from agentsploit.modules.mapper.models import Graph
    from agentsploit.modules.mapper.paths import shortest_path

    raw = _json.loads(graph_file.read_text())
    graph = Graph.model_validate(raw)

    matches_src = [n for n in graph.nodes.values() if n.name == from_tool]
    matches_dst = [n for n in graph.nodes.values() if n.name == to_tool]

    if not matches_src:
        raise typer.BadParameter(f"No tool named {from_tool!r} in the graph")
    if not matches_dst:
        raise typer.BadParameter(f"No tool named {to_tool!r} in the graph")

    # If a tool name exists on multiple servers, the first match wins. This
    # is fine for v0.5; we'll add explicit server-qualified IDs in v0.6.
    src = matches_src[0]
    dst = matches_dst[0]
    path = shortest_path(graph, src.id, dst.id)
    if path is None:
        raise typer.BadParameter(f"No inferred path from {from_tool!r} to {to_tool!r} in the graph")
    return path


@verify_app.command("path")
def verify_path(
    graph_file: Annotated[
        Path,
        typer.Option(
            "--graph",
            "-g",
            help="Path to a permission_graph.json produced by `map build`",
        ),
    ],
    from_tool: Annotated[
        str, typer.Option("--from", help="Source tool name on the path (e.g. read_file)")
    ],
    to_tool: Annotated[
        str, typer.Option("--to", help="Sink tool name on the path (e.g. run_shell)")
    ],
    agent_config: Annotated[
        Path | None,
        typer.Option(
            "--agent",
            "-a",
            help="Agent YAML config (optional - defaults to a mock agent)",
        ),
    ] = None,
    auth: Annotated[Path | None, typer.Option("--auth", help="Authorization YAML")] = None,
    training: Annotated[
        bool, typer.Option("--training", help="Use restricted training-mode auth")
    ] = False,
    sink_arg: Annotated[
        str | None,
        typer.Option(
            "--sink-arg",
            help="Sink argument name to land the canary in (default: auto-chosen)",
        ),
    ] = None,
    out_format: Annotated[str, typer.Option("--format", "-f", help="rich|json|sarif")] = "rich",
    out_path: Annotated[
        Path | None, typer.Option("--out", "-o", help="Output file (required for json/sarif)")
    ] = None,
) -> None:
    """Verify a mapper-inferred path by driving it through a live agent."""
    from agentsploit.modules.runner.config import RunnerConfig
    from agentsploit.modules.verifier.verifier import PathVerifier

    path = _resolve_path_in_graph(graph_file, from_tool, to_tool)

    # If the operator supplied an agent config, use it to set provider/model.
    # Otherwise the verifier defaults to the mock agent - full self-test loop
    # with no API keys.
    base_config: RunnerConfig | None = None
    if agent_config is not None:
        try:
            base_config = RunnerConfig.load(agent_config)
        except Exception as e:
            raise typer.BadParameter(f"Failed to load agent config: {e}") from e
        target_uri = base_config.target_uri()
    else:
        target_uri = "agent+mock://mock-1"

    authorization = _load_auth(auth, training, target_uri)
    target_obj = Target.parse(target_uri)
    reporter = _resolve_reporter(out_format, out_path)

    verifier = PathVerifier(path=path, base_config=base_config, sink_arg_name=sink_arg)
    session = Session(authorization=authorization)

    async def _run() -> None:
        async for finding in verifier.run(target_obj, session):
            session.add(finding)

    try:
        asyncio.run(_run())
    except Exception as e:
        err_console.print(f"[red]Verification failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    manifest = session.persist()
    reporter.emit(session)
    console.print(f"\nSession manifest: [dim]{manifest}[/dim]")

    confirmed = any("path-confirmed" in f.tags for f in session.findings)
    raise typer.Exit(code=1 if confirmed else 0)


@verify_app.command("all-paths")
def verify_all_paths(
    graph_file: Annotated[
        Path,
        typer.Option(
            "--graph",
            "-g",
            help="Path to a permission_graph.json produced by `map build`",
        ),
    ],
    agent_config: Annotated[
        Path | None,
        typer.Option(
            "--agent",
            "-a",
            help="Agent YAML config (optional - defaults to a mock agent)",
        ),
    ] = None,
    auth: Annotated[Path | None, typer.Option("--auth", help="Authorization YAML")] = None,
    training: Annotated[
        bool, typer.Option("--training", help="Use restricted training-mode auth")
    ] = False,
    min_privilege: Annotated[
        str,
        typer.Option(
            "--min-privilege",
            help="Lowest sink privilege to verify: read|internal_action|egress|mutation|execution",
        ),
    ] = "egress",
    max_length: Annotated[int, typer.Option("--max-length", help="Max path length in hops")] = 4,
    max_paths: Annotated[
        int | None,
        typer.Option("--max-paths", help="Cap how many paths to verify (cost control)"),
    ] = None,
    parallel: Annotated[int, typer.Option("--parallel", "-p", help="Concurrent verifications")] = 2,
    fuzz: Annotated[
        bool,
        typer.Option(
            "--fuzz",
            help="For each path, try multiple techniques and stop at first CONFIRMED",
        ),
    ] = False,
    fuzz_techniques: Annotated[
        str | None,
        typer.Option(
            "--techniques",
            help="Comma-separated technique names for --fuzz (default: all)",
        ),
    ] = None,
    out_format: Annotated[str, typer.Option("--format", "-f", help="rich|json|sarif")] = "rich",
    out_path: Annotated[
        Path | None, typer.Option("--out", "-o", help="Output file (required for json/sarif)")
    ] = None,
) -> None:
    """Batch-verify every source→sink path in the graph against a single agent."""
    import json as _json

    from agentsploit.modules.mapper.models import Graph
    from agentsploit.modules.mapper.models import Privilege as MapperPrivilege
    from agentsploit.modules.runner.config import RunnerConfig
    from agentsploit.modules.verifier.batch import BatchPathVerifier

    raw = _json.loads(graph_file.read_text())
    graph = Graph.model_validate(raw)

    try:
        priv = MapperPrivilege[min_privilege.upper()]
    except KeyError as e:
        raise typer.BadParameter(
            f"Unknown privilege {min_privilege!r}. Use one of: {[p.label for p in MapperPrivilege]}"
        ) from e

    base_config: RunnerConfig | None = None
    if agent_config is not None:
        try:
            base_config = RunnerConfig.load(agent_config)
        except Exception as e:
            raise typer.BadParameter(f"Failed to load agent config: {e}") from e
        target_uri = base_config.target_uri()
    else:
        target_uri = "agent+mock://mock-1"

    authorization = _load_auth(auth, training, target_uri)
    target_obj = Target.parse(target_uri)
    reporter = _resolve_reporter(out_format, out_path)

    technique_list: list[str] | None = None
    if fuzz_techniques:
        technique_list = [t.strip() for t in fuzz_techniques.split(",") if t.strip()]

    batch = BatchPathVerifier(
        graph=graph,
        base_config=base_config,
        max_path_length=max_length,
        min_sink_privilege=priv,
        max_paths=max_paths,
        parallel=parallel,
        fuzz=fuzz,
        fuzz_techniques=technique_list,
    )
    session = Session(authorization=authorization)

    async def _run() -> None:
        async for finding in batch.run(target_obj, session):
            session.add(finding)

    try:
        asyncio.run(_run())
    except Exception as e:
        err_console.print(f"[red]Batch verification failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    manifest = session.persist()
    reporter.emit(session)
    console.print(f"\nSession manifest: [dim]{manifest}[/dim]")

    confirmed = any("path-confirmed" in f.tags for f in session.findings)
    raise typer.Exit(code=1 if confirmed else 0)


@verify_app.command("fuzz-path")
def verify_fuzz_path(
    graph_file: Annotated[
        Path, typer.Option("--graph", "-g", help="Path to a permission_graph.json")
    ],
    from_tool: Annotated[str, typer.Option("--from", help="Source tool name on the path")],
    to_tool: Annotated[str, typer.Option("--to", help="Sink tool name on the path")],
    agent_config: Annotated[
        Path | None,
        typer.Option("--agent", "-a", help="Agent YAML config (defaults to mock agent)"),
    ] = None,
    auth: Annotated[Path | None, typer.Option("--auth", help="Authorization YAML")] = None,
    training: Annotated[
        bool, typer.Option("--training", help="Use restricted training-mode auth")
    ] = False,
    techniques: Annotated[
        str | None,
        typer.Option(
            "--techniques",
            help="Comma-separated technique names to try (default: all). "
            "Options: role_confusion, direct, delimiter, unicode_tag, tool_smuggling",
        ),
    ] = None,
    sink_arg: Annotated[
        str | None,
        typer.Option("--sink-arg", help="Sink argument to land canary in (default: auto)"),
    ] = None,
    no_early_stop: Annotated[
        bool,
        typer.Option(
            "--no-early-stop",
            help="Try every technique even after one CONFIRMS (default: stop on first)",
        ),
    ] = False,
    out_format: Annotated[str, typer.Option("--format", "-f", help="rich|json|sarif")] = "rich",
    out_path: Annotated[
        Path | None, typer.Option("--out", "-o", help="Output file (required for json/sarif)")
    ] = None,
) -> None:
    """Try multiple injection techniques against one path; stop at first CONFIRMED."""
    from agentsploit.modules.runner.config import RunnerConfig
    from agentsploit.modules.verifier.fuzzer import FuzzPathVerifier

    path = _resolve_path_in_graph(graph_file, from_tool, to_tool)

    base_config: RunnerConfig | None = None
    if agent_config is not None:
        try:
            base_config = RunnerConfig.load(agent_config)
        except Exception as e:
            raise typer.BadParameter(f"Failed to load agent config: {e}") from e
        target_uri = base_config.target_uri()
    else:
        target_uri = "agent+mock://mock-1"

    authorization = _load_auth(auth, training, target_uri)
    target_obj = Target.parse(target_uri)
    reporter = _resolve_reporter(out_format, out_path)

    technique_list: list[str] | None = None
    if techniques:
        technique_list = [t.strip() for t in techniques.split(",") if t.strip()]

    try:
        fuzzer = FuzzPathVerifier(
            path=path,
            base_config=base_config,
            techniques=technique_list,
            sink_arg_name=sink_arg,
            stop_on_first_confirm=not no_early_stop,
        )
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e

    session = Session(authorization=authorization)

    async def _run() -> None:
        async for finding in fuzzer.run(target_obj, session):
            session.add(finding)

    try:
        asyncio.run(_run())
    except Exception as e:
        err_console.print(f"[red]Fuzz verification failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    manifest = session.persist()
    reporter.emit(session)
    console.print(f"\nSession manifest: [dim]{manifest}[/dim]")

    confirmed = any("path-confirmed" in f.tags for f in session.findings)
    raise typer.Exit(code=1 if confirmed else 0)


# --------------------------------------------------------------------------- poison


@poison_app.command("verify")
def poison_verify(
    sink_tool: Annotated[
        str,
        typer.Option(
            "--sink-tool",
            help="Name of the sink tool the poisoned note should steer the victim toward",
        ),
    ],
    sink_arg: Annotated[
        str, typer.Option("--sink-arg", help="Sink argument that should hold the canary")
    ] = "body",
    sink_privilege: Annotated[
        str,
        typer.Option(
            "--sink-privilege",
            help="Label used in the finding remediation (egress|mutation|execution|...)",
        ),
    ] = "egress",
    agent_config: Annotated[
        Path | None,
        typer.Option("--agent", "-a", help="Agent YAML config (defaults to mock)"),
    ] = None,
    auth: Annotated[Path | None, typer.Option("--auth", help="Authorization YAML")] = None,
    training: Annotated[
        bool, typer.Option("--training", help="Use restricted training-mode auth")
    ] = False,
    technique: Annotated[
        str,
        typer.Option(
            "--technique",
            help="Injection envelope: role_confusion|direct|delimiter|unicode_tag|tool_smuggling",
        ),
    ] = "role_confusion",
    store_key: Annotated[
        str | None,
        typer.Option("--store-key", help="Key under which the poisoned note is stored"),
    ] = None,
    canary: Annotated[
        str | None, typer.Option("--canary", help="Override canary (default: random)")
    ] = None,
    out_format: Annotated[str, typer.Option("--format", "-f", help="rich|json|sarif")] = "rich",
    out_path: Annotated[
        Path | None, typer.Option("--out", "-o", help="Output file (required for json/sarif)")
    ] = None,
) -> None:
    """Two-phase memory poisoning: attacker writes a crafted note, victim reads it
    and is steered into invoking the sink with the canary."""
    from agentsploit.modules.poisoning.poisoner import MemoryPoisoner
    from agentsploit.modules.runner.config import RunnerConfig

    base_config: RunnerConfig | None = None
    if agent_config is not None:
        try:
            base_config = RunnerConfig.load(agent_config)
        except Exception as e:
            raise typer.BadParameter(f"Failed to load agent config: {e}") from e
        target_uri = base_config.target_uri()
    else:
        target_uri = "agent+mock://mock-1"

    authorization = _load_auth(auth, training, target_uri)
    target_obj = Target.parse(target_uri)
    reporter = _resolve_reporter(out_format, out_path)

    try:
        poisoner = MemoryPoisoner(
            sink_tool_name=sink_tool,
            sink_arg_name=sink_arg,
            sink_privilege_label=sink_privilege,
            base_config=base_config,
            technique=technique,
            store_key=store_key,
            canary=canary,
        )
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e

    session = Session(authorization=authorization)

    async def _run() -> None:
        async for finding in poisoner.run(target_obj, session):
            session.add(finding)

    try:
        asyncio.run(_run())
    except Exception as e:
        err_console.print(f"[red]Poison verification failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    manifest = session.persist()
    reporter.emit(session)
    console.print(f"\nSession manifest: [dim]{manifest}[/dim]")

    confirmed = any("poison-confirmed" in f.tags for f in session.findings)
    raise typer.Exit(code=1 if confirmed else 0)


@poison_app.command("verify-rag")
def poison_verify_rag(
    sink_tool: Annotated[
        str,
        typer.Option(
            "--sink-tool",
            help="Name of the sink tool the poisoned doc should steer the victim toward",
        ),
    ],
    sink_arg: Annotated[
        str, typer.Option("--sink-arg", help="Sink argument that should hold the canary")
    ] = "body",
    sink_privilege: Annotated[
        str,
        typer.Option(
            "--sink-privilege",
            help="Label used in finding remediation (egress|mutation|execution|...)",
        ),
    ] = "egress",
    target_query: Annotated[
        str,
        typer.Option(
            "--query",
            help="The query string the victim agent will run against the vector store",
        ),
    ] = "how do I reset my password",
    agent_config: Annotated[
        Path | None,
        typer.Option("--agent", "-a", help="Agent YAML config (defaults to mock)"),
    ] = None,
    auth: Annotated[Path | None, typer.Option("--auth", help="Authorization YAML")] = None,
    training: Annotated[
        bool, typer.Option("--training", help="Use restricted training-mode auth")
    ] = False,
    technique: Annotated[
        str,
        typer.Option(
            "--technique",
            help="Injection envelope: role_confusion|direct|delimiter|unicode_tag|tool_smuggling",
        ),
    ] = "role_confusion",
    canary: Annotated[
        str | None, typer.Option("--canary", help="Override canary (default: random)")
    ] = None,
    out_format: Annotated[str, typer.Option("--format", "-f", help="rich|json|sarif")] = "rich",
    out_path: Annotated[
        Path | None, typer.Option("--out", "-o", help="Output file (required for json/sarif)")
    ] = None,
) -> None:
    """RAG poisoning: index a crafted doc in a vector store, force a semantic
    search that retrieves it, confirm the victim agent obeys the embedded chain."""
    from agentsploit.modules.poisoning.rag import RAGPoisoner
    from agentsploit.modules.runner.config import RunnerConfig

    base_config: RunnerConfig | None = None
    if agent_config is not None:
        try:
            base_config = RunnerConfig.load(agent_config)
        except Exception as e:
            raise typer.BadParameter(f"Failed to load agent config: {e}") from e
        target_uri = base_config.target_uri()
    else:
        target_uri = "agent+mock://mock-1"

    authorization = _load_auth(auth, training, target_uri)
    target_obj = Target.parse(target_uri)
    reporter = _resolve_reporter(out_format, out_path)

    try:
        poisoner = RAGPoisoner(
            sink_tool_name=sink_tool,
            sink_arg_name=sink_arg,
            sink_privilege_label=sink_privilege,
            base_config=base_config,
            technique=technique,
            target_query=target_query,
            canary=canary,
        )
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e

    session = Session(authorization=authorization)

    async def _run() -> None:
        async for finding in poisoner.run(target_obj, session):
            session.add(finding)

    try:
        asyncio.run(_run())
    except Exception as e:
        err_console.print(f"[red]RAG poison verification failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    manifest = session.persist()
    reporter.emit(session)
    console.print(f"\nSession manifest: [dim]{manifest}[/dim]")

    confirmed = any("poison-confirmed" in f.tags for f in session.findings)
    raise typer.Exit(code=1 if confirmed else 0)


@poison_app.command("verify-thread")
def poison_verify_thread(
    sink_tool: Annotated[
        str,
        typer.Option(
            "--sink-tool",
            help="Name of the sink tool the poisoned thread turn should steer the victim toward",
        ),
    ],
    sink_arg: Annotated[
        str, typer.Option("--sink-arg", help="Sink argument that should hold the canary")
    ] = "body",
    sink_privilege: Annotated[
        str,
        typer.Option(
            "--sink-privilege",
            help="Label used in finding remediation (egress|mutation|execution|...)",
        ),
    ] = "egress",
    turns_back: Annotated[
        int,
        typer.Option(
            "--turns-back",
            help="How many turns back in the thread the poison sits (default 2)",
        ),
    ] = 2,
    thread_id: Annotated[
        str | None,
        typer.Option("--thread-id", help="Override the synthetic thread id"),
    ] = None,
    agent_config: Annotated[
        Path | None,
        typer.Option("--agent", "-a", help="Agent YAML config (defaults to mock)"),
    ] = None,
    auth: Annotated[Path | None, typer.Option("--auth", help="Authorization YAML")] = None,
    training: Annotated[
        bool, typer.Option("--training", help="Use restricted training-mode auth")
    ] = False,
    technique: Annotated[
        str,
        typer.Option(
            "--technique",
            help="Injection envelope: role_confusion|direct|delimiter|unicode_tag|tool_smuggling",
        ),
    ] = "role_confusion",
    canary: Annotated[
        str | None, typer.Option("--canary", help="Override canary (default: random)")
    ] = None,
    out_format: Annotated[str, typer.Option("--format", "-f", help="rich|json|sarif")] = "rich",
    out_path: Annotated[
        Path | None, typer.Option("--out", "-o", help="Output file (required for json/sarif)")
    ] = None,
) -> None:
    """Conversation-thread poisoning: inject a fake assistant turn into a
    shared thread, force the victim agent to resume from it, confirm the
    embedded chain instruction fires."""
    from agentsploit.modules.poisoning.thread import ThreadPoisoner
    from agentsploit.modules.runner.config import RunnerConfig

    base_config: RunnerConfig | None = None
    if agent_config is not None:
        try:
            base_config = RunnerConfig.load(agent_config)
        except Exception as e:
            raise typer.BadParameter(f"Failed to load agent config: {e}") from e
        target_uri = base_config.target_uri()
    else:
        target_uri = "agent+mock://mock-1"

    authorization = _load_auth(auth, training, target_uri)
    target_obj = Target.parse(target_uri)
    reporter = _resolve_reporter(out_format, out_path)

    try:
        poisoner = ThreadPoisoner(
            sink_tool_name=sink_tool,
            sink_arg_name=sink_arg,
            sink_privilege_label=sink_privilege,
            base_config=base_config,
            technique=technique,
            thread_id=thread_id,
            turns_back=turns_back,
            canary=canary,
        )
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e

    session = Session(authorization=authorization)

    async def _run() -> None:
        async for finding in poisoner.run(target_obj, session):
            session.add(finding)

    try:
        asyncio.run(_run())
    except Exception as e:
        err_console.print(f"[red]Thread poison verification failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    manifest = session.persist()
    reporter.emit(session)
    console.print(f"\nSession manifest: [dim]{manifest}[/dim]")

    confirmed = any("poison-confirmed" in f.tags for f in session.findings)
    raise typer.Exit(code=1 if confirmed else 0)


if __name__ == "__main__":
    app()
