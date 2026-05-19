"""Adapters that wrap existing scanner / verifier modules as JobRunners.

The CLI runs scans synchronously via `asyncio.run(...)`. The web server
already has a running event loop and a JobContext that streams events,
so we can't reuse those CLI functions verbatim. Each adapter here:

  - takes a JobContext
  - reads its parameters out of context.record.request
  - drives the underlying async generator and pushes findings into
    context.session.add(...) (which the JobManager has wrapped to emit
    events)

If you add a new "run X from the UI" feature, add an adapter here and
register it in `_REGISTRY` below.
"""

from __future__ import annotations

from pathlib import Path

from agentsploit.core import Target
from agentsploit.core.registry import registry as module_registry
from agentsploit.utils.logging import get_logger
from agentsploit.web.jobs import JobContext, JobRunner

log = get_logger(__name__)


async def run_mcp_scan(ctx: JobContext) -> None:
    """Run the MCP scanner module against a single target.

    Expected request keys: ``target_uri`` (required), ``checks`` (list,
    optional), ``insecure`` (bool, optional), ``timeout`` (float).
    """
    from agentsploit.modules.mcp.auth import Credentials
    from agentsploit.modules.mcp.scanner import MCPScanner

    req = ctx.record.request
    target_uri = req["target_uri"]
    target = Target.parse(target_uri)

    # Scope check against the active authorization.
    ctx.authorization.check(target_uri)

    module_registry.get("mcp/scanner")
    credentials = Credentials.from_cli(
        headers=req.get("headers") or None,
        bearer_token=req.get("bearer_token") or None,
        bearer_env=req.get("bearer_env") or None,
        insecure=bool(req.get("insecure", False)),
        timeout=float(req.get("timeout", 30.0)),
    )
    scanner = MCPScanner(check_filter=req.get("checks") or None, credentials=credentials)

    async for finding in scanner.run(target, ctx.session):
        ctx.session.add(finding)


async def run_path_verify(ctx: JobContext) -> None:
    """Verify a single mapper-inferred path against an agent.

    Expected request keys: ``source_session_id`` (session that produced
    the paths.json - the verify run drops its own session alongside),
    ``path_id`` (from paths.json), ``agent_config_path`` (optional),
    ``sink_arg`` (optional).
    """
    import json

    from agentsploit.modules.mapper.models import Path as MapperPath
    from agentsploit.modules.runner.config import RunnerConfig
    from agentsploit.modules.verifier.verifier import PathVerifier
    from agentsploit.web.api import _safe_session_path

    req = ctx.record.request
    source_session_id = req["source_session_id"]
    path_id = req["path_id"]

    source_session_dir = _safe_session_path(source_session_id)
    paths_path = source_session_dir / "paths.json"
    if not paths_path.exists():
        raise FileNotFoundError(
            f"session {source_session_id!r} has no paths.json - run `map build` first"
        )
    paths_blob = json.loads(paths_path.read_text())
    matches = [p for p in paths_blob.get("paths", []) if p.get("id") == path_id]
    if not matches:
        raise ValueError(f"path id {path_id!r} not found in {paths_path}")
    path_dict = matches[0]
    path = MapperPath(
        nodes=path_dict["nodes"],
        edges=path_dict["edges"],
        total_weight=path_dict.get("total_weight", float(path_dict.get("length", 1))),
    )

    base_config: RunnerConfig | None = None
    agent_config_path = req.get("agent_config_path")
    if agent_config_path:
        base_config = RunnerConfig.load(Path(agent_config_path))
        target_uri = base_config.target_uri()
    else:
        target_uri = "agent+mock://mock-1"

    ctx.authorization.check(target_uri)
    target = Target.parse(target_uri)

    verifier = PathVerifier(
        path=path,
        base_config=base_config,
        sink_arg_name=req.get("sink_arg"),
    )
    async for finding in verifier.run(target, ctx.session):
        ctx.session.add(finding)


_REGISTRY: dict[str, tuple[str, JobRunner]] = {
    "scan": ("Run MCP scanner", run_mcp_scan),
    "verify": ("Verify mapper path", run_path_verify),
}


def get_runner(kind: str) -> JobRunner:
    """Look up a registered runner by job kind."""
    entry = _REGISTRY.get(kind)
    if entry is None:
        raise KeyError(f"unknown job kind: {kind!r}")
    return entry[1]
