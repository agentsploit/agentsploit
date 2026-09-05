#!/usr/bin/env python3
"""AgentSploit open-source MCP survey harness.

Reproducible, execution-free survey of published MCP tool definitions:

  collect  -> shallow-clone repos in servers.yaml, statically extract tool
              definitions from their Python source (AST, no code run), write
              one JSON manifest per server into manifests/
  scan     -> build an agentsploit MCPInventory from each manifest and run the
              real inventory checks (tool_poisoning, tool_shadowing,
              unsafe_tool_args, prompt_disclosure). No network, no live server.
  aggregate-> roll the findings up into the numbers + table the disclosure
              post needs (out/aggregate.md).
  selftest -> run collect+scan against the bundled vulnerable fixture and
              assert the pipeline detects what it should. Proves the core.

Safety: this reads PUBLIC source code only. It never connects to a third-party
host and never executes a scanned server. See README.md.
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]  # ~/Tools/agentsploit (HERE = <repo>/launch/scan_harness)
REPOS_DIR = HERE / "repos"
MANIFESTS_DIR = HERE / "manifests"
OUT_DIR = HERE / "out"
FINDINGS_DIR = OUT_DIR / "findings"

# --------------------------------------------------------------------------- deps

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required. Run inside the agentsploit venv:  "
             f"{REPO_ROOT}/.venv/bin/python {__file__} ...")

# Import agentsploit's REAL checks. Prefer the installed package; fall back to
# the repo's src/ so the harness works from a fresh checkout too.
try:
    from agentsploit.core.finding import Severity  # noqa: F401
    from agentsploit.modules.mcp.client import MCPInventory
    from agentsploit.modules.mcp.checks.tool_poisoning import ToolPoisoningCheck
    from agentsploit.modules.mcp.checks.tool_shadowing import ToolShadowingCheck
    from agentsploit.modules.mcp.checks.unsafe_tool_args import UnsafeToolArgsCheck
    from agentsploit.modules.mcp.checks.prompt_disclosure import PromptDisclosureCheck
except ImportError:
    sys.path.insert(0, str(REPO_ROOT / "src"))
    from agentsploit.core.finding import Severity  # noqa: F401
    from agentsploit.modules.mcp.client import MCPInventory
    from agentsploit.modules.mcp.checks.tool_poisoning import ToolPoisoningCheck
    from agentsploit.modules.mcp.checks.tool_shadowing import ToolShadowingCheck
    from agentsploit.modules.mcp.checks.unsafe_tool_args import UnsafeToolArgsCheck
    from agentsploit.modules.mcp.checks.prompt_disclosure import PromptDisclosureCheck

INVENTORY_CHECKS = [
    ToolPoisoningCheck,
    ToolShadowingCheck,
    UnsafeToolArgsCheck,
    PromptDisclosureCheck,
]

# ------------------------------------------------------------------- AST extract

_DECORATOR_TOOL_NAMES = {"tool"}  # matches @mcp.tool(), @server.tool(), @app.tool()
_ANNOTATION_TO_JSON = {
    "str": "string", "int": "integer", "float": "number",
    "bool": "boolean", "list": "array", "dict": "object",
}


EnumMap = dict[tuple[str, str], str]


def _build_enum_map(tree: ast.AST) -> EnumMap:
    """Map (ClassName, MEMBER) -> str value for same-file str/Enum classes.

    Handles the very common `class GitTools(str, Enum): STATUS = "git_status"`
    pattern so `name=GitTools.STATUS` resolves to the real tool name."""
    enums: EnumMap = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = {
            (b.id if isinstance(b, ast.Name) else getattr(b, "attr", ""))
            for b in node.bases
        }
        if not (base_names & {"Enum", "IntEnum", "StrEnum"}):
            continue
        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                    and isinstance(stmt.targets[0], ast.Name) \
                    and isinstance(stmt.value, ast.Constant) \
                    and isinstance(stmt.value.value, str):
                enums[(node.name, stmt.targets[0].id)] = stmt.value.value
    return enums


def _static_str(node: ast.expr | None, enums: EnumMap | None = None) -> str | None:
    """Best-effort constant-fold a string expression: literal, implicit concat,
    `"a" + "b"`, or a same-file `str`-Enum member. None if not statically a str."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _static_str(node.left, enums), _static_str(node.right, enums)
        if left is not None and right is not None:
            return left + right
    if enums and isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return enums.get((node.value.id, node.attr))
    return None


def _static_obj(node: ast.expr | None) -> Any:
    """literal_eval a node (for inputSchema dicts). None if not a literal."""
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return None


def _kw(call: ast.Call, name: str) -> ast.expr | None:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _decorator_is_tool(dec: ast.expr) -> bool:
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr in _DECORATOR_TOOL_NAMES
    if isinstance(target, ast.Name):
        return target.id in _DECORATOR_TOOL_NAMES
    return False


def _schema_from_signature(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, Any]:
    """Rough inputSchema from annotated params (skips self/ctx/context)."""
    props: dict[str, Any] = {}
    required: list[str] = []
    args = fn.args
    defaults_start = len(args.args) - len(args.defaults)
    for i, a in enumerate(args.args):
        if a.arg in {"self", "cls", "ctx", "context"}:
            continue
        jtype = None
        if isinstance(a.annotation, ast.Name):
            jtype = _ANNOTATION_TO_JSON.get(a.annotation.id)
        props[a.arg] = {"type": jtype} if jtype else {}
        if i < defaults_start:
            required.append(a.arg)
    schema: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


@dataclass
class ExtractedTool:
    name: str
    description: str
    inputSchema: dict[str, Any] = field(default_factory=dict)
    source: str = ""          # file:line
    method: str = ""          # how it was extracted
    schema_partial: bool = False


def _extract_from_tree(tree: ast.AST, relpath: str) -> list[ExtractedTool]:
    tools: list[ExtractedTool] = []
    enums = _build_enum_map(tree)

    # Pattern A: Tool(name=..., description=..., inputSchema=...) call literals.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            fname = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
            if fname != "Tool":
                continue
            name = _static_str(_kw(node, "name"), enums)
            if name is None:
                continue
            desc = _static_str(_kw(node, "description"), enums) or ""
            schema = _static_obj(_kw(node, "inputSchema"))
            if not isinstance(schema, dict):
                schema = _static_obj(_kw(node, "input_schema"))
            partial = not isinstance(schema, dict)
            tools.append(ExtractedTool(
                name=name, description=desc,
                inputSchema=schema if isinstance(schema, dict) else {},
                source=f"{relpath}:{node.lineno}", method="Tool()-literal",
                schema_partial=partial,
            ))

    # Pattern B: @mcp.tool()/@server.tool() decorated functions.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            tool_decs = [d for d in node.decorator_list if _decorator_is_tool(d)]
            if not tool_decs:
                continue
            dec = tool_decs[0]
            name = None
            desc = None
            if isinstance(dec, ast.Call):
                name = _static_str(_kw(dec, "name"), enums)
                desc = _static_str(_kw(dec, "description"), enums)
            name = name or node.name
            desc = desc if desc is not None else (ast.get_docstring(node) or "")
            tools.append(ExtractedTool(
                name=name, description=desc,
                inputSchema=_schema_from_signature(node),
                source=f"{relpath}:{node.lineno}", method="@tool-decorator",
                schema_partial=True,  # signature-derived schema is approximate
            ))

    # Pattern C: Tool.from_function(fn, name=..., description=...) factory calls
    # (e.g. clickhouse: mcp.add_tool(Tool.from_function(list_databases, name=...))).
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "from_function":
            name = _static_str(_kw(node, "name"), enums)
            if name is None:
                continue
            tools.append(ExtractedTool(
                name=name, description=_static_str(_kw(node, "description"), enums) or "",
                inputSchema={}, source=f"{relpath}:{node.lineno}",
                method="from_function()", schema_partial=True,
            ))

    # Pattern D: programmatic registration `x.tool(fn, name=...)` /
    # `x.add_tool(fn, name=...)` (e.g. qdrant: self.tool(find_foo, name=...)).
    # Requires a positional arg + literal name= so it can't collide with the
    # zero-positional `@x.tool()` decorator (Pattern B) or a from_function arg.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in {"tool", "add_tool"} and node.args:
            first = node.args[0]
            if isinstance(first, ast.Call):  # e.g. add_tool(Tool.from_function(...)) -> Pattern C/A
                continue
            name = _static_str(_kw(node, "name"), enums)
            if name is None:
                continue
            tools.append(ExtractedTool(
                name=name, description=_static_str(_kw(node, "description"), enums) or "",
                inputSchema={}, source=f"{relpath}:{node.lineno}",
                method=f".{node.func.attr}()-call", schema_partial=True,
            ))

    # De-dupe by (name, source).
    seen: set[tuple[str, str]] = set()
    unique: list[ExtractedTool] = []
    for t in tools:
        key = (t.name, t.source)
        if key not in seen:
            seen.add(key)
            unique.append(t)
    return unique


def extract_tools_from_path(root: Path) -> tuple[list[ExtractedTool], list[str]]:
    """Walk a checkout and extract tools from every parseable .py file."""
    tools: list[ExtractedTool] = []
    parse_errors: list[str] = []
    skip = {".venv", "venv", "node_modules", "build", "dist", "tests", "test"}
    for py in sorted(root.rglob("*.py")):
        rel = py.relative_to(root)
        if set(rel.parts[:-1]) & skip:  # only dirs *below* the root, not the root itself
            continue
        try:
            src = py.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(src, filename=str(py))
        except (SyntaxError, ValueError) as e:
            parse_errors.append(f"{rel}: {e}")
            continue
        tools.extend(_extract_from_tree(tree, str(rel)))
    return tools, parse_errors

# ------------------------------------------------------------------------ collect


def _clone(repo: str, ref: str | None, dest: Path, refresh: bool) -> None:
    if dest.exists() and not refresh:
        return
    if dest.exists():
        subprocess.run(["rm", "-rf", str(dest)], check=True)
    cmd = ["git", "clone", "--depth", "1"]
    if ref:
        cmd += ["--branch", ref]
    cmd += [repo, str(dest)]
    subprocess.run(cmd, check=True, capture_output=True, text=True)


def cmd_collect(args: argparse.Namespace) -> int:
    servers = yaml.safe_load((HERE / args.servers).read_text())["servers"]
    MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)
    REPOS_DIR.mkdir(parents=True, exist_ok=True)

    for s in servers:
        name = s["name"]
        if "path" in s:                       # local checkout (e.g. self-test)
            root = (HERE / s["path"]).resolve() if not Path(s["path"]).is_absolute() \
                else Path(s["path"])
            repo = s.get("repo", f"local:{root}")
        else:
            root = REPOS_DIR / name
            repo = s["repo"]
            try:
                _clone(repo, s.get("ref"), root, args.refresh)
            except subprocess.CalledProcessError as e:
                print(f"  ! clone failed for {name}: {e.stderr.strip()[:200]}")
                continue
        subroot = root / s["subdir"] if s.get("subdir") else root
        tools, errors = extract_tools_from_path(subroot)
        manifest = {
            "name": name,
            "repo": repo,
            "ref": s.get("ref"),
            "subdir": s.get("subdir"),
            "tools": [asdict(t) for t in tools],
            "resources": [],
            "prompts": [],
            "extraction": {
                "tool_count": len(tools),
                "methods": dict(Counter(t.method for t in tools)),
                "schema_partial": sum(1 for t in tools if t.schema_partial),
                "parse_errors": len(errors),
            },
        }
        (MANIFESTS_DIR / f"{name}.json").write_text(json.dumps(manifest, indent=2))
        print(f"  {name}: {len(tools)} tools "
              f"({manifest['extraction']['methods']}), {len(errors)} parse errors")
    print(f"\nmanifests -> {MANIFESTS_DIR}")
    return 0

# --------------------------------------------------------------------------- scan


def _run_checks(inv: MCPInventory, target_uri: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for check_cls in INVENTORY_CHECKS:
        check = check_cls()
        for result in check.run(inv):
            findings.append({
                "check": check.NAME,
                "severity": result.severity.name if hasattr(result.severity, "name")
                            else str(result.severity),
                "title": result.title,
                "target_item": result.target_item,
                "evidence": result.evidence_extra or {},
                "target": target_uri,
            })
    return findings


def cmd_scan(args: argparse.Namespace) -> int:
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    manifests = sorted(MANIFESTS_DIR.glob("*.json"))
    if not manifests:
        print(f"No manifests in {MANIFESTS_DIR}. Run `collect` first.")
        return 1
    combined: list[dict[str, Any]] = []
    for mpath in manifests:
        m = json.loads(mpath.read_text())
        inv = MCPInventory(
            tools=m.get("tools", []),
            resources=m.get("resources", []),
            prompts=m.get("prompts", []),
        )
        target_uri = m.get("repo", m["name"])
        findings = _run_checks(inv, target_uri)
        for f in findings:
            f["server"] = m["name"]
        (FINDINGS_DIR / f"{m['name']}.json").write_text(json.dumps(findings, indent=2))
        combined.extend(findings)
        print(f"  {m['name']}: {len(m.get('tools', []))} tools -> {len(findings)} findings")
    (OUT_DIR / "findings.json").write_text(json.dumps(combined, indent=2))
    print(f"\ncombined findings -> {OUT_DIR / 'findings.json'}")
    return 0

# ---------------------------------------------------------------------- aggregate


def cmd_aggregate(args: argparse.Namespace) -> int:
    fpath = OUT_DIR / "findings.json"
    if not fpath.exists():
        print("No findings.json. Run `scan` first.")
        return 1
    findings = json.loads(fpath.read_text())
    manifests = {p.stem: json.loads(p.read_text()) for p in MANIFESTS_DIR.glob("*.json")}

    n_servers = len(manifests)
    n_tools = sum(m["extraction"]["tool_count"] for m in manifests.values())
    servers_with = defaultdict(set)   # check -> {server}
    counts = Counter()                # check -> finding count
    sev = Counter()                   # severity -> count
    for f in findings:
        servers_with[f["check"]].add(f["server"])
        counts[f["check"]] += 1
        sev[f["severity"]] += 1

    labels = {
        "tool_poisoning": "tool descriptions with prompt-injection patterns",
        "tool_shadowing": "tools shadowing a well-known name",
        "unsafe_tool_args": "tools with unconstrained dangerous args",
        "prompt_disclosure": "descriptions leaking prompts/secrets/paths",
    }
    lines = [
        "# MCP survey — aggregate results",
        "",
        f"- Servers surveyed: **{n_servers}**",
        f"- Tool definitions extracted: **{n_tools}**",
        f"- Servers with >=1 finding: **{len({f['server'] for f in findings})}**",
        "",
        "| Check | Servers affected | Total findings |",
        "|---|---|---|",
    ]
    for key, label in labels.items():
        lines.append(f"| `{key}` ({label}) | {len(servers_with[key])} | {counts[key]} |")
    lines += [
        "",
        "Severity breakdown: "
        + ", ".join(f"{k}={sev[k]}" for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                    if sev.get(k)) + ".",
        "",
        "> Numbers are candidate findings from pattern-based checks over statically",
        "> extracted tool definitions. Hand-review before publishing — some hits are",
        "> verbose-but-benign, and signature-derived schemas are approximate.",
        "",
        "## Per-server",
        "",
        "| Server | Tools | Findings |",
        "|---|---|---|",
    ]
    per_server = Counter(f["server"] for f in findings)
    for name, m in sorted(manifests.items()):
        lines.append(f"| {name} | {m['extraction']['tool_count']} | {per_server[name]} |")

    out = "\n".join(lines) + "\n"
    (OUT_DIR / "aggregate.md").write_text(out)
    print(out)
    print(f"aggregate -> {OUT_DIR / 'aggregate.md'}")
    return 0

# ------------------------------------------------------------------- surface/graph

# Heuristic capability classification. This is NOT a confirmed data-flow; it
# labels each tool by whether it *looks like* it ingests untrusted EXTERNAL
# content (source) and/or performs a high-impact action (sink). A server that
# exposes both in one context is where a source->sink chain can exist.
#
# Tightened for precision: source names are limited to external-content verbs
# (no bare get/list/search/read/open, which are mostly internal enumeration);
# arg matching is token-based (so `file` no longer matches `profile`).
_SOURCE_NAME = ("fetch", "crawl", "scrape", "download", "browse")
_SOURCE_ARG = ("url", "uri", "href", "endpoint", "webpage", "website",
               "path", "file", "filepath", "filename", "document")
_SINK_NAME = ("exec", "execute", "run", "shell", "command", "eval", "query", "sql",
              "cypher", "gremlin", "write", "create", "update", "delete", "remove",
              "insert", "send", "email", "commit", "push", "publish", "upload",
              "drop", "alter")
_SINK_ARG = ("command", "cmd", "query", "sql", "cypher", "code", "script",
             "body", "payload", "statement", "expression")

_re = __import__("re")
_CAMEL = _re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _tokens(s: str) -> set[str]:
    """camelCase- and delimiter-aware token set, so `executeQuery` -> {execute,
    query} but `dsql_read_docs` -> {dsql, read, docs} (no spurious `sql`)."""
    return {t for t in _re.split(r"[^A-Za-z0-9]+", _CAMEL.sub(" ", s).lower()) if t}


def _classify(tool: dict[str, Any]) -> dict[str, Any]:
    name_toks = _tokens(str(tool.get("name", "")))
    args = list((tool.get("inputSchema", {}) or {}).get("properties", {}).keys())
    src = [f"name~{k}" for k in _SOURCE_NAME if k in name_toks]
    snk = [f"name~{k}" for k in _SINK_NAME if k in name_toks]
    for a in args:
        toks = _tokens(a)
        if toks & set(_SOURCE_ARG):
            src.append(f"arg:{a}")
        if toks & set(_SINK_ARG):
            snk.append(f"arg:{a}")
    return {"source": bool(src), "sink": bool(snk),
            "source_why": src[:3], "sink_why": snk[:3]}


def cmd_surface(args: argparse.Namespace) -> int:
    manifests = {p.stem: json.loads(p.read_text())
                 for p in MANIFESTS_DIR.glob("*.json") if p.stem != "_fixture_vulnerable"}
    if not manifests:
        print("No manifests. Run `collect` first.")
        return 1
    rows = []
    tot_src = tot_snk = tot_both = tot_tools = 0
    coexist = 0
    bridges: list[tuple[str, str, list[str], list[str]]] = []  # single-tool source+sink
    for name, m in sorted(manifests.items()):
        s = k = b = 0
        for t in m.get("tools", []):
            c = _classify(t)
            s += c["source"]; k += c["sink"]
            if c["source"] and c["sink"]:
                b += 1
                bridges.append((name, str(t.get("name", "")),
                                c["source_why"], c["sink_why"]))
        n = len(m.get("tools", []))
        tot_tools += n; tot_src += s; tot_snk += k; tot_both += b
        both_present = s > 0 and k > 0
        coexist += both_present
        rows.append((name, n, s, k, b, both_present))

    lines = [
        "# MCP attack-surface classification",
        "",
        "Heuristic capability labels over statically extracted tools. **Not** a",
        "confirmed data-flow — a source and a sink coexisting in one server is a",
        "*potential* source->sink chain, not proof an agent will bridge them.",
        "",
        f"- Tools classified: **{tot_tools}**",
        f"- Untrusted-content **sources**: **{tot_src}**",
        f"- High-impact **sinks**: **{tot_snk}**",
        f"- Tools that are **both** (ingest AND act): **{tot_both}**",
        f"- Servers exposing **>=1 source AND >=1 sink** in one context: "
        f"**{coexist} / {len(manifests)}**",
        "",
        "| Server | Tools | Sources | Sinks | Both | Source+Sink coexist |",
        "|---|---|---|---|---|---|",
    ]
    for name, n, s, k, b, both in rows:
        lines.append(f"| {name} | {n} | {s} | {k} | {b} | {'YES' if both else '-'} |")

    lines += [
        "",
        "## Single-tool source->sink bridges",
        "",
        "Tools that BOTH ingest external content AND perform a high-impact action "
        "— the sharpest edge (a one-call bridge if the ingested content is "
        f"attacker-controlled). {len(bridges)} total; showing up to 40:",
        "",
        "| Server | Tool | source signal | sink signal |",
        "|---|---|---|---|",
    ]
    seen_rows: set[tuple[str, str, str, str]] = set()
    shown = 0
    for server, tool, swhy, kwhy in bridges:
        row = (server, tool, ", ".join(swhy), ", ".join(kwhy))
        if row in seen_rows:
            continue
        seen_rows.add(row)
        lines.append(f"| {row[0]} | `{row[1]}` | {row[2]} | {row[3]} |")
        shown += 1
        if shown >= 40:
            break
    out = "\n".join(lines) + "\n"
    (OUT_DIR / "surface.md").write_text(out)
    print(out)
    print(f"surface -> {OUT_DIR / 'surface.md'}")
    return 0


# ----------------------------------------------------------------------- selftest


def cmd_selftest(args: argparse.Namespace) -> int:
    """Prove the pipeline on the bundled vulnerable fixture."""
    fixture = REPO_ROOT / "tests/fixtures/vulnerable_mcp"
    tools, errors = extract_tools_from_path(fixture)
    names = {t.name for t in tools}
    inv = MCPInventory(tools=[asdict(t) for t in tools])
    findings = _run_checks(inv, "fixture")
    by_check = defaultdict(set)
    for f in findings:
        by_check[f["check"]].add(f["target_item"])

    checks = [
        ("extracted 4 tools", names == {"read_secret_file", "read_file",
                                        "run_command", "safe_add"}),
        ("tool_poisoning fires on read_secret_file",
         any("read_secret_file" in x for x in by_check["tool_poisoning"])),
        ("prompt_disclosure fires (leaked secret/prompt)",
         len(by_check["prompt_disclosure"]) >= 1),
        ("tool_shadowing fires on read_file",
         any("read_file" in x for x in by_check["tool_shadowing"])),
        ("unsafe_tool_args fires on run_command",
         any("run_command" in x for x in by_check["unsafe_tool_args"])),
        ("safe_add triggers nothing",
         not any("safe_add" in x for s in by_check.values() for x in s)),
        ("no parse errors", not errors),
    ]
    ok = True
    for label, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
        ok = ok and passed
    print(f"\nSELF-TEST {'PASSED' if ok else 'FAILED'} "
          f"({len(tools)} tools, {len(findings)} findings)")
    return 0 if ok else 1

# --------------------------------------------------------------------------- main


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="clone repos + extract tool manifests")
    c.add_argument("--servers", default="servers.yaml")
    c.add_argument("--refresh", action="store_true", help="re-clone even if cached")
    c.set_defaults(func=cmd_collect)

    s = sub.add_parser("scan", help="run agentsploit checks over manifests")
    s.set_defaults(func=cmd_scan)

    a = sub.add_parser("aggregate", help="roll findings into the disclosure table")
    a.set_defaults(func=cmd_aggregate)

    g = sub.add_parser("surface", help="classify tools as sources/sinks (attack surface)")
    g.set_defaults(func=cmd_surface)

    t = sub.add_parser("selftest", help="validate pipeline on bundled fixture")
    t.set_defaults(func=cmd_selftest)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
