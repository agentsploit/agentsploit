# Web UI

`agentsploit serve` starts a local web server that lets you browse
engagement output (sessions, findings, permission graphs, traces) in
a browser instead of grepping JSON.

The UI is **read-only as of v1.5**. Triggering scans/verifies from the
UI lands with the live-engagement dashboard in v1.6.

## Quick start

```bash
# 1. Run any scan/map/verify/poison command that writes to engagements/
agentsploit init my-engagement/
cd my-engagement/
agentsploit scan mcp-injection stdio://./vuln-mcp --auth auth.yaml

# 2. Browse the results
agentsploit serve
# -> http://127.0.0.1:8800
```

## Layout

```
/                          -> Sessions table
/sessions/<session-id>     -> Findings + Graph tabs
```

### Findings tab

- Severity filter pills (all / critical / high / medium / low / info).
- Click a row to open a detail aside with title, target, description,
  remediation, tags, references, and raw evidence JSON.

### Graph tab

- Cytoscape-rendered permission graph (when the session contains
  `permission_graph.json`, written by `agentsploit map build`).
- Nodes coloured by classification (source / pivot / sink) and labelled
  with privilege level (READ / ACT / EGRESS / MUTATE / EXEC).
- Click a node to open a detail aside with classification reasons and
  the originating MCP server URI.

## Bind safety

The server defaults to `127.0.0.1:8800`. It refuses to silently bind to
anything else: passing `--host 0.0.0.0` works but prints a loud warning
because:

- The UI surfaces engagement artifacts that may contain canaries, tool
  call arguments, and finding evidence — i.e. raw data extracted from
  attacker probes against real systems.
- v1.5 has **no authentication**. If you bind off-localhost, do it
  inside an already-trust-bounded network.

Authentication lands in v1.6.

## Engagement directory

`serve` scans `./engagements/` by default. Override with
`--engagement-dir <path>` (alias `-d`):

```bash
agentsploit serve -d /var/agentsploit/engagements
```

The on-disk layout is `<engagement-dir>/<engagement-id>/<session-id>/`,
which is what every `agentsploit` write command produces — there's no
separate index file to maintain.

## Dev workflow

The Python wheel ships a pre-built React bundle inside
`agentsploit.web.frontend`. If you're working on the UI itself, run
Vite + FastAPI side-by-side:

```bash
# Terminal 1: API
agentsploit serve   # binds :8800

# Terminal 2: Vite dev server with HMR
cd ui/
npm install
npm run dev         # binds :5173, proxies /api to :8800
```

When done, rebuild the bundle so the wheel picks up the changes:

```bash
cd ui/
npm run build       # writes to ../src/agentsploit/web/frontend/
```

## API

The REST API is mounted under `/api`. OpenAPI docs at `/docs`.

| Endpoint | Returns |
| --- | --- |
| `GET /api/health` | Server status + version + engagement_dir |
| `GET /api/sessions` | All sessions, newest first |
| `GET /api/sessions/{id}` | One session's summary |
| `GET /api/sessions/{id}/findings` | Findings sorted by severity desc |
| `GET /api/sessions/{id}/graph` | Permission graph JSON verbatim |
| `GET /api/sessions/{id}/traces` | Trace artefact listing |
| `GET /api/sessions/{id}/traces/{filename}` | One trace JSON |

All read-only. Write endpoints (trigger scan, trigger verify) land in
v1.6.
