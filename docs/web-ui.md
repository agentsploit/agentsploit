# Web UI

`agentsploit serve` starts a local web server that lets you browse
engagement output (sessions, findings, permission graphs, traces, attack
paths) AND drive new scans/verifies, all in a browser.

v1.5 shipped the read-only browser. v1.6 adds:

- bearer-token auth
- POST endpoints for triggering scans and verifies
- a live SSE event stream that the UI subscribes to (so findings appear
  in real time as a scan progresses)
- a path explorer page backed by a new `paths.json` mapper artifact

## Quick start

```bash
# 1. Scaffold an engagement (or use an existing one)
agentsploit init my-engagement/
cd my-engagement/

# 2. Run scans from the CLI or from the UI
agentsploit serve --auth authorization.yaml
# -> http://127.0.0.1:8800
# Token printed on startup. Paste into the /login page.
```

## Layout

```
/                          -> Sessions table (live-updating)
/sessions/<session-id>     -> Findings, Graph, Paths tabs
/jobs                      -> Background jobs + "Run scan" form
/login                     -> Token entry
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

## Auth

`agentsploit serve` (v1.6+) requires a bearer token by default. On
first start it mints a token, prints it to the console, and persists it
at `~/.config/agentsploit/web-token` (chmod 600). Subsequent starts
reuse the same value.

Send it as:

```
Authorization: Bearer <token>
```

For the SSE endpoint (`/api/events`), the browser `EventSource` API
cannot set headers; the server therefore also accepts `?token=<token>`
in the query string.

To disable auth entirely (single-operator local-only use):

```bash
agentsploit serve --no-auth
```

`--no-auth` refuses to bind to anything except loopback. Off-localhost
binds *with* auth print a warning but proceed.

## Triggering scans from the UI

Two prerequisites:

1. Start with an active authorization context. Either `--auth <file>`
   or `--training`. Without one, the UI is read-only.
2. The requested target must be in scope per that authorization.
   Out-of-scope POSTs return 403.

```bash
agentsploit serve \
    --engagement-dir engagements/ \
    --auth engagements/authorization.yaml
```

Then in the UI: **Sessions -> Run scan -> enter target URI -> Submit**.
Findings appear in the new session's detail page live as they're
discovered.

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
| `GET /api/sessions/{id}/paths` | (v1.6) Attack paths from `paths.json` |
| `POST /api/jobs/scan` | (v1.6) Queue an MCP scan job |
| `POST /api/jobs/verify` | (v1.6) Queue a path-verify job |
| `POST /api/jobs/{id}/cancel` | (v1.6) Cancel a running job |
| `GET /api/jobs` | (v1.6) List jobs (newest first) |
| `GET /api/jobs/{id}` | (v1.6) One job's status |
| `GET /api/events` | (v1.6) SSE stream of broker events |

### SSE event types

| Event | Payload | Notes |
| --- | --- | --- |
| `job.queued` | `{kind, label}` | Fires immediately on POST. |
| `job.started` | `{kind, label}` | Runner picked up the job. |
| `job.finding` | `{finding: ...}` | One finding per emit. |
| `job.finished` | `{finding_count}` | Normal completion. |
| `job.failed` | `{error}` | Exception during run. |
| `job.cancelled` | `{}` | Operator cancelled. |
