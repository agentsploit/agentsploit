"""AgentSploit web UI: FastAPI backend + React frontend bundle.

Serves the engagement-output directory through a REST API:
  GET /api/sessions
  GET /api/sessions/{sid}
  GET /api/sessions/{sid}/findings
  GET /api/sessions/{sid}/graph
  GET /api/sessions/{sid}/traces/{tid}

The React frontend (pre-built bundle under `frontend/`) consumes those
endpoints and renders the sessions list, permission graph, and findings
table. Built and shipped in the wheel.
"""

from agentsploit.web.server import build_app, serve

__all__ = ["build_app", "serve"]
