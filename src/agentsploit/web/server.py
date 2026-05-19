"""FastAPI app construction + uvicorn entry point for `agentsploit serve`.

v1.6 introduces auth (bearer token, see web/auth.py), write endpoints
(see api.submit_scan_job / submit_verify_job), and an in-process job
runner. The server is still localhost-only by default.
"""

from __future__ import annotations

import warnings
from importlib import resources
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from agentsploit.core import Authorization
from agentsploit.utils.logging import get_logger
from agentsploit.version import __version__
from agentsploit.web import api, auth

log = get_logger(__name__)


def build_app(
    engagement_dir: Path,
    *,
    authorization: Authorization | None = None,
    auth_enabled: bool = True,
    token: str | None = None,
) -> FastAPI:
    """Construct the FastAPI app.

    `authorization` gates the write endpoints (scan/verify); it's optional
    so a UI started in read-only mode still works against existing
    engagements.

    `auth_enabled=False` disables the bearer-token check entirely (dev mode).
    """
    api.configure(engagement_dir, authorization=authorization)
    auth.configure(token=token, enabled=auth_enabled)

    app = FastAPI(
        title="AgentSploit",
        version=__version__,
        description="Web UI for browsing AgentSploit engagement output.",
    )
    app.include_router(api.router)

    frontend_dir = _frontend_dir()
    if frontend_dir is not None and frontend_dir.exists():
        # Serve hashed static assets under /assets/* and the index.html for
        # any other path (so the SPA's client-side router can take over).
        assets_dir = frontend_dir / "assets"
        if assets_dir.exists():
            app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

        index_path = frontend_dir / "index.html"

        @app.get("/")
        @app.get("/{full_path:path}", include_in_schema=False)
        def _spa(full_path: str = "") -> Response:
            # API requests fall through to the router (mounted before this);
            # any other unmatched path serves the SPA shell.
            if full_path.startswith("api/"):
                return Response(status_code=404)
            if index_path.exists():
                return FileResponse(index_path)
            return Response(
                content=_unbuilt_frontend_message(),
                media_type="text/html",
                status_code=200,
            )

    else:
        # Bundle not present (developer running from source without `npm run build`).
        @app.get("/")
        def _root() -> Response:
            return Response(
                content=_unbuilt_frontend_message(),
                media_type="text/html",
                status_code=200,
            )

    return app


def serve(
    *,
    host: str = "127.0.0.1",
    port: int = 8800,
    engagement_dir: Path | None = None,
    authorization: Authorization | None = None,
    auth_enabled: bool = True,
    token: str | None = None,
    reload: bool = False,
) -> None:
    """Start the web UI server.

    Bind safety
    -----------
    Defaults to localhost. Binding off-loopback is refused outright if
    auth is disabled (`auth_enabled=False`), because engagement artifacts
    may contain canaries / tool args / finding evidence. With auth on,
    a non-loopback bind only prints a warning - the operator presumably
    knows what they're doing.
    """
    is_loopback = host in ("127.0.0.1", "localhost", "::1")
    if not is_loopback:
        if not auth_enabled:
            raise RuntimeError(
                f"Refusing to bind to {host!r} with --no-auth. "
                f"The UI surfaces engagement artifacts and write endpoints "
                f"that would be exposed without authentication."
            )
        warnings.warn(
            f"Binding the AgentSploit web UI to {host!r}. The UI exposes "
            f"engagement artifacts and write endpoints. Make sure you're "
            f"inside an already-trust-bounded network.",
            stacklevel=2,
        )

    engagement_dir = engagement_dir or Path.cwd() / "engagements"
    app = build_app(
        engagement_dir,
        authorization=authorization,
        auth_enabled=auth_enabled,
        token=token,
    )
    uvicorn.run(app, host=host, port=port, log_level="info")


# ----------------------------------------------------------- helpers


def _frontend_dir() -> Path | None:
    """Locate the packaged frontend bundle, both in dev (source tree) and
    in installed-wheel mode."""
    try:
        # importlib.resources.files() gives a Traversable that works both
        # in the source tree and installed-from-wheel modes.
        traversable = resources.files("agentsploit.web") / "frontend"
        path = Path(str(traversable))
        return path
    except (ModuleNotFoundError, FileNotFoundError):  # pragma: no cover
        return None


_UNBUILT_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>AgentSploit</title></head>
<body style="font-family:system-ui,sans-serif;max-width:42rem;
margin:3rem auto;padding:1rem;line-height:1.5">
<h1>AgentSploit</h1>
<p>The web UI bundle is not built. You're running from source.</p>
<pre style="background:#f4f4f4;padding:1rem;border-radius:4px">
cd ui/
npm install
npm run build
# then re-run `agentsploit serve`
</pre>
<p>The REST API is available right now at <code>/api/sessions</code> et al.
See <a href="/docs">/docs</a> for OpenAPI documentation.</p>
</body></html>
"""


def _unbuilt_frontend_message() -> str:
    return _UNBUILT_HTML
