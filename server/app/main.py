"""FastAPI application factory.

Routes:
  * ``/healthz`` — liveness, unauthenticated.
  * ``/mcp`` — the MCP Streamable HTTP endpoint (stateless, JSON responses),
    served by the mounted MCP Starlette app, bearer-protected.
  * ``/.well-known/oauth-protected-resource/mcp`` — RFC 9728 metadata
    (path-inserted form), served by the same mounted app.
  * ``/.well-known/oauth-protected-resource`` — root-form alias, served here.

The MCP sub-app is mounted at the root so its routes keep their canonical
paths; FastAPI's own routes are matched first. Its session manager only runs
inside this app's lifespan — mounted sub-app lifespans do not run on their
own.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import get_settings
from app.mcp_server import build_mcp


def create_app() -> FastAPI:
    # Fail fast: refuse to boot at all if required configuration is missing.
    settings = get_settings()

    mcp = build_mcp()
    mcp_asgi_app = mcp.streamable_http_app()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        async with mcp.session_manager.run():
            yield

    app = FastAPI(title="Murray Context Ledger", version="0.2.0", lifespan=lifespan)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/oauth-protected-resource")
    async def protected_resource_metadata_root() -> dict[str, object]:
        """RFC 9728 root-form metadata; clients that skip the path-inserted
        form (served by the MCP app) fall back to this."""
        return {
            "resource": settings.resource_server_url,
            "authorization_servers": [settings.auth0_issuer],
            "bearer_methods_supported": ["header"],
        }

    app.mount("/", mcp_asgi_app)

    return app


app = create_app()
