"""FastAPI application factory.

P0 exposes only /healthz. The MCP protocol layer lands in P1 and will mount
its routes here, with `app.auth.current_user` guarding every authenticated
endpoint and `app.db.user_client` carrying the caller's JWT to Postgres.
"""

from fastapi import FastAPI

from app.config import get_settings


def create_app() -> FastAPI:
    # Fail fast: refuse to boot at all if required configuration is missing.
    get_settings()

    app = FastAPI(title="Murray Context Ledger", version="0.1.0")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
