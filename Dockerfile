# Production image for the Murray Context Ledger MCP resource server.
#
# uv installs dependencies into /app/.venv, which we then run directly (no uv at
# runtime). The app is configured entirely from environment variables (see
# .env.example / docs/DEPLOY.md) and fails fast at startup if any are missing.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# 1) Dependencies first, for layer caching. This repo is an application monorepo
#    (package = false), so there is no project to install — only the locked
#    runtime deps, minus the dev group (pytest/ruff are test-only).
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# 2) Application code (server runtime + the intentionally-empty pipeline pkg).
COPY server ./server
COPY pipeline ./pipeline

# Run out of the synced venv; app.* resolves from server/.
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/server"

EXPOSE 8080
# Honor $PORT when a platform injects one (Cloud Run, Railway, Fly.io, …).
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8080}"]
