.PHONY: dev tunnel stack stack-no-docker db-reset test lint

dev: ## Run the API + MCP server on :8080 (reload on change)
	uv run uvicorn --app-dir server app.main:app --host 0.0.0.0 --port 8080 --reload

tunnel: ## Expose :8080 over HTTPS for connector testing; prints the strings to paste into Claude/ChatGPT
	./scripts/tunnel.sh

stack: ## Local Supabase data plane (Docker) with migrations applied
	supabase start
	supabase db reset

stack-no-docker: ## Same data plane without Docker (native Postgres + PostgREST)
	./scripts/no_docker_stack.sh

db-reset: ## Re-apply all migrations to the running local stack
	supabase db reset

test: ## Full suite: auth, RLS isolation gate, MCP protocol + tools
	uv run pytest -v

lint:
	uv run ruff check .
	uv run ruff format --check .
