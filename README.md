# Murray Context Ledger

Hosted, user-owned memory layer that AI clients (Claude, ChatGPT, Cursor) read/write
via MCP. **P0** laid the foundations (Supabase schema with row-level security, Auth0
JWT verification, the cross-user isolation test gate). **P1** adds the MCP protocol
layer: an OAuth 2.1-protected Streamable HTTP endpoint at `/mcp` with six read
tools, connectable from Claude and ChatGPT as a custom connector (docs/CONNECT.md).

## Quickstart

```sh
uv sync                          # Python 3.12 env + dependencies
make stack                       # local Postgres + PostgREST; applies supabase/migrations/
make test                        # auth + RLS isolation gate + MCP suites — must be green
cp .env.example .env             # fill in Auth0 values to exercise real auth
make dev                         # API + MCP server on :8080 (/healthz, /mcp)
make tunnel                      # HTTPS tunnel + the strings to paste into Claude/ChatGPT
```

No Docker available? `./scripts/no_docker_stack.sh` stands up an equivalent data
plane (native Postgres + the PostgREST static binary + a `/rest/v1` proxy) and the
test suite runs unchanged against it.

## Layout

| Path | Purpose |
| --- | --- |
| `server/app/` | FastAPI app: `auth.py` (Auth0 JWT verification), `mcp_server.py` (MCP tools + OAuth resource server), `db.py` (caller-scoped/service Supabase clients), `config.py` (fail-fast settings), `main.py` (mounting, `/healthz`, RFC 9728 metadata) |
| `supabase/migrations/` | All schema changes, numbered SQL only — never the dashboard |
| `pipeline/` | Empty package; extraction lands in P5 |
| `tests/` | `test_rls_isolation.py` is the P0 gate; `test_mcp_*` re-prove it through the MCP path |
| `docs/AUTH.md` | Auth end to end: P0 request path + P1 OAuth 2.1 resource server |
| `docs/CONNECT.md` | Step-by-step: Auth0 tenant setup, Claude + ChatGPT connector forms |

## Ground rules

- Request-path database access always uses the caller's JWT through the anon client,
  so **Postgres RLS enforces isolation** — not application discipline. The
  service-role key is for pipeline jobs only.
- `user_id` is `text` holding the Auth0 `sub` claim; Supabase `auth.users` is unused.
- The RLS tests mutate data and therefore refuse to run against a non-local
  `SUPABASE_URL` (override: `LEDGER_TESTS_ALLOW_REMOTE=1`).
- CI (`.github/workflows/ci.yml`) runs ruff plus both suites against a fresh
  `supabase start`; a red isolation suite is the entire point of P0.
