# Murray Context Ledger

Hosted, user-owned memory layer that AI clients (Claude, ChatGPT, Cursor) read/write
via MCP. **P0 = foundations only**: FastAPI scaffold, Supabase schema with row-level
security, Auth0 JWT verification, and a test suite that proves cross-user isolation.
The MCP protocol layer lands in P1.

## Quickstart

```sh
uv sync                          # Python 3.12 env + dependencies
supabase start                   # local Postgres + PostgREST; applies supabase/migrations/
uv run pytest                    # auth suite + the RLS isolation gate — must be green
cp .env.example .env             # then fill in Auth0 values to exercise real auth
uv run uvicorn --app-dir server app.main:app --reload    # serves GET /healthz
```

No Docker available? `./scripts/no_docker_stack.sh` stands up an equivalent data
plane (native Postgres + the PostgREST static binary + a `/rest/v1` proxy) and the
test suite runs unchanged against it.

## Layout

| Path | Purpose |
| --- | --- |
| `server/app/` | FastAPI app: `auth.py` (Auth0 JWT dependency), `db.py` (user/service Supabase clients), `config.py` (fail-fast settings), `main.py` (`/healthz`) |
| `supabase/migrations/` | All schema changes, numbered SQL only — never the dashboard |
| `pipeline/` | Empty package; extraction lands in P5 |
| `tests/` | `test_rls_isolation.py` is the P0 acceptance gate |
| `docs/AUTH.md` | How auth works end to end, including the test-JWT mechanism |

## Ground rules

- Request-path database access always uses the caller's JWT through the anon client,
  so **Postgres RLS enforces isolation** — not application discipline. The
  service-role key is for pipeline jobs only.
- `user_id` is `text` holding the Auth0 `sub` claim; Supabase `auth.users` is unused.
- The RLS tests mutate data and therefore refuse to run against a non-local
  `SUPABASE_URL` (override: `LEDGER_TESTS_ALLOW_REMOTE=1`).
- CI (`.github/workflows/ci.yml`) runs ruff plus both suites against a fresh
  `supabase start`; a red isolation suite is the entire point of P0.
