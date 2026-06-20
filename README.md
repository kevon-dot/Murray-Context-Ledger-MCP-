# Murray Context Ledger

Hosted, multi-tenant **team memory** that AI clients (Murray, Claude, ChatGPT) read
and write via MCP. **P0** laid the foundations (Supabase schema with row-level
security, Auth0 JWT verification, the isolation test gate). **P1** added the MCP
protocol layer: an OAuth 2.1-protected Streamable HTTP endpoint at `/mcp`.
**P2–P6** turned the single-user, read-only ledger into a written, idempotent team
memory:

- **Tenancy is user-within-org.** Every fact keeps an owner (`user_id`, the Auth0
  `sub`) **and** gains an `org_id`. Org members share reads; the audit trail stays
  per-person. Isolation moved from the per-user to the per-org boundary but still
  lives entirely in Postgres — enforced by org-member RLS using the function
  `public.user_org_ids()` (security invoker, stable, pinned `search_path=''`,
  schema-qualified; reads the caller's own memberships via RLS so it can only
  ever return the caller's own orgs). The `service_role` never touches the
  request path.
- **Writes**: `remember_facts` (batch, per-item, idempotent via a client-supplied
  `dedupe_key`, auto-promote to `active` at `confidence >= 0.9`) and
  `supersede_fact` (retire-and-replace via `superseded_by`). Every write is audited;
  `connector_source` attributes the writer (Murray vs Claude vs ChatGPT).
- **Review**: facts below the auto-promote threshold wait in `pending_review`;
  owner/office triage them with `list_pending_facts` / `promote_fact` / `reject_fact`.
- **Provisioning** is service-role only (no authenticated path): the
  `scripts/ledger_admin.py` CLI creates orgs, grants seats, and registers
  connectors. Deploy with the `Dockerfile`; full runbook in `docs/DEPLOY.md`.
- **Roles**: `owner`/`rep`/`office` see appropriately different scope slices within
  an org (`ROLE_SCOPES`), and a single connector seat can be revoked without
  affecting the rest of the org. Role scoping narrows *within* an org; it is never
  the thing that keeps orgs apart.
- **No NLP in this repo.** Speech → intent → structured facts happens in the Murray
  app; the Ledger only validates-and-stores already-typed facts. The wire shape is
  pinned in [docs/MURRAY_CONTRACT.md](docs/MURRAY_CONTRACT.md).

**v1 assumes each user belongs to exactly one org**; a caller in zero or multiple
orgs is rejected (the multi-org seam is marked `TODO(multi-org)`).

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
| `server/app/` | FastAPI app: `auth.py` (Auth0 JWT verification), `mcp_server.py` (MCP read+write+review tools, membership resolution, OAuth resource server), `schemas.py` (`FactInput` write validation), `db.py` (caller-scoped/service Supabase clients), `admin.py` (operator provisioning + seat admin), `config.py` (fail-fast settings), `main.py` (mounting, `/healthz`, RFC 9728 metadata) |
| `scripts/ledger_admin.py` | Operator CLI (service-role) for provisioning orgs/members/connectors and revoking seats — see `docs/DEPLOY.md` |
| `Dockerfile` | Production image (`uvicorn app.main:app`); configured entirely from env |
| `supabase/migrations/` | All schema changes, numbered SQL only — never the dashboard. `0003` = org tenancy + RLS re-key + `public.user_org_ids()`; `0004` = write path (`dedupe_key`, `connector_source`) |
| `pipeline/` | Empty package — voice/NLP extraction lives in the Murray app, never here |
| `tests/` | `test_rls_isolation` + `test_org_isolation` are the isolation gates; `test_membership_resolution`, `test_write_path`, `test_murray_contract`, `test_role_governance`, `test_admin_provisioning`, `test_review_lifecycle` gate the rest; `test_mcp_*` re-prove behavior through the MCP path |
| `docs/AUTH.md` | Auth end to end: request path, OAuth 2.1 resource server, org tenancy |
| `docs/MURRAY_CONTRACT.md` | The authoritative Murray → Ledger wire contract (Contract v1) |
| `docs/DEPLOY.md` | Production runbook: Supabase + Auth0 + server + provisioning |
| `docs/CONNECT.md` | Step-by-step: Auth0 tenant setup, Claude + ChatGPT connector forms |

## Ground rules

- Request-path database access always uses the caller's JWT through the anon client,
  so **Postgres RLS enforces isolation** — not application discipline. The
  service-role key is for provisioning/pipeline jobs only and never on the request
  path; membership is resolved by the `public.user_org_ids()` function, not a
  service-role read.
- `user_id` is `text` holding the Auth0 `sub` claim; Supabase `auth.users` is unused.
  RLS reads identity via `auth.jwt()->>'sub'`, never `auth.uid()`.
- Orgs and memberships are **service-role provisioned** in v1 (no authenticated
  insert). Tokens carry only `sub`; the org is resolved in Postgres from memberships.
- Writes go through the caller-scoped client too — `FactInput` is shape validation,
  RLS is the enforcement. Facts are never partially committed; idempotent re-sends
  (same `org_id` + `dedupe_key`) are no-ops.
- The RLS/write tests mutate data and therefore refuse to run against a non-local
  `SUPABASE_URL` (override: `LEDGER_TESTS_ALLOW_REMOTE=1`).
- CI (`.github/workflows/ci.yml`) runs ruff plus the full suite against a fresh
  `supabase start` (migrations `0001`–`0004`); a red isolation suite is the entire
  point — provably intact cross-org isolation is what makes the team memory safe.
