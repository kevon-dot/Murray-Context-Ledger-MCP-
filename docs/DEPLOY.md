# Deploying the Context Ledger

This is the end-to-end runbook for standing up a real (hosted) Ledger: the
Supabase data plane, the Auth0 authorization server, the FastAPI + MCP resource
server, and the first org. It assumes the rehab is merged (migrations
`0001`–`0004`, the write/review tools, and the provisioning CLI).

Architecture recap: the Ledger is an **OAuth 2.1 resource server** (we issue no
tokens). **Auth0** is the authorization server; **Supabase** (Postgres + RLS) is
the data plane and the *only* place isolation is enforced. The server holds the
service-role key but never uses it on the request path — see `docs/AUTH.md`.

> Steps that must happen in the Supabase/Auth0 consoles are called out as
> **[console]** — those are yours to click; everything else is scripted.

---

## 0. Prerequisites

- A Supabase project (hosted) — **fresh/empty**, see §1.
- An Auth0 tenant (RS256).
- The Supabase CLI (`supabase`) and `uv`, or Docker, on the deploy machine.
- This repo checked out.

## 1. Supabase data plane

1. **[console]** Create a Supabase project. From **Project Settings → API**, copy
   the **Project URL**, the **anon** key, and the **service_role** key. From
   **Project Settings → API → JWT** (legacy/“JWT secret”), copy the **JWT
   secret** — the MCP layer signs short-lived Data-API tokens with it
   (`docs/AUTH.md`), so the project's legacy HS256 secret must remain enabled.

2. Apply the migrations to the project (they must land on **empty** data tables —
   `0003` has a guard that aborts if `facts/clients/audit_log/jobs` already hold
   rows):

   ```sh
   supabase link --project-ref <your-project-ref>
   supabase db push        # applies supabase/migrations/0001 … 0004 in order
   ```

   There is no `seed.sql`, so the tables come up empty and the guard passes.

3. Sanity-check the security-critical objects landed:

   ```sql
   -- public.user_org_ids exists, security INVOKER, stable:
   select proname, prosecdef, provolatile from pg_proc
    where proname = 'user_org_ids' and pronamespace = 'public'::regnamespace;
   -- every data table is org-member RLS + FORCE:
   select relname, relrowsecurity, relforcerowsecurity from pg_class
    where relname in ('facts','clients','audit_log','jobs','orgs','memberships');
   ```

## 2. Auth0 authorization server

Follow **`docs/CONNECT.md` Part 1** for the click-path; the essentials:

1. **[console]** Create an **API** in Auth0 whose identifier is your ledger
   audience (e.g. `https://ledger.yourdomain.com/mcp`). Set it as the tenant's
   **Default Audience** (Auth0 ignores RFC 8707 `resource`; the default audience
   is how MCP access tokens come out bound to the ledger — see the deviation log
   in `docs/AUTH.md`).
2. **[console]** Add a **post-login Action** that stamps the role claim Supabase
   switches on — on the **ID token**, because Auth0 strips non-namespaced custom
   claims from *access* tokens:

   ```javascript
   exports.onExecutePostLogin = async (event, api) => {
     api.idToken.setCustomClaim('role', 'authenticated')
   }
   ```
3. **[console]** Confirm the tenant signs with **RS256** (`app/auth.py` accepts
   RS256 only).

Optionally enable Auth0 as a Supabase **[console]** third-party provider
(Dashboard → Authentication → Third-Party Auth, or `supabase/config.toml`'s
`[auth.third_party.auth0]` block) if you want PostgREST to accept Auth0 tokens
directly; the MCP path does not require it (it mints its own DB tokens).

## 3. Configure + run the server

Set the environment (see `.env.example` for the full annotated list):

| Variable | Value |
|---|---|
| `AUTH0_DOMAIN` | your tenant, e.g. `murray.us.auth0.com` |
| `AUTH0_AUDIENCE` | the Auth0 **application** client id (ID-token path) |
| `AUTH0_API_AUDIENCE` | the ledger API identifier from §2 |
| `RESOURCE_SERVER_URL` | the **public** URL of `/mcp`, e.g. `https://ledger.yourdomain.com/mcp` |
| `SUPABASE_URL` / `SUPABASE_ANON_KEY` / `SUPABASE_SERVICE_ROLE_KEY` / `SUPABASE_JWT_SECRET` | from §1 |

`RESOURCE_SERVER_URL` **must** be the externally reachable `/mcp` URL — it is
advertised as the RFC 9728 `resource` and used to build fact URLs.

**Docker:**

```sh
docker build -t murray-ledger .
docker run --rm -p 8080:8080 --env-file .env murray-ledger
```

The image runs `uvicorn app.main:app` and honors `$PORT` if your platform injects
one (Cloud Run, Railway, Fly.io, …). For higher throughput run multiple
replicas behind the load balancer (the MCP transport is stateless), or add
`--workers N` to the `CMD`. Liveness probe: `GET /healthz` (unauthenticated).

**Without Docker:** `uv sync --no-dev && PYTHONPATH=server uv run uvicorn app.main:app --host 0.0.0.0 --port 8080`.

## 4. Provision the first org (and Murray's connector)

Provisioning is **service-role only in v1** — there is no authenticated path to
create orgs/seats. Run the CLI from a checkout with the **production** env
loaded (it uses `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY`). Each command
prints JSON.

```sh
# 1) The org.
uv run python scripts/ledger_admin.py create-org --name "Henderson Roofing"
#    -> {"id": "<ORG_ID>", ...}

# 2) People. user ids are Auth0 subjects (the `sub` claim, e.g. "auth0|abc123").
uv run python scripts/ledger_admin.py add-member --org <ORG_ID> --user 'auth0|owner'  --role owner
uv run python scripts/ledger_admin.py add-member --org <ORG_ID> --user 'auth0|office' --role office
uv run python scripts/ledger_admin.py add-member --org <ORG_ID> --user 'auth0|rep1'   --role rep

# 3) Murray's connector seat. --client-id is Murray's OAuth client id (the `azp`
#    its access tokens carry); reps share this seat, so it is keyed per org and
#    attributed as murray_app. Grant the field-sales scope set.
uv run python scripts/ledger_admin.py register-connector \
    --org <ORG_ID> --client-id <MURRAY_OAUTH_CLIENT_ID> \
    --source murray_app --registered-by 'auth0|owner' \
    --scopes account,personal,work
```

`v1 assumes one org per user` — add each person to exactly one org. A user in
zero or multiple orgs is rejected at request time.

If a connector connected before you registered it (so its `connector_source` is
null), backfill it:

```sh
uv run python scripts/ledger_admin.py set-connector-source --org <ORG_ID> --client-id <CLIENT_ID> --source claude
```

## 5. Connect clients

Point Murray / Claude / ChatGPT at `https://<host>/mcp` and run the OAuth flow —
**`docs/CONNECT.md` Part 2** has the exact connector forms. On first call a
client auto-registers its seat (default scopes `{personal, work}`); pre-register
via §4 when you want the scope set and `connector_source` right from the start.

## 6. Smoke test

```sh
curl -fsS https://<host>/healthz                      # {"status":"ok"}
curl -fsS https://<host>/.well-known/oauth-protected-resource   # RFC 9728 metadata
```

Then, with a real access token (from the OAuth flow), call `ping` over MCP — it
returns `ledger ok — N active facts for this user.` A rep can `remember_facts`;
an owner/office user can `list_pending_facts` and `promote_fact`.

## 7. Day-2 operations

- **Revoke a seat** (lost device, offboarding a connector) — affects only that
  seat, not the org's other connectors:
  ```sh
  uv run python scripts/ledger_admin.py revoke-seat --org <ORG_ID> --client-id <CLIENT_ID>
  uv run python scripts/ledger_admin.py reinstate-seat --org <ORG_ID> --client-id <CLIENT_ID>
  ```
- **Triage field notes** — facts written below `confidence 0.9` wait in
  `pending_review`; owner/office promote/reject them via the MCP review tools.
- **Audit** — every read and write appends to `audit_log`, attributable to the
  person (`user_id`) and the connector (`client_id → connector_source`).
- **Backups / PITR** — rely on Supabase's managed backups; all state is in Postgres.

## What this runbook can't do for you

The **[console]** steps (creating the Supabase project, the Auth0 API/Action,
DNS/TLS for your host, and the actual hosting platform deploy) are manual by
nature. Everything in code — migrations, the server image, and provisioning — is
scripted above. Re-verify the Auth0 and Supabase console UIs against their
current docs on first setup; the exact menu paths drift.
