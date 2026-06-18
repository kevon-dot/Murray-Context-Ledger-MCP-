# Authentication, end to end

Auth0 is the identity provider. Supabase never issues our user identities;
it is configured for **third-party auth** so Auth0-issued JWTs are honored by
PostgREST and usable inside row-level-security policies via `auth.jwt()`.
`user_id` columns are `text` holding the Auth0 `sub` claim verbatim —
Supabase's `auth.users` is not used anywhere.

## The path of a request

```
AI client ── Bearer <Auth0 JWT> ──> FastAPI (server/app)
    1. app/auth.py  verifies the JWT (RS256, tenant JWKS, aud+iss+exp) → {sub, email}
    2. app/db.py    user_client(jwt): anon key as `apikey`, the SAME user JWT
                    as `Authorization` → PostgREST
    3. PostgREST    re-validates the JWT, assumes the Postgres role from its
                    `role` claim (`authenticated`), exposes claims as
                    request.jwt.claims
    4. Postgres     RLS policies compare auth.jwt()->>'sub' to each row's
                    user_id — isolation is enforced HERE, not in app code
```

The service-role key (`service_client()`) has `BYPASSRLS` and exists for
pipeline jobs only (P5+). It never serves request-path traffic; nothing in the
request path can even reach it by construction, because handlers are only given
the caller's JWT.

## Which Auth0 token? The ID token (verified against current Supabase docs)

The Supabase third-party-auth guide for Auth0 was re-checked while building P0
(June 2026), and one integration detail matters a lot:

> Supabase requires the literal `role` claim in the JWT. **Auth0 silently
> strips non-namespaced custom claims from access tokens**, so
> `api.accessToken.setCustomClaim('role', …)` does not work. Use
> `api.idToken.setCustomClaim` and pass the **ID token** to Supabase.

So the contract is:

1. Clients authenticate against Auth0 and send the **ID token** as the bearer
   token, both to our API and (through us) to Supabase.
2. An Auth0 **post-login Action** stamps the claim Supabase switches roles on:

   ```javascript
   exports.onExecutePostLogin = async (event, api) => {
     api.idToken.setCustomClaim('role', 'authenticated')
   }
   ```

3. Because the bearer is an ID token, its `aud` is the Auth0 **application
   client ID** — that is what `AUTH0_AUDIENCE` must be set to.
4. The Auth0 tenant must sign with **RS256**. Supabase third-party auth does
   not support HS256 or PS256 tenants, and `app/auth.py` accepts RS256 only.

If a later phase moves MCP clients to proper OAuth access tokens with a custom
API audience, both `AUTH0_AUDIENCE` and the Action need to change together —
revisit this section then.

## Enabling third-party auth on a Supabase project

* **Hosted project:** Dashboard → Authentication → Third-Party Auth → add the
  Auth0 integration with the tenant ID (and region if applicable). This is an
  auth *configuration*, not schema — the migrations-only rule doesn't apply.
* **Local stack:** `supabase/config.toml` already carries the block; flip it on
  to exercise a real tenant locally:

  ```toml
  [auth.third_party.auth0]
  enabled = true
  tenant = "<tenant-id>"
  tenant_region = "<region>"
  ```

Server-side verification in `app/auth.py` is independent of Supabase: PyJWT
fetches the tenant JWKS (`https://AUTH0_DOMAIN/.well-known/jwks.json`) once and
caches it in-process, then enforces signature, `exp`, `aud == AUTH0_AUDIENCE`,
`iss == https://AUTH0_DOMAIN/`, and presence of `sub`. Every failure mode is a
plain 401; there is no custom crypto.

## How the tests mint JWTs (and why that's faithful)

The RLS suite needs two users with valid tokens, without a round-trip to
Auth0. Local Supabase stacks validate Data-API JWTs against the project's
**HS256 JWT secret** (default
`super-secret-jwt-token-with-at-least-32-characters-long`), so
`tests/conftest.py:mint_user_jwt` signs tokens with that secret carrying
exactly the claims production would see from Auth0 third-party auth:

```json
{"sub": "auth0|itest-a-…", "email": "…", "role": "authenticated",
 "aud": "authenticated", "iat": …, "exp": …}
```

PostgREST's behavior downstream of signature verification is identical for an
HS256-local token and an RS256-Auth0 token: pick the Postgres role from
`role`, publish claims to `auth.jwt()`. That is precisely the machinery the
isolation tests must prove, so the test tokens exercise the real enforcement
path. (`tests/test_auth.py` covers the RS256/JWKS verification half with a
stubbed JWKS — no network.)

The unauthenticated case uses the anon key alone, which maps to the `anon`
Postgres role: it holds no grants on ledger tables and there are no `anon`
policies, so it can read nothing.

CI re-exports `SUPABASE_*` values from `supabase status` after `supabase
start`, so the suite always runs against what actually started.

## P1 — the MCP path: OAuth 2.1 resource server

P1 adds a second authenticated surface: the MCP endpoint at `/mcp`
(Streamable HTTP, stateless, JSON responses). The ledger is an **OAuth 2.1
resource server** and Auth0 remains the only authorization server — we issue
no tokens and run no login UI. Implemented against the current MCP
authorization spec (revision **2025-11-25**, read from the spec source while
building):

```
Claude / ChatGPT ── POST /mcp (no token) ──> 401
    WWW-Authenticate: Bearer ..., resource_metadata=
        "https://<host>/.well-known/oauth-protected-resource/mcp"
    └─> client fetches that metadata → authorization_servers = [Auth0 tenant]
        → discovers Auth0 (RFC 8414 / OIDC), registers itself (RFC 7591 DCR),
          runs OAuth 2.1 + PKCE, returns with an access token
Claude / ChatGPT ── POST /mcp (Bearer access token) ──> tools
```

Spec conformance points:

* **RFC 9728 Protected Resource Metadata** served at both forms the spec
  lists: path-inserted `/.well-known/oauth-protected-resource/mcp` (primary,
  served by the MCP app) and root `/.well-known/oauth-protected-resource`
  (fallback alias). `resource` comes from `RESOURCE_SERVER_URL` — set it to
  the public URL when tunneling or deploying.
* **401 challenges** carry `resource_metadata` in `WWW-Authenticate` (the
  spec's primary discovery mechanism).
* **Token validation**: every MCP request is verified by the same
  `app/auth.py` code path as P0 — RS256 against the tenant JWKS (cached),
  issuer, expiry — with the audience check extended to accept the **ledger
  API identifier** (`AUTH0_API_AUDIENCE`) alongside the P0 client-ID
  audience. Tokens not minted for this resource are rejected (the spec's
  audience-binding MUST).
* **Client identity**: the OAuth client ID arrives in the access token's
  `azp` claim and keys the per-user `clients` registry row (created on first
  contact with default scopes `{personal, work}`; revoked rows reject calls
  with instructions to re-enable in the dashboard). If `azp` were ever
  absent, a stable hash of the token's issuer+audience stands in.

### Spec deviation log (P1)

* **Auth0 does not implement RFC 8707 `resource`.** MCP clients MUST send the
  `resource` parameter; Auth0 ignores it and uses its proprietary `audience`
  parameter instead. Bridge: set the tenant **Default Audience** to the
  ledger API identifier (docs/CONNECT.md Part 1.3) so tokens still arrive
  audience-bound to the ledger. The server's own audience validation is what
  enforces the spec's token-binding requirement.
* **DB access token exchange.** The spec's security best practices forbid
  **token passthrough**, and Auth0 access tokens cannot carry the literal
  `role` claim PostgREST needs (stripped from access tokens, see P0 notes).
  So the MCP layer never forwards the inbound token: after verification it
  mints a short-lived (120 s) HS256 Data-API JWT for the *same verified
  `sub`* signed with `SUPABASE_JWT_SECRET`, and uses that through the anon
  client. Postgres RLS still enforces per-user isolation — the minted token
  carries one `sub` and cannot bypass anything; the service role remains
  unused on the request path. This refines P0's "caller's JWT" rule: the
  caller's *identity* flows to Postgres; the caller's *credential* does not
  transit beyond verification. (Hosted Supabase: requires the project's
  legacy HS256 JWT secret to remain enabled.)
* **Doc verification limits of this build environment.** The MCP spec was
  verified from its source repository; Auth0's DCR docs and OpenAI's
  connector docs were unreachable (network policy), so the Auth0 steps in
  CONNECT.md follow the documented tenant flags as last known, and the
  ChatGPT `search`/`fetch` result shapes were taken from OpenAI's official
  deep-research MCP sample server (cookbook). Re-verify both consoles' UI
  paths on first real connect.

## P2–P6 — multi-tenant team memory (org tenancy + write path)

The ledger is now **user-within-org**: every fact keeps its owner (`user_id`)
and gains an `org_id`; org members share reads, audit stays per-person.
Isolation moved from the per-user to the per-org boundary, but the enforcement
model is unchanged — it is still Postgres RLS on the caller's JWT, never
application code.

### The membership function (the isolation pivot)

`auth.user_org_ids()` (migration `0003`) is the single most security-sensitive
object in the repo. Every RLS policy on `facts`/`clients`/`audit_log`/`jobs` is
re-keyed from `user_id = sub` to `org_id = any ((select auth.user_org_ids())::uuid[])`.
Its security properties are load-bearing and must not be relaxed:

* **`security definer`** — it reads `public.memberships` under its owner
  (`postgres`/`BYPASSRLS`), so it works even with `force row level security` on
  that table, and **no broad membership SELECT policy is needed**.
* **filters on `auth.jwt()->>'sub'` internally** — so despite bypassing RLS, it
  can *only ever return the calling user's orgs*. It cannot be coerced to return
  another user's orgs. `tests/test_org_isolation.py` proves this directly.
* **`stable` + `set search_path = ''` + schema-qualified** — the empty
  search_path means nothing can be shadowed; `stable` lets the planner cache it
  as an `InitPlan` evaluated once per query (the `::uuid[]` cast forces ANY's
  array form so it both typechecks and stays cached).
* **`service_role` stays off the request path.** Membership is resolved by this
  function, not by a service-role read at request entry. `public.my_org_ids()` is
  a thin `security invoker` passthrough so a caller can observe their own org set
  over the Data API (PostgREST exposes only `public`); it grants nothing the
  `memberships_select_self` / `orgs_select_member` policies don't already.

### Request path, with org resolution

The P0 diagram still holds; `_begin` adds one step after minting the caller's DB
token: it reads the caller's memberships through the **caller-scoped** client
(`memberships_select_self` returns exactly their rows — no service role) and
binds a single `(org_id, role)` into `ToolContext`. v1 **fails closed**: zero or
more-than-one memberships are rejected (the multi-org case is marked
`TODO(multi-org)` — the function already returns an array, so the RLS layer needs
no change when that lands). `_finish` stamps `org_id` on every audit row.

### Writes

`remember_facts` and `supersede_fact` insert through the caller-scoped client, so
the org-member `WITH CHECK` (`org_id` in the caller's orgs **and** `user_id =
sub`) is the real enforcement; `FactInput` (`server/app/schemas.py`) is only shape
validation. Idempotency is a partial unique index on `(org_id, dedupe_key)` — a
re-send is swallowed as a no-op. `connector_source` on the `clients` row attributes
each write (Murray vs Claude vs ChatGPT); the audit trail names the writer via
`audit_log.client_id → clients.connector_source`.

### Roles and seats

`ROLE_SCOPES` narrows what a seat *sees* within its org (owner unrestricted,
office → `{account, work}`, rep → `{account, personal}`). This is a **product
decision, not a security boundary** — org isolation is the hard boundary in
Postgres and is unaffected by role scoping. Seat revocation
(`clients.status = 'revoked'`, keyed per `(org_id, oauth_client_id)`) is an
operator/service-role action (`server/app/admin.py`), never an authenticated MCP
tool, and affects only the one seat.

## Workaround log

* **No workaround needed for third-party auth itself**, but note the ID-token
  requirement above — older examples that put `role` on the access token no
  longer work (Auth0 strips it).
* **This build environment couldn't run `supabase start`** (Docker image
  registry blocked), so `scripts/no_docker_stack.sh` stands up the equivalent
  data plane — native Postgres, Supabase's role model
  (`scripts/supabase_compat_roles.sql`), the verbatim `auth.jwt()` definition
  (`scripts/supabase_compat_auth.sql`), the real PostgREST binary, and a
  `/rest/v1` prefix proxy standing in for Kong. The same env defaults and the
  same test suite pass against either stack; CI uses the real CLI stack.

## Configuration reference

| Variable | Meaning |
| --- | --- |
| `AUTH0_DOMAIN` | Tenant domain; issuer is `https://$AUTH0_DOMAIN/`, JWKS is fetched from it |
| `AUTH0_AUDIENCE` | Accepted `aud` — the Auth0 application client ID (ID tokens, P0 path) |
| `AUTH0_API_AUDIENCE` | Accepted `aud` — the Auth0 API identifier for the ledger (access tokens, MCP path) |
| `RESOURCE_SERVER_URL` | Canonical public URL of `/mcp`; advertised as the RFC 9728 `resource` |
| `SUPABASE_URL` | Supabase project / local stack URL |
| `SUPABASE_ANON_KEY` | Publishable key; request path, RLS enforced |
| `SUPABASE_SERVICE_ROLE_KEY` | BYPASSRLS key; pipeline jobs only |
| `SUPABASE_JWT_SECRET` | HS256 Data-API secret: the MCP layer mints short-lived per-user DB tokens with it; tests mint user JWTs with it |

`server/app/config.py` loads these via pydantic-settings and raises at startup
if any are missing — the app refuses to boot half-configured.
