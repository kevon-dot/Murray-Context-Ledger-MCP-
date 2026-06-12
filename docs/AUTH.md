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
| `AUTH0_AUDIENCE` | Accepted `aud` — the Auth0 application client ID (ID tokens) |
| `SUPABASE_URL` | Supabase project / local stack URL |
| `SUPABASE_ANON_KEY` | Publishable key; request path, RLS enforced |
| `SUPABASE_SERVICE_ROLE_KEY` | BYPASSRLS key; pipeline jobs only |
| `SUPABASE_JWT_SECRET` | Tests only: local stack's HS256 secret for minting user JWTs |

`server/app/config.py` loads these via pydantic-settings and raises at startup
if any are missing — the app refuses to boot half-configured.
