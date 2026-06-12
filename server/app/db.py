"""Supabase client factories.

Two clients, two trust models:

* ``user_client(jwt)`` — anon key plus a caller-scoped JWT. PostgREST
  validates the JWT, assumes the ``authenticated`` Postgres role, and RLS
  policies compare ``auth.jwt()->>'sub'`` to each row's ``user_id``. ALL
  request-path database access goes through this — isolation is enforced by
  Postgres, not by application discipline.

* ``service_client()`` — service-role key, which BYPASSES RLS. Reserved for
  pipeline jobs (imports, extraction, retention). Never call it while
  handling a user request.

The MCP path obtains its caller-scoped JWT via ``client_for_subject``: the
inbound Auth0 access token is verified first, then exchanged for a short-lived
DB token carrying the same ``sub``. The inbound token itself is never
forwarded (MCP security best practices forbid token passthrough, and Auth0
access tokens cannot carry the ``role`` claim PostgREST switches on — see
docs/AUTH.md). The minted token is per-user: it cannot read another user's
rows, and it cannot bypass RLS.
"""

import time

import jwt
from supabase import Client, create_client
from supabase.lib.client_options import SyncClientOptions

from app.config import get_settings

DB_TOKEN_TTL_SECONDS = 120


def user_client(access_token: str) -> Client:
    """RLS-enforced client acting as the calling user."""
    settings = get_settings()
    options = SyncClientOptions(
        headers={"Authorization": f"Bearer {access_token}"},
        auto_refresh_token=False,
        persist_session=False,
    )
    return create_client(settings.supabase_url, settings.supabase_anon_key, options)


def service_client() -> Client:
    """RLS-bypassing client. Pipeline jobs ONLY — never the request path."""
    settings = get_settings()
    options = SyncClientOptions(auto_refresh_token=False, persist_session=False)
    return create_client(settings.supabase_url, settings.supabase_service_role_key, options)


def mint_db_token(sub: str, email: str | None = None) -> str:
    """Short-lived Data-API JWT for an already-verified caller.

    Carries exactly the claims PostgREST needs: the caller's ``sub`` (what RLS
    policies match on) and ``role: authenticated`` (what PostgREST switches
    Postgres roles on). Call this only with a ``sub`` taken from a token that
    `app.auth.verify_token` accepted.
    """
    settings = get_settings()
    now = int(time.time())
    claims: dict[str, object] = {
        "sub": sub,
        "role": "authenticated",
        "aud": "authenticated",
        "iss": "murray-ledger-server",
        "iat": now,
        "exp": now + DB_TOKEN_TTL_SECONDS,
    }
    if email:
        claims["email"] = email
    return jwt.encode(claims, settings.supabase_jwt_secret, algorithm="HS256")


def client_for_subject(sub: str, email: str | None = None) -> Client:
    """RLS-enforced client for a verified subject (the MCP request path)."""
    return user_client(mint_db_token(sub, email))
