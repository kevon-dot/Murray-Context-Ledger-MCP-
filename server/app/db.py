"""Supabase client factories.

Two clients, two trust models:

* ``user_client(jwt)`` — anon key plus the caller's JWT. PostgREST validates
  the JWT, assumes the ``authenticated`` Postgres role, and RLS policies
  compare ``auth.jwt()->>'sub'`` to each row's ``user_id``. ALL request-path
  database access goes through this — isolation is enforced by Postgres, not
  by application discipline.

* ``service_client()`` — service-role key, which BYPASSES RLS. Reserved for
  pipeline jobs (imports, extraction, retention). Never call it while
  handling a user request.
"""

from supabase import Client, create_client
from supabase.lib.client_options import SyncClientOptions

from app.config import get_settings


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
