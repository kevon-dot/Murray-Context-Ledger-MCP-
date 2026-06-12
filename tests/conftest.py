"""Shared test configuration.

Defaults target a local Supabase stack and use the Supabase CLI's public
local-development credentials (identical on every machine, valid only for
local stacks — nothing secret here). CI overrides them from
`supabase status` after `supabase start`; any other deployment must inject
its own values via the environment.

The env defaults are applied at import time, before any `app.*` module reads
its settings.
"""

import os
import time
import uuid
from dataclasses import dataclass

import jwt

# The Supabase CLI's well-known local development credentials. The two API
# keys are HS256 JWTs signed with the default local JWT secret; Kong matches
# them by exact string, so they are hardcoded rather than re-minted.
LOCAL_SUPABASE_URL = "http://127.0.0.1:54321"
LOCAL_JWT_SECRET = "super-secret-jwt-token-with-at-least-32-characters-long"
LOCAL_ANON_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9."
    "CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0"
)
LOCAL_SERVICE_ROLE_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0."
    "EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU"
)

_ENV_DEFAULTS = {
    "SUPABASE_URL": LOCAL_SUPABASE_URL,
    "SUPABASE_ANON_KEY": LOCAL_ANON_KEY,
    "SUPABASE_SERVICE_ROLE_KEY": LOCAL_SERVICE_ROLE_KEY,
    "SUPABASE_JWT_SECRET": LOCAL_JWT_SECRET,
    # Dummy Auth0 tenant for the auth unit tests (the JWKS is stubbed there;
    # no network calls are made). The RLS suite does not involve Auth0 at all.
    "AUTH0_DOMAIN": "murray-test.us.auth0.com",
    "AUTH0_AUDIENCE": "murray-ledger-test-client",
}
for _key, _value in _ENV_DEFAULTS.items():
    os.environ.setdefault(_key, _value)


@dataclass(frozen=True)
class TestUser:
    """A simulated Auth0 principal for RLS tests."""

    sub: str
    email: str

    __test__ = False  # not a pytest collectable


def mint_user_jwt(user: TestUser, ttl_seconds: int = 600) -> str:
    """Sign a JWT the local Supabase stack accepts for `user`.

    Local stacks validate JWTs with the project's HS256 secret, so tests can
    mint their own. The claims mirror what production receives from Auth0
    third-party auth: `sub` carries the Auth0 subject and `role` is
    `authenticated`, which is what PostgREST uses to pick the Postgres role
    that RLS policies are written against. See docs/AUTH.md.
    """
    now = int(time.time())
    claims = {
        "sub": user.sub,
        "email": user.email,
        "role": "authenticated",
        "aud": "authenticated",
        "iss": "ledger-test-harness",
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(claims, os.environ["SUPABASE_JWT_SECRET"], algorithm="HS256")


def make_test_user(label: str) -> TestUser:
    """Unique Auth0-shaped principal per test run, so runs never collide."""
    unique = uuid.uuid4().hex[:12]
    return TestUser(sub=f"auth0|itest-{label}-{unique}", email=f"{label}-{unique}@example.com")
