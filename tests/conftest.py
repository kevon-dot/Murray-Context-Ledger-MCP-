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
    # Ledger API identifier: the audience carried by MCP access tokens.
    "AUTH0_API_AUDIENCE": "https://ledger.test/mcp",
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


def mint_access_token(private_key, sub: str, azp: str, ttl_seconds: int = 600) -> str:
    """Sign an Auth0-shaped *access token* for the MCP path.

    Pairs with a stubbed JWKS (the matching public key), mirroring what Auth0
    issues after the OAuth flow: RS256, ledger API audience, `azp` carrying
    the OAuth client id, space-separated `scope`.
    """
    now = int(time.time())
    claims = {
        "sub": sub,
        "azp": azp,
        "scope": "openid profile email",
        "iss": f"https://{os.environ['AUTH0_DOMAIN']}/",
        "aud": os.environ["AUTH0_API_AUDIENCE"],
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test-key"})


MCP_PROTOCOL_VERSION = "2025-06-18"


def mcp_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def mcp_rpc(
    client, method: str, params: dict | None = None, token: str | None = None, id_: int = 1
):
    """POST one JSON-RPC request to /mcp and return the httpx response."""
    body = {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}
    return client.post("/mcp", json=body, headers=mcp_headers(token))


def mcp_call_tool(client, token: str, name: str, arguments: dict | None = None) -> dict:
    """Call a tool and return the JSON-RPC `result` (CallToolResult shape)."""
    response = mcp_rpc(client, "tools/call", {"name": name, "arguments": arguments or {}}, token)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "error" not in payload, payload
    return payload["result"]
