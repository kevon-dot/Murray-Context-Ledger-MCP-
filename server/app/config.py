"""Application settings.

Settings are read from the environment (a local `.env` is honored for
development). Instantiating `Settings` with anything missing raises a pydantic
ValidationError, so the app fails fast at startup rather than at first use.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Auth0 tenant, e.g. "my-tenant.us.auth0.com" (no scheme, no trailing slash).
    auth0_domain: str
    # The `aud` claim we accept. Clients send the Auth0 ID token (see
    # docs/AUTH.md), whose audience is the Auth0 application client ID.
    auth0_audience: str
    # The Auth0 API identifier for the ledger (MCP path). Access tokens minted
    # for this audience are also accepted; set it to the API you create in
    # Auth0 for the MCP integration (docs/CONNECT.md). Optional so a P0-style
    # deployment without the MCP layer still boots.
    auth0_api_audience: str | None = None

    supabase_url: str
    # Anon (publishable) key: request-path access, combined with a caller-scoped
    # JWT so Postgres RLS enforces isolation.
    supabase_anon_key: str
    # Service-role key: BYPASSES RLS. Pipeline jobs only — never the request path.
    supabase_service_role_key: str
    # HS256 secret the Supabase stack validates Data-API JWTs with. The MCP
    # layer exchanges a *verified* Auth0 access token for a short-lived,
    # per-user DB token signed with this secret (see docs/AUTH.md — Auth0
    # access tokens cannot carry the `role` claim, and the MCP spec forbids
    # passing inbound tokens through to upstream services). Per-user RLS is
    # still enforced by Postgres; this secret cannot bypass it.
    supabase_jwt_secret: str

    # Canonical public URL of the MCP endpoint (RFC 9728 `resource`). Override
    # when exposing through a tunnel or in production, e.g.
    # https://ledger.example.com/mcp
    resource_server_url: str = "http://127.0.0.1:8080/mcp"

    @property
    def accepted_audiences(self) -> list[str]:
        audiences = [self.auth0_audience]
        if self.auth0_api_audience:
            audiences.append(self.auth0_api_audience)
        return audiences

    @property
    def auth0_issuer(self) -> str:
        # Auth0 issuers always carry a trailing slash.
        return f"https://{self.auth0_domain}/"

    @property
    def auth0_jwks_url(self) -> str:
        return f"https://{self.auth0_domain}/.well-known/jwks.json"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
