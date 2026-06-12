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

    supabase_url: str
    # Anon (publishable) key: request-path access, combined with the caller's
    # JWT so Postgres RLS enforces isolation.
    supabase_anon_key: str
    # Service-role key: BYPASSES RLS. Pipeline jobs only — never the request path.
    supabase_service_role_key: str

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
