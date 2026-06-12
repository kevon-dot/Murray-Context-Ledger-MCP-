"""Auth0 JWT verification.

`current_user` is the FastAPI dependency for every authenticated route. It
validates the bearer token as an RS256 JWT issued by our Auth0 tenant:
signature against the tenant JWKS (fetched once and cached in-process),
plus audience, issuer, and expiry from configuration. On success it returns
``{"sub": ..., "email": ...}``; every failure mode is a plain 401.

Verification is delegated to PyJWT — no custom crypto here.
"""

from functools import lru_cache
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient
from jwt.exceptions import InvalidTokenError, PyJWKClientError

from app.config import Settings, get_settings

ALLOWED_ALGORITHMS = ["RS256"]

# auto_error=False so a missing/malformed Authorization header yields our own
# 401 instead of FastAPI's default 403.
_bearer_scheme = HTTPBearer(auto_error=False)


@lru_cache(maxsize=4)
def _jwks_client(jwks_url: str) -> PyJWKClient:
    # One client per URL for the process lifetime; PyJWKClient additionally
    # caches the fetched signing keys, so the JWKS is not re-fetched per request.
    return PyJWKClient(jwks_url, cache_keys=True, max_cached_keys=16, lifespan=3600)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail="Invalid or missing credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def verify_token(token: str, settings: Settings) -> dict[str, Any]:
    """Validate an Auth0 RS256 JWT and return its claims; raise 401 otherwise.

    Accepts either configured audience: the Auth0 application client ID (ID
    tokens, P0 request path) or the ledger API identifier (access tokens, MCP
    path). PyJWT treats an audience list as "any of these".
    """
    try:
        signing_key = _jwks_client(settings.auth0_jwks_url).get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=ALLOWED_ALGORITHMS,
            audience=settings.accepted_audiences,
            issuer=settings.auth0_issuer,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except (InvalidTokenError, PyJWKClientError) as exc:
        # Covers expired tokens, wrong audience/issuer, unsigned or non-RS256
        # tokens, garbage input, and unknown signing keys.
        raise _unauthorized() from exc


async def current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    """FastAPI dependency: the verified caller as ``{"sub": ..., "email": ...}``."""
    if credentials is None:
        raise _unauthorized()
    claims = verify_token(credentials.credentials, settings)
    return {"sub": claims["sub"], "email": claims.get("email")}
