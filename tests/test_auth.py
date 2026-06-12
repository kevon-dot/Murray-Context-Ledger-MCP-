"""Auth0 JWT verification dependency tests.

No network involved: the tenant JWKS lookup is stubbed with a locally
generated RSA keypair, so these tests exercise everything `app.auth` does
after key retrieval — signature, algorithm, audience, issuer, expiry, and
required-claim enforcement.
"""

import time
from types import SimpleNamespace
from typing import Annotated

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import app.auth as app_auth
from app.config import get_settings

SUB = "auth0|user-12345"
EMAIL = "person@example.com"


@pytest.fixture(scope="module")
def rsa_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture()
def api(rsa_private_key, monkeypatch):
    """A FastAPI app with one route guarded by the real `current_user` dependency.

    Only the JWKS fetch is stubbed: any token, regardless of `kid`, is checked
    against our test public key — exactly what PyJWKClient would return after
    fetching the tenant JWKS.
    """
    public_key = rsa_private_key.public_key()

    def fake_jwks_client(jwks_url: str):
        return SimpleNamespace(
            get_signing_key_from_jwt=lambda token: SimpleNamespace(key=public_key)
        )

    monkeypatch.setattr(app_auth, "_jwks_client", fake_jwks_client)

    test_app = FastAPI()

    @test_app.get("/whoami")
    async def whoami(user: Annotated[dict, Depends(app_auth.current_user)]):
        return user

    return TestClient(test_app)


def make_token(
    signing_key,
    *,
    algorithm: str = "RS256",
    drop: set[str] | None = None,
    **claim_overrides,
):
    settings = get_settings()
    now = int(time.time())
    claims = {
        "sub": SUB,
        "email": EMAIL,
        "iss": settings.auth0_issuer,
        "aud": settings.auth0_audience,
        "iat": now,
        "exp": now + 600,
    }
    claims.update(claim_overrides)
    for claim in drop or set():
        del claims[claim]
    headers = {"kid": "test-key"} if algorithm != "none" else None
    return pyjwt.encode(claims, signing_key, algorithm=algorithm, headers=headers)


def test_valid_auth0_jwt_passes(api, rsa_private_key):
    token = make_token(rsa_private_key)
    response = api.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"sub": SUB, "email": EMAIL}


def test_email_is_optional(api, rsa_private_key):
    token = make_token(rsa_private_key, drop={"email"})
    response = api.get("/whoami", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"sub": SUB, "email": None}


def test_expired_token_rejected(api, rsa_private_key):
    now = int(time.time())
    token = make_token(rsa_private_key, iat=now - 700, exp=now - 100)
    assert api.get("/whoami", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_wrong_audience_rejected(api, rsa_private_key):
    token = make_token(rsa_private_key, aud="some-other-app")
    assert api.get("/whoami", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_wrong_issuer_rejected(api, rsa_private_key):
    token = make_token(rsa_private_key, iss="https://evil-tenant.example.com/")
    assert api.get("/whoami", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_unsigned_token_rejected(api):
    token = make_token(None, algorithm="none")
    assert api.get("/whoami", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_token_signed_with_wrong_key_rejected(api):
    interloper_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = make_token(interloper_key)
    assert api.get("/whoami", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_token_missing_sub_rejected(api, rsa_private_key):
    token = make_token(rsa_private_key, drop={"sub"})
    assert api.get("/whoami", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_garbage_token_rejected(api):
    assert api.get("/whoami", headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401


def test_missing_authorization_header_rejected(api):
    assert api.get("/whoami").status_code == 401
