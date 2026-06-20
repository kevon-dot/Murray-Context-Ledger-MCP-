"""Membership resolution on the request path (P3 gate).

The DB already enforces org isolation; this proves the app binds the caller's
single org + role into ToolContext and fails closed otherwise:

  * exactly one membership  -> bound; reads see only that org.
  * zero memberships        -> rejected (NO_ORG_MESSAGE), fail closed.
  * two memberships         -> rejected (MULTI_ORG_MESSAGE), v1 single-org rule.
  * _resolve_client         -> keyed (org_id, oauth_client_id); reused, not duped.

Plus a unit check that mint_db_token's optional org_ids claim is wired (and
RLS-independent).
"""

import os
from types import SimpleNamespace
from urllib.parse import urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import app.auth as app_auth
from app.db import mint_db_token, service_client
from app.mcp_server import MULTI_ORG_MESSAGE, NO_ORG_MESSAGE
from conftest import (
    add_membership,
    cleanup_orgs,
    make_test_org,
    make_test_user,
    mcp_call_tool,
    mint_access_token,
)


def _fact(user_sub: str, org_id: str, content: str) -> dict:
    return {
        "user_id": user_sub,
        "org_id": org_id,
        "type": "preference",
        "content": content,
        "source": "user_manual",
        "status": "active",
        "confidence": 0.8,
    }


def _text(result: dict) -> str:
    assert not result.get("isError"), result
    return result["content"][0]["text"]


def _error_text(result: dict) -> str:
    assert result.get("isError"), f"expected tool error, got: {result}"
    return result["content"][0]["text"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _stack_guard():
    url = os.environ["SUPABASE_URL"]
    host = urlparse(url).hostname
    if host not in {"127.0.0.1", "localhost", "::1"} and not os.environ.get(
        "LEDGER_TESTS_ALLOW_REMOTE"
    ):
        pytest.fail(f"Refusing to run mutating tests against non-local {url!r}.")
    try:
        httpx.get(f"{url}/rest/v1/", timeout=10)
    except httpx.HTTPError as exc:
        pytest.fail(f"Local Supabase stack unreachable at {url} ({exc}) — see README.")


@pytest.fixture(scope="module")
def rsa_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def api(rsa_private_key):
    public_key = rsa_private_key.public_key()
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        app_auth,
        "_jwks_client",
        lambda url: SimpleNamespace(
            get_signing_key_from_jwt=lambda token: SimpleNamespace(key=public_key)
        ),
    )
    from app.main import create_app

    with TestClient(create_app()) as client:
        yield client
    monkeypatch.undo()


@pytest.fixture(scope="module")
def world(rsa_private_key):
    """Provision four principals: a single-org user (with another org alongside
    to prove scoping), a no-membership user, and a two-org user."""
    service = service_client()

    single = make_test_user("res-single")
    org_single = make_test_org(service, "res-org-single")
    add_membership(service, org_single, single.sub, "owner")

    other = make_test_user("res-other")
    org_other = make_test_org(service, "res-org-other")
    add_membership(service, org_other, other.sub, "owner")

    service.table("facts").insert(
        [
            _fact(single.sub, org_single, "single-org fact about espresso"),
            _fact(other.sub, org_other, "other-org fact about tea"),
        ]
    ).execute()

    none_user = make_test_user("res-none")

    multi = make_test_user("res-multi")
    org_m1 = make_test_org(service, "res-org-m1")
    org_m2 = make_test_org(service, "res-org-m2")
    add_membership(service, org_m1, multi.sub, "owner")
    add_membership(service, org_m2, multi.sub, "rep")

    yield {
        "service": service,
        "single": single,
        "org_single": org_single,
        "none": none_user,
        "multi": multi,
    }

    cleanup_orgs(service, [single.sub, other.sub, none_user.sub, multi.sub])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_single_membership_binds_org_and_scopes_reads(api, rsa_private_key, world):
    token = mint_access_token(rsa_private_key, world["single"].sub, "client-res-single")
    text = _text(mcp_call_tool(api, token, "search_context", {"query": "fact"}))
    assert "single-org fact about espresso" in text
    assert "other-org fact about tea" not in text, "binding leaked another org's facts"

    # The bound org is observable on the audit row _finish wrote (org_id NOT NULL).
    audit = (
        world["service"]
        .table("audit_log")
        .select("org_id")
        .eq("user_id", world["single"].sub)
        .eq("tool", "search_context")
        .execute()
        .data
    )
    assert audit, "the successful call must have been audited"
    assert all(row["org_id"] == world["org_single"] for row in audit)


def test_no_membership_is_rejected_fail_closed(api, rsa_private_key, world):
    token = mint_access_token(rsa_private_key, world["none"].sub, "client-res-none")
    message = _error_text(mcp_call_tool(api, token, "ping"))
    assert NO_ORG_MESSAGE in message
    # Fail closed: nothing was audited (there is no org to scope an audit row to).
    audited = (
        world["service"]
        .table("audit_log")
        .select("id", count="exact", head=True)
        .eq("user_id", world["none"].sub)
        .execute()
    )
    assert (audited.count or 0) == 0


def test_multi_membership_is_rejected(api, rsa_private_key, world):
    token = mint_access_token(rsa_private_key, world["multi"].sub, "client-res-multi")
    message = _error_text(mcp_call_tool(api, token, "ping"))
    assert MULTI_ORG_MESSAGE in message


def test_resolve_client_keys_on_org_and_reuses(api, rsa_private_key, world):
    oauth_client_id = "client-res-keying"
    token = mint_access_token(rsa_private_key, world["single"].sub, oauth_client_id)

    _text(mcp_call_tool(api, token, "ping"))  # first contact registers the client
    _text(mcp_call_tool(api, token, "ping"))  # second contact must reuse, not duplicate

    rows = (
        world["service"]
        .table("clients")
        .select("id,org_id,user_id,oauth_client_id")
        .eq("org_id", world["org_single"])
        .eq("oauth_client_id", oauth_client_id)
        .execute()
        .data
    )
    assert len(rows) == 1, f"expected exactly one clients row, got {rows}"
    assert rows[0]["user_id"] == world["single"].sub
    assert rows[0]["org_id"] == world["org_single"]


def test_mint_db_token_optional_org_claim_is_forward_looking():
    """org_ids is an optional claim; RLS never reads it, so it must be absent
    unless explicitly supplied and present (as strings) when it is."""
    secret = os.environ["SUPABASE_JWT_SECRET"]

    plain = jwt.decode(
        mint_db_token("auth0|res-x"),
        secret,
        algorithms=["HS256"],
        options={"verify_aud": False},
    )
    assert "org_ids" not in plain

    with_orgs = jwt.decode(
        mint_db_token("auth0|res-x", org_ids=["o1", "o2"]),
        secret,
        algorithms=["HS256"],
        options={"verify_aud": False},
    )
    assert with_orgs["org_ids"] == ["o1", "o2"]
