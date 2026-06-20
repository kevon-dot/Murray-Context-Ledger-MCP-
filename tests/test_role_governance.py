"""Role + seat governance gate (P6).

Within ONE org, owner/rep/office see appropriately different slices
(ROLE_SCOPES), and a single seat can be revoked without collateral. None of it
weakens org isolation — that hard boundary still holds on top of role scoping.
"""

import os
from types import SimpleNamespace
from urllib.parse import urlparse

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import app.auth as app_auth
from app.admin import revoke_seat
from app.db import service_client
from conftest import (
    add_membership,
    cleanup_orgs,
    make_test_org,
    make_test_user,
    mcp_call_tool,
    mint_access_token,
)

CLIENT_OWNER = "client-role-owner"
CLIENT_REP = "client-role-rep"
CLIENT_OFFICE = "client-role-office"
CLIENT_VICTIM = "client-role-victim"  # a second owner seat, revoked in isolation

# Distinctive markers per scope so a returned activity line is unambiguous.
ACCOUNT_FACT = "Account scope roofing note ALPHA"
PERSONAL_FACT = "Personal scope roofing note BRAVO"
WORK_FACT = "Work scope roofing note CHARLIE"
OTHER_ORG_FACT = "Other org roofing note DELTA"

ALL_SCOPES = ["account", "personal", "work"]


def _state_fact(user_sub, org_id, content, scope):
    return {
        "user_id": user_sub,
        "org_id": org_id,
        "type": "state",
        "content": content,
        "source": "user_manual",
        "status": "active",
        "scope_tags": [scope],
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
        pytest.fail(f"Refusing to run mutating role tests against non-local {url!r}.")
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
def world():
    """One org with an owner, a rep, and an office user. Every seat is granted
    all scopes, so ROLE_SCOPES — not the client grant — is what narrows. A
    second org carries a fact none of them may see."""
    service = service_client()
    owner = make_test_user("role-owner")
    rep = make_test_user("role-rep")
    office = make_test_user("role-office")
    org = make_test_org(service, "role-org")
    add_membership(service, org, owner.sub, "owner")
    add_membership(service, org, rep.sub, "rep")
    add_membership(service, org, office.sub, "office")

    # Other org + member + fact, to prove role scoping never crosses orgs.
    other_user = make_test_user("role-other")
    other_org = make_test_org(service, "role-other-org")
    add_membership(service, other_org, other_user.sub, "owner")

    for sub, client_id in (
        (owner.sub, CLIENT_OWNER),
        (rep.sub, CLIENT_REP),
        (office.sub, CLIENT_OFFICE),
        (owner.sub, CLIENT_VICTIM),
    ):
        service.table("clients").insert(
            {
                "org_id": org,
                "user_id": sub,
                "oauth_client_id": client_id,
                "display_name": client_id,
                "granted_scopes": ALL_SCOPES,
            }
        ).execute()

    service.table("facts").insert(
        [
            _state_fact(owner.sub, org, ACCOUNT_FACT, "account"),
            _state_fact(owner.sub, org, PERSONAL_FACT, "personal"),
            _state_fact(owner.sub, org, WORK_FACT, "work"),
            _state_fact(other_user.sub, other_org, OTHER_ORG_FACT, "account"),
        ]
    ).execute()

    yield {"service": service, "org": org, "owner": owner, "rep": rep, "office": office}
    cleanup_orgs(service, [owner.sub, rep.sub, office.sub, other_user.sub])


def _activity(api, rsa_private_key, sub, client_id) -> str:
    token = mint_access_token(rsa_private_key, sub, client_id)
    return _text(mcp_call_tool(api, token, "get_recent_activity"))


# ---------------------------------------------------------------------------
# Role-scoped visibility
# ---------------------------------------------------------------------------


def test_owner_sees_every_scope(api, rsa_private_key, world):
    text = _activity(api, rsa_private_key, world["owner"].sub, CLIENT_OWNER)
    assert ACCOUNT_FACT in text
    assert PERSONAL_FACT in text
    assert WORK_FACT in text


def test_rep_sees_account_and_personal_not_work(api, rsa_private_key, world):
    text = _activity(api, rsa_private_key, world["rep"].sub, CLIENT_REP)
    assert ACCOUNT_FACT in text
    assert PERSONAL_FACT in text
    assert WORK_FACT not in text, "rep must not see work-scoped facts (ROLE_SCOPES)"


def test_office_sees_account_and_work_not_personal(api, rsa_private_key, world):
    text = _activity(api, rsa_private_key, world["office"].sub, CLIENT_OFFICE)
    assert ACCOUNT_FACT in text
    assert WORK_FACT in text
    assert PERSONAL_FACT not in text, "office must not see rep-personal facts (ROLE_SCOPES)"


# ---------------------------------------------------------------------------
# Per-seat revoke (no collateral)
# ---------------------------------------------------------------------------


def test_revoking_one_seat_does_not_affect_others(api, rsa_private_key, world):
    # Revoke only the victim seat (a second owner connector).
    revoked = revoke_seat(world["org"], CLIENT_VICTIM)
    assert revoked and revoked[0]["status"] == "revoked"

    victim_token = mint_access_token(rsa_private_key, world["owner"].sub, CLIENT_VICTIM)
    message = _error_text(mcp_call_tool(api, victim_token, "ping"))
    assert "revoked" in message
    assert "re-enable it in their ledger dashboard" in message

    # Other seats in the SAME org keep working — revocation is per-seat, not per-org.
    assert _text(
        mcp_call_tool(
            api, mint_access_token(rsa_private_key, world["owner"].sub, CLIENT_OWNER), "ping"
        )
    ).startswith("ledger ok")
    assert _text(
        mcp_call_tool(api, mint_access_token(rsa_private_key, world["rep"].sub, CLIENT_REP), "ping")
    ).startswith("ledger ok")


# ---------------------------------------------------------------------------
# Sanity: role scoping never crosses orgs
# ---------------------------------------------------------------------------


def test_no_role_sees_another_org(api, rsa_private_key, world):
    for sub, client_id in (
        (world["owner"].sub, CLIENT_OWNER),
        (world["rep"].sub, CLIENT_REP),
        (world["office"].sub, CLIENT_OFFICE),
    ):
        text = _activity(api, rsa_private_key, sub, client_id)
        assert OTHER_ORG_FACT not in text, "ISOLATION BREACH: role scoping leaked another org"
