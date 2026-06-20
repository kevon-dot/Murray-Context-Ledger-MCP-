"""Provisioning + connector registration gate (productionization).

The operator surface (service-role only, off the request path) that stands up an
org, grants seats, and attributes connectors — plus the end-to-end proof that a
provisioned Murray connector attributes a real write.
"""

import json
import os
from types import SimpleNamespace
from urllib.parse import urlparse

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import app.auth as app_auth
from app import admin
from app.db import service_client
from conftest import make_test_user, mcp_call_tool, mint_access_token

CLIENT_MURRAY = "client-prov-murray"


def _structured(result: dict) -> dict:
    assert not result.get("isError"), result
    if "structuredContent" in result:
        return result["structuredContent"]
    return json.loads(result["content"][0]["text"])


@pytest.fixture(scope="module", autouse=True)
def _stack_guard():
    url = os.environ["SUPABASE_URL"]
    host = urlparse(url).hostname
    if host not in {"127.0.0.1", "localhost", "::1"} and not os.environ.get(
        "LEDGER_TESTS_ALLOW_REMOTE"
    ):
        pytest.fail(f"Refusing to run mutating admin tests against non-local {url!r}.")
    try:
        httpx.get(f"{url}/rest/v1/", timeout=10)
    except httpx.HTTPError as exc:
        pytest.fail(f"Local Supabase stack unreachable at {url} ({exc}) — see README.")


@pytest.fixture(scope="module")
def tracker():
    return {"org_ids": set()}


@pytest.fixture(scope="module")
def service(tracker):
    svc = service_client()
    yield svc
    org_ids = list(tracker["org_ids"])
    if org_ids:
        for table in ("audit_log", "facts", "jobs", "clients", "memberships"):
            svc.table(table).delete().in_("org_id", org_ids).execute()
        svc.table("orgs").delete().in_("id", org_ids).execute()


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


# ---------------------------------------------------------------------------
# Orgs + memberships
# ---------------------------------------------------------------------------


def test_create_org_and_list(service, tracker):
    org = admin.create_org("Henderson Roofing")
    tracker["org_ids"].add(org["id"])
    assert org["name"] == "Henderson Roofing"
    assert org["id"] in {o["id"] for o in admin.list_orgs()}

    with pytest.raises(ValueError):
        admin.create_org("   ")


def test_add_member_validates_and_is_idempotent(service, tracker):
    org = admin.create_org("Members Co")
    tracker["org_ids"].add(org["id"])
    user = make_test_user("prov-member")

    with pytest.raises(ValueError):
        admin.add_member(org["id"], user.sub, "superuser")  # not a real role

    added = admin.add_member(org["id"], user.sub, "rep")
    assert added["role"] == "rep"

    # Re-adding with a new role updates in place (no duplicate membership).
    rerole = admin.add_member(org["id"], user.sub, "office")
    assert rerole["role"] == "office"
    members = admin.list_members(org["id"])
    assert [m["user_id"] for m in members] == [user.sub]
    assert members[0]["role"] == "office"

    removed = admin.remove_member(org["id"], user.sub)
    assert removed and removed[0]["user_id"] == user.sub
    assert admin.list_members(org["id"]) == []


# ---------------------------------------------------------------------------
# Connector registration
# ---------------------------------------------------------------------------


def test_register_connector_sets_source_and_is_idempotent(service, tracker):
    org = admin.create_org("Connector Co")
    tracker["org_ids"].add(org["id"])
    owner = make_test_user("prov-conn-owner")
    admin.add_member(org["id"], owner.sub, "owner")

    seat = admin.register_connector(
        org["id"],
        CLIENT_MURRAY,
        "murray_app",
        owner.sub,
        display_name="Murray",
        granted_scopes=["account", "personal", "work"],
    )
    assert seat["connector_source"] == "murray_app"
    assert seat["status"] == "active"
    assert seat["user_id"] == owner.sub
    assert set(seat["granted_scopes"]) == {"account", "personal", "work"}

    # Re-register updates in place (one row, new scopes), no duplicate seat.
    again = admin.register_connector(
        org["id"], CLIENT_MURRAY, "murray_app", owner.sub, granted_scopes=["account"]
    )
    assert again["id"] == seat["id"]
    seats = admin.list_connectors(org["id"])
    assert len(seats) == 1
    assert seats[0]["granted_scopes"] == ["account"]


def test_set_connector_source_backfills(service, tracker):
    org = admin.create_org("Backfill Co")
    tracker["org_ids"].add(org["id"])
    owner = make_test_user("prov-backfill")
    admin.add_member(org["id"], owner.sub, "owner")
    # Simulate a client that auto-registered on first contact with a null source.
    service.table("clients").insert(
        {
            "org_id": org["id"],
            "user_id": owner.sub,
            "oauth_client_id": "client-auto",
            "display_name": "client-auto",
        }
    ).execute()

    updated = admin.set_connector_source(org["id"], "client-auto", "claude")
    assert updated and updated[0]["connector_source"] == "claude"


# ---------------------------------------------------------------------------
# End-to-end: a provisioned Murray connector attributes a real write
# ---------------------------------------------------------------------------


def test_provisioned_connector_attributes_a_write(api, rsa_private_key, service, tracker):
    org = admin.create_org("Murray Field Co")
    tracker["org_ids"].add(org["id"])
    owner = make_test_user("prov-e2e-owner")
    admin.add_member(org["id"], owner.sub, "owner")
    admin.register_connector(
        org["id"],
        CLIENT_MURRAY,
        "murray_app",
        owner.sub,
        granted_scopes=["account"],
    )

    token = mint_access_token(rsa_private_key, owner.sub, CLIENT_MURRAY)
    summary = _structured(
        mcp_call_tool(
            api,
            token,
            "remember_facts",
            {"facts": [{"type": "state", "content": "Roof claim open", "confidence": 0.95}]},
        )
    )
    assert summary["connector_source"] == "murray_app"
    assert summary["counts"]["created"] == 1

    # And the audit row is attributable to Murray via client_id -> connector_source.
    audit = (
        service.table("audit_log")
        .select("client_id")
        .eq("org_id", org["id"])
        .eq("tool", "remember_facts")
        .execute()
        .data
    )
    assert audit
    client = (
        service.table("clients")
        .select("connector_source")
        .eq("id", audit[-1]["client_id"])
        .execute()
        .data
    )
    assert client[0]["connector_source"] == "murray_app"


# ---------------------------------------------------------------------------
# CLI dispatch
# ---------------------------------------------------------------------------


def test_cli_create_org_and_add_member(service, tracker, capsys):
    from scripts import ledger_admin

    assert ledger_admin.main(["create-org", "--name", "CLI Roofing"]) == 0
    org = json.loads(capsys.readouterr().out)
    tracker["org_ids"].add(org["id"])
    assert org["name"] == "CLI Roofing"

    user = make_test_user("prov-cli")
    assert (
        ledger_admin.main(
            ["add-member", "--org", org["id"], "--user", user.sub, "--role", "office"]
        )
        == 0
    )
    member = json.loads(capsys.readouterr().out)
    assert member["role"] == "office"
