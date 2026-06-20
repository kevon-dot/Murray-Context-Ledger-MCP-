"""pending_review lifecycle gate (productionization).

Facts below the auto-promote threshold land pending_review; owner/office triage
them with list_pending_facts / promote_fact / reject_fact. Reps dictate but
cannot review; review is role-scoped and org-bounded like every other read.
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
from app.db import service_client
from conftest import (
    add_membership,
    cleanup_orgs,
    make_test_org,
    make_test_user,
    mcp_call_tool,
    mint_access_token,
)

C_OWNER = "client-rev-owner"
C_OFFICE = "client-rev-office"
C_REP = "client-rev-rep"
C_OTHER = "client-rev-other"
ALL_SCOPES = ["account", "personal", "work"]


def _structured(result: dict) -> dict:
    assert not result.get("isError"), result
    if "structuredContent" in result:
        return result["structuredContent"]
    return json.loads(result["content"][0]["text"])


def _error_text(result: dict) -> str:
    assert result.get("isError"), f"expected tool error, got: {result}"
    return result["content"][0]["text"]


@pytest.fixture(scope="module", autouse=True)
def _stack_guard():
    url = os.environ["SUPABASE_URL"]
    host = urlparse(url).hostname
    if host not in {"127.0.0.1", "localhost", "::1"} and not os.environ.get(
        "LEDGER_TESTS_ALLOW_REMOTE"
    ):
        pytest.fail(f"Refusing to run mutating review tests against non-local {url!r}.")
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
    service = service_client()
    owner = make_test_user("rev-owner")
    office = make_test_user("rev-office")
    rep = make_test_user("rev-rep")
    org = make_test_org(service, "rev-org")
    add_membership(service, org, owner.sub, "owner")
    add_membership(service, org, office.sub, "office")
    add_membership(service, org, rep.sub, "rep")

    other = make_test_user("rev-other")
    other_org = make_test_org(service, "rev-other-org")
    add_membership(service, other_org, other.sub, "owner")

    for org_id, sub, cid in (
        (org, owner.sub, C_OWNER),
        (org, office.sub, C_OFFICE),
        (org, rep.sub, C_REP),
        (other_org, other.sub, C_OTHER),
    ):
        service.table("clients").insert(
            {
                "org_id": org_id,
                "user_id": sub,
                "oauth_client_id": cid,
                "display_name": cid,
                "granted_scopes": ALL_SCOPES,
            }
        ).execute()

    yield {
        "service": service,
        "org": org,
        "owner": owner,
        "office": office,
        "rep": rep,
        "other": other,
    }
    cleanup_orgs(service, [owner.sub, office.sub, rep.sub, other.sub])


@pytest.fixture(scope="module")
def tokens(rsa_private_key, world):
    return {
        "owner": mint_access_token(rsa_private_key, world["owner"].sub, C_OWNER),
        "office": mint_access_token(rsa_private_key, world["office"].sub, C_OFFICE),
        "rep": mint_access_token(rsa_private_key, world["rep"].sub, C_REP),
        "other": mint_access_token(rsa_private_key, world["other"].sub, C_OTHER),
    }


def _write_pending(api, token, content, *, scope="account", confidence=0.6) -> str:
    summary = _structured(
        mcp_call_tool(
            api,
            token,
            "remember_facts",
            {
                "facts": [
                    {
                        "type": "state",
                        "content": content,
                        "confidence": confidence,
                        "scope_tags": [scope],
                    }
                ]
            },
        )
    )
    assert summary["counts"]["created"] == 1
    return summary["created"][0]


def _status(service, fact_id: str) -> str:
    return service.table("facts").select("status").eq("id", fact_id).execute().data[0]["status"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_pending_lands_and_office_promotes(api, world, tokens):
    fact_id = _write_pending(api, tokens["rep"], "Roof claim note ALPHA")
    assert _status(world["service"], fact_id) == "pending_review"

    listed = _structured(mcp_call_tool(api, tokens["office"], "list_pending_facts"))
    assert fact_id in {row["id"] for row in listed["pending"]}

    result = _structured(mcp_call_tool(api, tokens["office"], "promote_fact", {"fact_id": fact_id}))
    assert result == {"promoted": fact_id, "status": "active"}
    assert _status(world["service"], fact_id) == "active"

    # Audited.
    audit = (
        world["service"]
        .table("audit_log")
        .select("fact_ids")
        .eq("org_id", world["org"])
        .eq("tool", "promote_fact")
        .execute()
        .data
    )
    assert any(fact_id in (row["fact_ids"] or []) for row in audit)


def test_office_rejects(api, world, tokens):
    fact_id = _write_pending(api, tokens["rep"], "Roof claim note BRAVO")
    result = _structured(
        mcp_call_tool(api, tokens["office"], "reject_fact", {"fact_id": fact_id, "reason": "dup"})
    )
    assert result == {"rejected": fact_id, "status": "rejected"}
    assert _status(world["service"], fact_id) == "rejected"

    # A rejected fact is not team-visible.
    search = _structured(mcp_call_tool(api, tokens["owner"], "search", {"query": "BRAVO"}))
    assert search == {"results": []}


def test_rep_cannot_review(api, world, tokens):
    assert "owner and office" in _error_text(
        mcp_call_tool(api, tokens["rep"], "list_pending_facts")
    )
    fact_id = _write_pending(api, tokens["rep"], "Roof claim note rep-self")
    assert "owner and office" in _error_text(
        mcp_call_tool(api, tokens["rep"], "promote_fact", {"fact_id": fact_id})
    )
    assert _status(world["service"], fact_id) == "pending_review"  # unchanged


def test_review_queue_is_role_scoped(api, world, tokens):
    personal_id = _write_pending(api, tokens["rep"], "Personal note CHARLIE", scope="personal")

    office_queue = _structured(mcp_call_tool(api, tokens["office"], "list_pending_facts"))
    assert personal_id not in {row["id"] for row in office_queue["pending"]}, (
        "office must not see rep-personal facts in the review queue"
    )

    owner_queue = _structured(mcp_call_tool(api, tokens["owner"], "list_pending_facts"))
    assert personal_id in {row["id"] for row in owner_queue["pending"]}

    # And office cannot promote what it cannot see.
    denied = _structured(
        mcp_call_tool(api, tokens["office"], "promote_fact", {"fact_id": personal_id})
    )
    assert denied["promoted"] is None and "message" in denied
    assert _status(world["service"], personal_id) == "pending_review"


def test_promote_non_pending_is_a_clear_noop(api, world, tokens):
    fact_id = _write_pending(api, tokens["rep"], "Roof claim note DELTA")
    _structured(mcp_call_tool(api, tokens["office"], "promote_fact", {"fact_id": fact_id}))
    # Second promote: it is active now, not pending -> nothing to act on.
    again = _structured(mcp_call_tool(api, tokens["office"], "promote_fact", {"fact_id": fact_id}))
    assert again["promoted"] is None and "message" in again


def test_cross_org_promote_finds_nothing(api, world, tokens):
    foreign_id = _write_pending(api, tokens["other"], "Other org pending ECHO")
    result = _structured(
        mcp_call_tool(api, tokens["office"], "promote_fact", {"fact_id": foreign_id})
    )
    assert result["promoted"] is None and "message" in result
    assert _status(world["service"], foreign_id) == "pending_review", "orgB fact must be untouched"
