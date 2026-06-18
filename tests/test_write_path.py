"""Write path gate (P4): remember_facts + supersede_fact.

Proves the team memory is actually writable and safe:
  * org-scoped writes that peers in the same org can read and other orgs cannot;
  * auto-promote at confidence >= 0.9;
  * idempotency via dedupe_key, scoped per org;
  * per-item validation (one bad fact never drops the batch);
  * supersede retires the old fact and is org-bounded;
  * every outcome is audited and attributed to the writing connector.
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
from app.db import service_client, user_client
from conftest import (
    add_membership,
    cleanup_orgs,
    make_test_org,
    make_test_user,
    mcp_call_tool,
    mint_access_token,
    mint_user_jwt,
)

CLIENT_MURRAY = "client-murray-write"
CLIENT_REP = "client-rep-write"
CLIENT_B = "client-b-write"


def _payload(
    type_, content, confidence, *, dedupe_key=None, source="mcp_writeback", scope_tags=None
):
    fact = {
        "type": type_,
        "content": content,
        "confidence": confidence,
        "source": source,
        "scope_tags": scope_tags or ["account"],
    }
    if dedupe_key is not None:
        fact["dedupe_key"] = dedupe_key
    return fact


def _structured(result: dict) -> dict:
    assert not result.get("isError"), result
    if "structuredContent" in result:
        return result["structuredContent"]
    return json.loads(result["content"][0]["text"])


def _remember(api, token, facts) -> dict:
    return _structured(mcp_call_tool(api, token, "remember_facts", {"facts": facts}))


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
        pytest.fail(f"Refusing to run mutating write tests against non-local {url!r}.")
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
    """orgA = {userA owner, userA2 rep}; orgB = {userB owner}. userA's writing
    connector is pre-registered as Murray so writes are attributed."""
    service = service_client()
    user_a = make_test_user("wp-a")
    user_a2 = make_test_user("wp-a2")
    user_b = make_test_user("wp-b")
    org_a = make_test_org(service, "wp-org-a")
    org_b = make_test_org(service, "wp-org-b")
    add_membership(service, org_a, user_a.sub, "owner")
    add_membership(service, org_a, user_a2.sub, "rep")
    add_membership(service, org_b, user_b.sub, "owner")
    # Pre-register userA's connector as Murray (keyed (org_id, oauth_client_id)
    # exactly like _resolve_client), so connector_source attributes the writes.
    service.table("clients").insert(
        {
            "org_id": org_a,
            "user_id": user_a.sub,
            "oauth_client_id": CLIENT_MURRAY,
            "display_name": "Murray",
            "connector_source": "murray_app",
            "granted_scopes": ["account", "personal", "work"],
        }
    ).execute()
    yield {
        "service": service,
        "user_a": user_a,
        "user_a2": user_a2,
        "user_b": user_b,
        "org_a": org_a,
        "org_b": org_b,
    }
    cleanup_orgs(service, [user_a.sub, user_a2.sub, user_b.sub])


@pytest.fixture(scope="module")
def token_a(rsa_private_key, world):
    return mint_access_token(rsa_private_key, world["user_a"].sub, CLIENT_MURRAY)


@pytest.fixture(scope="module")
def token_b(rsa_private_key, world):
    return mint_access_token(rsa_private_key, world["user_b"].sub, CLIENT_B)


def _facts_by_id(service, ids):
    rows = service.table("facts").select("*").in_("id", ids).execute().data
    return {r["id"]: r for r in rows}


# ---------------------------------------------------------------------------
# Org-scoped write + peer read + cross-org isolation
# ---------------------------------------------------------------------------


def test_org_scoped_write_peer_read_cross_org_zero(api, world, token_a):
    summary = _remember(
        api,
        token_a,
        [
            _payload("state", "Insurance claim is open on the roof", 0.95, dedupe_key="wp-r1"),
            _payload("relationship", "Spouse is the decision-maker", 0.95, dedupe_key="wp-r2"),
        ],
    )
    assert summary["counts"]["created"] == 2
    ids = summary["created"]

    stored = _facts_by_id(world["service"], ids)
    for fact in stored.values():
        assert fact["org_id"] == world["org_a"]
        assert fact["user_id"] == world["user_a"].sub

    # Peer (same-org rep) reads them through the RLS-enforced client.
    db_a2 = user_client(mint_user_jwt(world["user_a2"]))
    peer = db_a2.table("facts").select("id").in_("id", ids).execute().data
    assert {r["id"] for r in peer} == set(ids), "WITHIN-ORG SHARING BROKEN: rep can't read writes"

    # Other org reads zero.
    db_b = user_client(mint_user_jwt(world["user_b"]))
    assert db_b.table("facts").select("id").in_("id", ids).execute().data == []


# ---------------------------------------------------------------------------
# Auto-promote by confidence
# ---------------------------------------------------------------------------


def test_auto_promote_by_confidence(api, world, token_a):
    summary = _remember(
        api,
        token_a,
        [
            _payload("state", "High confidence fact", 0.95, dedupe_key="wp-hi"),
            _payload("state", "Low confidence fact", 0.5, dedupe_key="wp-lo"),
        ],
    )
    stored = _facts_by_id(world["service"], summary["created"])
    by_content = {f["content"]: f for f in stored.values()}
    assert by_content["High confidence fact"]["status"] == "active"
    assert by_content["Low confidence fact"]["status"] == "pending_review"


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_idempotent_repeat_is_a_noop(api, world, token_a):
    fact = _payload("state", "Soft decking on the north slope", 0.85, dedupe_key="wp-idem")
    first = _remember(api, token_a, [fact])
    second = _remember(api, token_a, [fact])

    assert first["counts"] == {"created": 1, "deduped": 0, "invalid": 0}
    assert second["counts"] == {"created": 0, "deduped": 1, "invalid": 0}
    assert first["created"][0] == second["deduped"][0], "dedupe must resolve to the same row"

    rows = (
        world["service"]
        .table("facts")
        .select("id")
        .eq("org_id", world["org_a"])
        .eq("dedupe_key", "wp-idem")
        .execute()
        .data
    )
    assert len(rows) == 1, "a repeated write must not create a second row"


def test_dedupe_key_is_org_scoped(api, world, token_a, token_b):
    key = "wp-cross-org-key"
    a = _remember(api, token_a, [_payload("state", "orgA version", 0.8, dedupe_key=key)])
    b = _remember(api, token_b, [_payload("state", "orgB version", 0.8, dedupe_key=key)])
    assert a["counts"]["created"] == 1
    assert b["counts"]["created"] == 1, "same key in another org is not a collision"

    rows = world["service"].table("facts").select("org_id").eq("dedupe_key", key).execute().data
    assert {r["org_id"] for r in rows} == {world["org_a"], world["org_b"]}


# ---------------------------------------------------------------------------
# Validation (per-item — one bad fact never drops the batch)
# ---------------------------------------------------------------------------


def test_validation_is_per_item(api, world, token_a):
    summary = _remember(
        api,
        token_a,
        [
            _payload("preference", "A perfectly valid fact", 0.8, dedupe_key="wp-valid"),
            _payload("state", "Confidence out of range", 1.5),
            {"type": "astrological", "content": "Invalid type", "confidence": 0.5},
        ],
    )
    assert summary["counts"]["created"] == 1
    assert summary["counts"]["invalid"] == 2
    assert {entry["index"] for entry in summary["invalid"]} == {1, 2}
    # Each invalid entry names the offending field with a message.
    for entry in summary["invalid"]:
        assert entry["errors"] and all("field" in e and "message" in e for e in entry["errors"])

    valid = (
        world["service"]
        .table("facts")
        .select("content")
        .eq("org_id", world["org_a"])
        .eq("dedupe_key", "wp-valid")
        .execute()
        .data
    )
    assert valid == [{"content": "A perfectly valid fact"}], "the valid fact must still commit"


# ---------------------------------------------------------------------------
# Supersede
# ---------------------------------------------------------------------------


def test_supersede_retires_old_and_links_new(api, world, token_a):
    original = _remember(
        api, token_a, [_payload("state", "Original roof note", 0.8, dedupe_key="wp-sup-old")]
    )
    old_id = original["created"][0]

    result = _structured(
        mcp_call_tool(
            api,
            token_a,
            "supersede_fact",
            {
                "old_fact_id": old_id,
                "new_fact": _payload("state", "Corrected roof note", 0.95, dedupe_key="wp-sup-new"),
            },
        )
    )
    new_id = result["created"]
    assert result["superseded"] == old_id
    assert result["new_status"] == "active"  # 0.95 >= 0.9

    stored = _facts_by_id(world["service"], [old_id, new_id])
    assert stored[old_id]["status"] == "superseded"
    assert stored[old_id]["superseded_by"] == new_id
    assert stored[new_id]["status"] == "active"


def test_cross_org_supersede_finds_nothing(api, world, token_b):
    # An orgA-only fact, written directly by the service role.
    a_fact = (
        world["service"]
        .table("facts")
        .insert(
            {
                "org_id": world["org_a"],
                "user_id": world["user_a"].sub,
                "type": "state",
                "content": "orgA private note",
                "source": "user_manual",
                "status": "active",
            }
        )
        .execute()
        .data[0]
    )

    result = _structured(
        mcp_call_tool(
            api,
            token_b,
            "supersede_fact",
            {"old_fact_id": a_fact["id"], "new_fact": _payload("state", "B's attempt", 0.8)},
        )
    )
    assert result["superseded"] is None
    assert result["created"] is None, "cross-org supersede must not create an orphan replacement"
    assert "message" in result

    untouched = (
        world["service"].table("facts").select("status").eq("id", a_fact["id"]).execute().data[0]
    )
    assert untouched["status"] == "active", "orgA fact must be untouched by orgB"


# ---------------------------------------------------------------------------
# Audit — every write attributed to the connector
# ---------------------------------------------------------------------------


def _audit_rows(service, user_sub, tool):
    return (
        service.table("audit_log")
        .select("*")
        .eq("user_id", user_sub)
        .eq("tool", tool)
        .order("id")
        .execute()
        .data
    )


def test_every_write_is_audited_and_attributed(api, world, token_a):
    svc = world["service"]
    sub = world["user_a"].sub

    before = len(_audit_rows(svc, sub, "remember_facts"))
    created = _remember(api, token_a, [_payload("state", "Audited fact", 0.8, dedupe_key="wp-aud")])
    deduped = _remember(api, token_a, [_payload("state", "Audited fact", 0.8, dedupe_key="wp-aud")])

    rows = _audit_rows(svc, sub, "remember_facts")
    assert len(rows) == before + 2, "both the create and the dedupe call must be audited"

    # The created id is recorded; both calls attribute to the Murray connector.
    assert created["created"][0] in (rows[-2]["fact_ids"] or [])
    assert created["connector_source"] == "murray_app"
    assert deduped["counts"]["deduped"] == 1
    for row in rows[-2:]:
        client = (
            svc.table("clients")
            .select("connector_source")
            .eq("id", row["client_id"])
            .execute()
            .data
        )
        assert client[0]["connector_source"] == "murray_app"

    # supersede is audited too, naming both the new and the retired fact.
    old_id = created["created"][0]
    sup = _structured(
        mcp_call_tool(
            api,
            token_a,
            "supersede_fact",
            {"old_fact_id": old_id, "new_fact": _payload("state", "Audited replacement", 0.95)},
        )
    )
    sup_rows = _audit_rows(svc, sub, "supersede_fact")
    assert sup_rows, "supersede must be audited"
    assert set(sup_rows[-1]["fact_ids"]) == {sup["created"], old_id}
