"""Cross-user isolation proof — the P0 acceptance gate.

Runs against a real Supabase data plane (Postgres + PostgREST) with migration
0001 applied: `supabase start` locally/CI, or scripts/no_docker_stack.sh where
Docker isn't available. Every request goes through `app.db.user_client` /
`service_client` — the exact factories the server uses — so what is proven
here is the production enforcement path: anon key + caller JWT, RLS in
Postgres.

If user B can ever read, modify, or delete user A's rows, this module fails
and the build goes red. That is its entire purpose.
"""

import os
from urllib.parse import urlparse

import httpx
import pytest
from postgrest.exceptions import APIError
from supabase import create_client

from app.db import service_client, user_client
from conftest import add_membership, cleanup_orgs, make_test_org, make_test_user, mint_user_jwt

CHECK_VIOLATION = "23514"  # Postgres check constraint
NOT_AUTHORIZED = "42501"  # insufficient_privilege (missing grant or RLS with-check)


def _valid_fact(user_sub: str, org_id: str) -> dict:
    return {
        "user_id": user_sub,
        "org_id": org_id,
        "type": "preference",
        "content": "prefers espresso over filter coffee",
        "source": "user_manual",
        "confidence": 0.8,
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _stack_guard():
    """Refuse to run anywhere but a local stack, and fail loudly if it's down."""
    url = os.environ["SUPABASE_URL"]
    host = urlparse(url).hostname
    if host not in {"127.0.0.1", "localhost", "::1"} and not os.environ.get(
        "LEDGER_TESTS_ALLOW_REMOTE"
    ):
        pytest.fail(
            f"Refusing to run mutating RLS tests against non-local SUPABASE_URL={url!r}. "
            "Set LEDGER_TESTS_ALLOW_REMOTE=1 only if you really mean it."
        )
    try:
        httpx.get(
            f"{url}/rest/v1/",
            headers={"apikey": os.environ["SUPABASE_ANON_KEY"]},
            timeout=10,
        )
    except httpx.HTTPError as exc:
        pytest.fail(
            f"Local Supabase stack unreachable at {url} ({exc}). "
            "Run `supabase start` (or scripts/no_docker_stack.sh) first — see README."
        )


@pytest.fixture(scope="module")
def user_a():
    return make_test_user("a")


@pytest.fixture(scope="module")
def user_b():
    return make_test_user("b")


@pytest.fixture(scope="module")
def db_a(user_a):
    return user_client(mint_user_jwt(user_a))


@pytest.fixture(scope="module")
def db_b(user_b):
    return user_client(mint_user_jwt(user_b))


@pytest.fixture(scope="module")
def db_service(user_a, user_b):
    service = service_client()
    yield service
    # Cleanup with the service role (the only role that may delete); FK-safe,
    # and removes the orgs/memberships these users belonged to as well.
    cleanup_orgs(service, [user_a.sub, user_b.sub])


@pytest.fixture(scope="module")
def orgs(db_service, user_a, user_b):
    """userA in orgA, userB in orgB — isolation is now enforced at the org
    boundary. Each owns their org so they can write their own facts."""
    org_a = make_test_org(db_service, "rls-org-a")
    org_b = make_test_org(db_service, "rls-org-b")
    add_membership(db_service, org_a, user_a.sub, "owner")
    add_membership(db_service, org_b, user_b.sub, "owner")
    return {"a": org_a, "b": org_b}


@pytest.fixture(scope="module")
def a_fact(db_a, db_service, orgs, user_a):
    """A fact inserted by user A through the RLS-enforced client."""
    response = db_a.table("facts").insert(_valid_fact(user_a.sub, orgs["a"])).execute()
    assert len(response.data) == 1, "user A must be able to insert their own fact"
    return response.data[0]


# ---------------------------------------------------------------------------
# 1–2. Owner can write and read their own data
# ---------------------------------------------------------------------------


def test_user_a_inserts_and_reads_own_fact(a_fact, db_a, user_a):
    assert a_fact["user_id"] == user_a.sub
    rows = db_a.table("facts").select("*").execute().data
    assert [row["id"] for row in rows] == [a_fact["id"]]
    assert rows[0]["status"] == "pending_review"  # contractual default


# ---------------------------------------------------------------------------
# 3. The gate: B must see zero of A's rows
# ---------------------------------------------------------------------------


def test_user_b_sees_zero_facts(a_fact, db_b):
    rows = db_b.table("facts").select("*").execute().data
    assert rows == [], f"ISOLATION BREACH: user B can read other users' facts: {rows}"


def test_user_b_cannot_read_a_fact_by_id(a_fact, db_b):
    rows = db_b.table("facts").select("*").eq("id", a_fact["id"]).execute().data
    assert rows == [], "ISOLATION BREACH: user B can read user A's fact by id"


# ---------------------------------------------------------------------------
# 4. B cannot update or delete A's fact
# ---------------------------------------------------------------------------


def test_user_b_cannot_update_a_fact(a_fact, db_a, db_b):
    updated = (
        db_b.table("facts").update({"content": "B was here"}).eq("id", a_fact["id"]).execute().data
    )
    assert updated == [], "ISOLATION BREACH: user B updated user A's fact"

    seen_by_a = db_a.table("facts").select("content").eq("id", a_fact["id"]).execute().data
    assert seen_by_a == [{"content": a_fact["content"]}]


def test_user_b_cannot_delete_a_fact(a_fact, db_a, db_b):
    # DELETE is denied at the privilege layer for the whole authenticated role
    # (42501); environments that still auto-grant DELETE fall back to the RLS
    # layer and report zero rows. Either way the fact must survive.
    try:
        deleted = db_b.table("facts").delete().eq("id", a_fact["id"]).execute().data
    except APIError as exc:
        assert exc.code == NOT_AUTHORIZED
    else:
        assert deleted == [], "ISOLATION BREACH: user B deleted user A's fact"

    still_there = db_a.table("facts").select("id").eq("id", a_fact["id"]).execute().data
    assert still_there == [{"id": a_fact["id"]}]


def test_user_b_cannot_insert_a_fact_owned_by_a(db_b, user_a, db_a, a_fact, orgs):
    # B spoofing a fact into A's org (and as A) is denied by the org-member
    # WITH CHECK: orgA is not in B's orgs.
    with pytest.raises(APIError) as excinfo:
        db_b.table("facts").insert(_valid_fact(user_a.sub, orgs["a"])).execute()
    assert excinfo.value.code == NOT_AUTHORIZED

    rows_of_a = db_a.table("facts").select("id").execute().data
    assert rows_of_a == [{"id": a_fact["id"]}], "spoofed insert must not reach A's ledger"


# ---------------------------------------------------------------------------
# 5. Unauthenticated access
# ---------------------------------------------------------------------------


def test_unauthenticated_anon_reads_nothing(a_fact):
    settings_url = os.environ["SUPABASE_URL"]
    anon_only = create_client(settings_url, os.environ["SUPABASE_ANON_KEY"])
    try:
        rows = anon_only.table("facts").select("*").execute().data
    except APIError as exc:
        assert exc.code == NOT_AUTHORIZED  # anon holds no grants at all
    else:
        assert rows == [], f"ISOLATION BREACH: anonymous client can read facts: {rows}"


# ---------------------------------------------------------------------------
# 6. audit_log is append-only, even for the row's owner
# ---------------------------------------------------------------------------


def test_audit_log_append_only(db_a, user_a, orgs):
    inserted = (
        db_a.table("audit_log")
        .insert(
            {
                "user_id": user_a.sub,
                "org_id": orgs["a"],
                "tool": "test_tool",
                "payload_hash": "abc123",
            }
        )
        .execute()
        .data
    )
    assert len(inserted) == 1
    entry_id = inserted[0]["id"]

    with pytest.raises(APIError) as update_attempt:
        db_a.table("audit_log").update({"tool": "rewritten"}).eq("id", entry_id).execute()
    assert update_attempt.value.code == NOT_AUTHORIZED

    with pytest.raises(APIError) as delete_attempt:
        db_a.table("audit_log").delete().eq("id", entry_id).execute()
    assert delete_attempt.value.code == NOT_AUTHORIZED

    # The row is intact.
    rows = db_a.table("audit_log").select("tool").eq("id", entry_id).execute().data
    assert rows == [{"tool": "test_tool"}]


# ---------------------------------------------------------------------------
# 7. Check constraints reject bad facts
# ---------------------------------------------------------------------------


def test_invalid_fact_type_rejected(db_a, user_a, orgs):
    bad = _valid_fact(user_a.sub, orgs["a"]) | {"type": "astrological"}
    with pytest.raises(APIError) as excinfo:
        db_a.table("facts").insert(bad).execute()
    assert excinfo.value.code == CHECK_VIOLATION


@pytest.mark.parametrize("confidence", [-0.1, 1.5])
def test_out_of_range_confidence_rejected(db_a, user_a, orgs, confidence):
    bad = _valid_fact(user_a.sub, orgs["a"]) | {"confidence": confidence}
    with pytest.raises(APIError) as excinfo:
        db_a.table("facts").insert(bad).execute()
    assert excinfo.value.code == CHECK_VIOLATION


# ---------------------------------------------------------------------------
# Service role (pipeline path) bypasses RLS by design
# ---------------------------------------------------------------------------


def test_service_role_sees_all_test_rows(a_fact, db_service, user_a, user_b):
    rows = (
        db_service.table("facts")
        .select("id,user_id")
        .in_("user_id", [user_a.sub, user_b.sub])
        .execute()
        .data
    )
    assert {row["id"] for row in rows} == {a_fact["id"]}
