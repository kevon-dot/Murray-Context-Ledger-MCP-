"""Org-tenancy gate (P2) — the multi-tenant successor to test_rls_isolation.

Proves three properties of the org re-key, each as load-bearing as the original
single-user isolation gate:

  A. CROSS-ORG ISOLATION  — a member of org B reads zero of org A's facts.
  B. WITHIN-ORG SHARING   — a rep reads facts the owner wrote in the same org
                            (the team-memory property actually works).
  C. FUNCTION SAFETY      — auth.user_org_ids() (observed via the public
                            my_org_ids passthrough) returns ONLY the caller's
                            orgs, despite bypassing RLS internally, and a user
                            with no membership resolves to the empty set.

Every request goes through the production factories (anon key + caller JWT, RLS
in Postgres), exactly like test_rls_isolation.
"""

import os
from urllib.parse import urlparse

import httpx
import pytest

from app.db import service_client, user_client
from conftest import add_membership, cleanup_orgs, make_test_org, make_test_user, mint_user_jwt


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
        pytest.fail(f"Refusing to run mutating org-isolation tests against non-local {url!r}.")
    try:
        httpx.get(
            f"{url}/rest/v1/",
            headers={"apikey": os.environ["SUPABASE_ANON_KEY"]},
            timeout=10,
        )
    except httpx.HTTPError as exc:
        pytest.fail(f"Local Supabase stack unreachable at {url} ({exc}) — see README.")


@pytest.fixture(scope="module")
def user_a():
    return make_test_user("org-a-owner")


@pytest.fixture(scope="module")
def user_a2():
    return make_test_user("org-a-rep")


@pytest.fixture(scope="module")
def user_b():
    return make_test_user("org-b-owner")


@pytest.fixture(scope="module")
def user_none():
    """A verified principal with no membership at all."""
    return make_test_user("org-none")


@pytest.fixture(scope="module")
def db_service(user_a, user_a2, user_b, user_none):
    service = service_client()
    yield service
    cleanup_orgs(service, [user_a.sub, user_a2.sub, user_b.sub, user_none.sub])


@pytest.fixture(scope="module")
def setup(db_service, user_a, user_a2, user_b):
    """orgA = {userA owner, userA2 rep}; orgB = {userB owner}. Each org has its
    own seeded fact, written by its owner."""
    org_a = make_test_org(db_service, "org-a")
    org_b = make_test_org(db_service, "org-b")
    add_membership(db_service, org_a, user_a.sub, "owner")
    add_membership(db_service, org_a, user_a2.sub, "rep")
    add_membership(db_service, org_b, user_b.sub, "owner")

    inserted = (
        db_service.table("facts")
        .insert(
            [
                _fact(user_a.sub, org_a, "orgA fact: prefers espresso"),
                _fact(user_b.sub, org_b, "orgB fact: prefers tea"),
            ]
        )
        .execute()
        .data
    )
    by_content = {row["content"]: row for row in inserted}
    return {
        "org_a": org_a,
        "org_b": org_b,
        "a_fact": by_content["orgA fact: prefers espresso"],
        "b_fact": by_content["orgB fact: prefers tea"],
    }


@pytest.fixture(scope="module")
def db_a(user_a):
    return user_client(mint_user_jwt(user_a))


@pytest.fixture(scope="module")
def db_a2(user_a2):
    return user_client(mint_user_jwt(user_a2))


@pytest.fixture(scope="module")
def db_b(user_b):
    return user_client(mint_user_jwt(user_b))


@pytest.fixture(scope="module")
def db_none(user_none):
    return user_client(mint_user_jwt(user_none))


# ---------------------------------------------------------------------------
# A. Cross-org isolation
# ---------------------------------------------------------------------------


def test_org_b_reads_zero_of_org_a(setup, db_b):
    rows = db_b.table("facts").select("*").execute().data
    contents = {r["content"] for r in rows}
    assert "orgA fact: prefers espresso" not in contents, (
        f"ISOLATION BREACH: org B read org A's facts: {rows}"
    )


def test_org_b_cannot_read_org_a_fact_by_id(setup, db_b):
    rows = db_b.table("facts").select("*").eq("id", setup["a_fact"]["id"]).execute().data
    assert rows == [], "ISOLATION BREACH: org B read org A's fact by id"


def test_org_a_reads_zero_of_org_b(setup, db_a):
    rows = db_a.table("facts").select("*").eq("id", setup["b_fact"]["id"]).execute().data
    assert rows == [], "ISOLATION BREACH: org A read org B's fact by id"


def test_org_b_cannot_update_org_a_fact(setup, db_a, db_b):
    updated = (
        db_b.table("facts")
        .update({"content": "B was here"})
        .eq("id", setup["a_fact"]["id"])
        .execute()
        .data
    )
    assert updated == [], "ISOLATION BREACH: org B updated org A's fact"
    seen_by_a = db_a.table("facts").select("content").eq("id", setup["a_fact"]["id"]).execute().data
    assert seen_by_a == [{"content": "orgA fact: prefers espresso"}]


# ---------------------------------------------------------------------------
# B. Within-org sharing (the team-memory property)
# ---------------------------------------------------------------------------


def test_rep_reads_owner_fact_in_same_org(setup, db_a2):
    """userA2 (rep) must SEE the fact userA (owner) wrote in orgA — shared read
    is the whole point of the re-key, not just that isolation holds."""
    rows = db_a2.table("facts").select("*").eq("id", setup["a_fact"]["id"]).execute().data
    assert len(rows) == 1, "WITHIN-ORG SHARING BROKEN: rep cannot read owner's fact in same org"
    assert rows[0]["user_id"] == setup["a_fact"]["user_id"]  # owner stays the owner
    assert rows[0]["content"] == "orgA fact: prefers espresso"


def test_rep_still_isolated_from_org_b(setup, db_a2):
    rows = db_a2.table("facts").select("*").eq("id", setup["b_fact"]["id"]).execute().data
    assert rows == [], "ISOLATION BREACH: orgA rep read orgB's fact"


# ---------------------------------------------------------------------------
# C. Function safety — auth.user_org_ids() leaks nothing across callers
# ---------------------------------------------------------------------------


def test_user_org_ids_returns_only_callers_org_a(setup, db_a, db_a2):
    assert db_a.rpc("my_org_ids").execute().data == [setup["org_a"]]
    # A second member of the same org resolves to the same single org.
    assert db_a2.rpc("my_org_ids").execute().data == [setup["org_a"]]


def test_user_org_ids_returns_only_callers_org_b(setup, db_b):
    assert db_b.rpc("my_org_ids").execute().data == [setup["org_b"]]


def test_user_org_ids_empty_for_non_member(setup, db_none):
    assert db_none.rpc("my_org_ids").execute().data == []


def test_non_member_sees_zero_facts(setup, db_none):
    """The corollary: empty org set => RLS lets the caller read nothing."""
    rows = db_none.table("facts").select("*").execute().data
    assert rows == [], f"ISOLATION BREACH: a user with no membership read facts: {rows}"
