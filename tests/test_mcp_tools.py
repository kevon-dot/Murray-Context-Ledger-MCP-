"""MCP tool behavior against the real data plane.

Re-proves the P0 guarantees through the MCP path — host → /mcp → caller-scoped
DB client → Postgres RLS — rather than through PostgREST alone, and proves the
P1 contracts: scope filtering, append-only auditing of every call, revoked
client rejection, the ChatGPT search/fetch shapes, and the get_profile token
budget.
"""

import hashlib
import json
import math
import os
from datetime import UTC, datetime
from types import SimpleNamespace
from urllib.parse import urlparse

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import app.auth as app_auth
from app.db import service_client
from app.mcp_server import PROFILE_TOKEN_BUDGET
from conftest import make_test_user, mcp_call_tool, mint_access_token

B_MARKER = "ZZYZX-B-ONLY-MARKER"
CLIENT_A = "client-claude-test"
CLIENT_B = "client-chatgpt-test"


def _fact(user_sub, type_, content, scopes=("personal",), confidence=0.8):
    return {
        "user_id": user_sub,
        "type": type_,
        "content": content,
        "source": "user_manual",
        "status": "active",
        "scope_tags": list(scopes),
        "confidence": confidence,
    }


@pytest.fixture(scope="module", autouse=True)
def _stack_guard():
    url = os.environ["SUPABASE_URL"]
    host = urlparse(url).hostname
    if host not in {"127.0.0.1", "localhost", "::1"} and not os.environ.get(
        "LEDGER_TESTS_ALLOW_REMOTE"
    ):
        pytest.fail(f"Refusing to run mutating MCP tests against non-local {url!r}.")
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
def user_a():
    return make_test_user("mcp-a")


@pytest.fixture(scope="module")
def user_b():
    return make_test_user("mcp-b")


@pytest.fixture(scope="module")
def user_crowd():
    return make_test_user("mcp-crowd")


@pytest.fixture(scope="module")
def db_service(user_a, user_b, user_crowd):
    service = service_client()
    yield service
    subs = [user_a.sub, user_b.sub, user_crowd.sub]
    for table in ("audit_log", "facts", "jobs", "clients"):
        service.table(table).delete().in_("user_id", subs).execute()


@pytest.fixture(scope="module")
def seeded(db_service, user_a, user_b, user_crowd):
    rows = [
        _fact(
            user_a.sub,
            "identity",
            "Murray Tester is a product designer based in Austin.",
            confidence=0.95,
        ),
        _fact(user_a.sub, "preference", "Prefers espresso over filter coffee.", confidence=0.9),
        _fact(
            user_a.sub,
            "style",
            "Prefers blunt, concise feedback on drafts.",
            scopes=("work",),
            confidence=0.85,
        ),
        _fact(
            user_a.sub,
            "state",
            "Currently migrating the Murray app billing to Stripe.",
            scopes=("work",),
            confidence=0.7,
        ),
        _fact(
            user_a.sub,
            "episodic",
            "Visited the Austin design conference last week.",
            confidence=0.6,
        ),
        _fact(
            user_a.sub,
            "state",
            "Tracking marathon training recovery after an ankle sprain.",
            scopes=("health",),
            confidence=0.75,
        ),
        _fact(user_b.sub, "identity", f"{B_MARKER} belongs to user B and must never leak."),
        _fact(user_b.sub, "preference", f"{B_MARKER} user B prefers tea."),
    ]
    # A crowd of long preference facts to pressure the profile token budget.
    rows += [
        _fact(
            user_crowd.sub,
            "preference",
            f"Crowd preference number {i:03d}: " + ("enjoys long-form documentation " * 6),
            confidence=0.5 + (i % 50) / 100,
        )
        for i in range(200)
    ]
    inserted = db_service.table("facts").insert(rows).execute().data
    by_content = {row["content"]: row for row in inserted}
    return {
        "health_fact": by_content["Tracking marathon training recovery after an ankle sprain."],
        "espresso_fact": by_content["Prefers espresso over filter coffee."],
    }


@pytest.fixture(scope="module")
def token_a(rsa_private_key, user_a):
    return mint_access_token(rsa_private_key, user_a.sub, CLIENT_A)


@pytest.fixture(scope="module")
def token_b(rsa_private_key, user_b):
    return mint_access_token(rsa_private_key, user_b.sub, CLIENT_B)


def _text(result: dict) -> str:
    assert not result.get("isError"), result
    return result["content"][0]["text"]


def _error_text(result: dict) -> str:
    assert result.get("isError"), f"expected tool error, got: {result}"
    return result["content"][0]["text"]


def _structured(result: dict) -> dict:
    assert not result.get("isError"), result
    if "structuredContent" in result:
        return result["structuredContent"]
    return json.loads(result["content"][0]["text"])


def _audit_rows(db_service, user_sub: str, tool: str) -> list[dict]:
    return (
        db_service.table("audit_log")
        .select("*")
        .eq("user_id", user_sub)
        .eq("tool", tool)
        .order("id")
        .execute()
        .data
    )


# ---------------------------------------------------------------------------
# Isolation through the MCP path
# ---------------------------------------------------------------------------


def test_get_profile_returns_own_facts_only(api, token_a, seeded, user_a):
    text = _text(mcp_call_tool(api, token_a, "get_profile"))
    assert "product designer" in text
    assert "espresso" in text
    assert B_MARKER not in text, "ISOLATION BREACH: profile leaked another user's fact"
    # Profile is identity/preference/style only.
    assert "marathon" not in text
    assert "Stripe" not in text


def test_search_cannot_reach_other_users_facts(api, token_a, seeded):
    text = _text(mcp_call_tool(api, token_a, "search_context", {"query": B_MARKER}))
    assert text == f"No stored facts match '{B_MARKER}'."

    results = _structured(mcp_call_tool(api, token_a, "search", {"query": B_MARKER}))
    assert results == {"results": []}


def test_user_b_sees_only_their_facts(api, token_b, seeded):
    text = _text(mcp_call_tool(api, token_b, "get_profile"))
    assert B_MARKER in text
    assert "espresso" not in text, "ISOLATION BREACH: user B saw user A's facts"


def test_fetch_other_users_fact_is_denied(api, token_b, seeded):
    fact_id = seeded["espresso_fact"]["id"]
    message = _error_text(mcp_call_tool(api, token_b, "fetch", {"id": fact_id}))
    assert "not found or not accessible" in message


# ---------------------------------------------------------------------------
# Tool behavior
# ---------------------------------------------------------------------------


def test_search_context_finds_seeded_fact(api, token_a, seeded):
    text = _text(mcp_call_tool(api, token_a, "search_context", {"query": "espresso coffee"}))
    assert "espresso" in text
    assert text.splitlines()[1].startswith("[preference, 0.90]")


def test_get_recent_activity_orders_and_filters(api, token_a, seeded):
    text = _text(mcp_call_tool(api, token_a, "get_recent_activity"))
    assert "Stripe" in text or "conference" in text

    work_only = _text(mcp_call_tool(api, token_a, "get_recent_activity", {"domain": "work"}))
    assert "Stripe" in work_only
    assert "conference" not in work_only

    ungranted = _text(mcp_call_tool(api, token_a, "get_recent_activity", {"domain": "health"}))
    assert ungranted == "Domain 'health' is not within this client's granted scopes."


def test_search_and_fetch_shapes_for_chatgpt(api, token_a, seeded):
    payload = _structured(mcp_call_tool(api, token_a, "search", {"query": "espresso coffee"}))
    assert payload["results"], "seeded fact must be searchable"
    first = payload["results"][0]
    assert set(first) == {"id", "title", "text", "url"}

    fetched = _structured(mcp_call_tool(api, token_a, "fetch", {"id": first["id"]}))
    assert set(fetched) == {"id", "title", "text", "url", "metadata"}
    assert fetched["id"] == first["id"]
    assert fetched["text"] == "Prefers espresso over filter coffee."
    assert fetched["metadata"]["type"] == "preference"


def test_ping_reports_active_fact_count(api, token_a, seeded):
    text = _text(mcp_call_tool(api, token_a, "ping"))
    assert text.startswith("ledger ok — ")
    assert "active facts" in text


# ---------------------------------------------------------------------------
# Scope enforcement (shared filter, proven via a work-only client)
# ---------------------------------------------------------------------------


def test_scope_restricted_client_cannot_reach_health_fact(
    api, rsa_private_key, db_service, user_a, seeded
):
    client_id = "client-scope-test"
    token = mint_access_token(rsa_private_key, user_a.sub, client_id)

    mcp_call_tool(api, token, "ping")  # first contact registers the client
    updated = (
        db_service.table("clients")
        .update({"granted_scopes": ["work"]})
        .eq("user_id", user_a.sub)
        .eq("oauth_client_id", client_id)
        .execute()
        .data
    )
    assert len(updated) == 1

    health_fact = seeded["health_fact"]

    profile = _text(mcp_call_tool(api, token, "get_profile"))
    assert "marathon" not in profile and "espresso" not in profile
    assert "blunt, concise feedback" in profile  # work-scoped style fact remains

    search_text = _text(mcp_call_tool(api, token, "search_context", {"query": "marathon"}))
    assert search_text == "No stored facts match 'marathon'."

    results = _structured(mcp_call_tool(api, token, "search", {"query": "marathon"}))
    assert results == {"results": []}

    recent = _text(mcp_call_tool(api, token, "get_recent_activity"))
    assert "marathon" not in recent

    denied = _error_text(mcp_call_tool(api, token, "fetch", {"id": health_fact["id"]}))
    assert "not found or not accessible" in denied


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------


def test_every_tool_call_appends_exactly_one_audit_row(
    api, rsa_private_key, db_service, user_a, seeded
):
    client_id = "client-audit-test"
    token = mint_access_token(rsa_private_key, user_a.sub, client_id)
    calls = [
        ("get_profile", {}),
        ("search_context", {"query": "espresso"}),
        ("get_recent_activity", {"domain": None}),
        ("search", {"query": "espresso"}),
        ("ping", {}),
    ]
    for tool, arguments in calls:
        before = len(_audit_rows(db_service, user_a.sub, tool))
        mcp_call_tool(api, token, tool, arguments)
        rows = _audit_rows(db_service, user_a.sub, tool)
        assert len(rows) == before + 1, f"{tool} must append exactly one audit row"
        newest = rows[-1]
        canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
        assert newest["payload_hash"] == hashlib.sha256(canonical.encode()).hexdigest()
        assert newest["client_id"], "audit row must reference the clients row"

    # fetch audits the returned fact id.
    fact_id = seeded["espresso_fact"]["id"]
    mcp_call_tool(api, token, "fetch", {"id": fact_id})
    fetch_rows = _audit_rows(db_service, user_a.sub, "fetch")
    assert fetch_rows[-1]["fact_ids"] == [fact_id]

    # search_context audits which facts it returned.
    search_rows = _audit_rows(db_service, user_a.sub, "search_context")
    assert fact_id in (search_rows[-1]["fact_ids"] or [])


# ---------------------------------------------------------------------------
# Revoked client
# ---------------------------------------------------------------------------


def test_revoked_client_is_rejected_with_guidance(api, rsa_private_key, db_service, user_a, seeded):
    client_id = "client-revoked-test"
    token = mint_access_token(rsa_private_key, user_a.sub, client_id)
    mcp_call_tool(api, token, "ping")

    db_service.table("clients").update(
        {"status": "revoked", "revoked_at": datetime.now(UTC).isoformat()}
    ).eq("user_id", user_a.sub).eq("oauth_client_id", client_id).execute()

    before = len(_audit_rows(db_service, user_a.sub, "get_profile"))
    message = _error_text(mcp_call_tool(api, token, "get_profile"))
    assert "revoked" in message
    assert "re-enable it in their ledger dashboard" in message
    # The rejected call is audited too.
    assert len(_audit_rows(db_service, user_a.sub, "get_profile")) == before + 1


# ---------------------------------------------------------------------------
# Token budget
# ---------------------------------------------------------------------------


def test_get_profile_respects_token_budget(api, rsa_private_key, user_crowd, seeded):
    token = mint_access_token(rsa_private_key, user_crowd.sub, "client-budget-test")
    text = _text(mcp_call_tool(api, token, "get_profile"))
    estimated_tokens = math.ceil(len(text) / 4)
    assert estimated_tokens <= PROFILE_TOKEN_BUDGET, (
        f"profile is {estimated_tokens} estimated tokens against a budget of {PROFILE_TOKEN_BUDGET}"
    )
    assert len(text.splitlines()) - 1 <= 30  # header + at most 30 fact lines
