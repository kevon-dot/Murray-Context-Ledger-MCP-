"""Murray contract golden round-trip (P5 gate).

The canonical Henderson field note from docs/MURRAY_CONTRACT.md, sent verbatim
to remember_facts, must validate, store org-scoped + Murray-attributed, land the
right status per confidence, and no-op on an identical re-send. This is the seam
that lets Murray and the Ledger be tested against truth instead of assumption —
keep the payload and the dedupe_key derivation in sync with the doc.
"""

import hashlib
import json
import os
import re
from types import SimpleNamespace
from urllib.parse import urlparse

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import app.auth as app_auth
from app.db import service_client
from app.schemas import FactInput
from conftest import (
    add_membership,
    cleanup_orgs,
    make_test_org,
    make_test_user,
    mcp_call_tool,
    mint_access_token,
)

CLIENT_MURRAY = "client-murray-contract"

# The dedupe_key digests published in docs/MURRAY_CONTRACT.md §4 (worked keys).
DOC_DEDUPE_KEYS = {
    "Insurance claim is open on the roof": (
        "459424b5b5390ae144cf316471b71a72c82be7fb302c95f37c398b56468322ec"
    ),
    "Spouse is the decision-maker": (
        "2816eda7a8d432401b82b1c96f11387f9a7dc699c38a90763118be96b47e7619"
    ),
    "Soft decking on the north slope": (
        "a6f5759edccc2cd39e328ffce402ae6c4ea44876b3a97339c2a909f403d09449"
    ),
}


def _dedupe_key(content: str, source_ref: str, source: str) -> str:
    """The normative derivation from docs/MURRAY_CONTRACT.md §4, verbatim."""
    normalized = re.sub(r"\s+", " ", re.sub(r"[^\w\s]", "", content.lower())).strip()
    basis = f"{normalized}|{source_ref}|{source}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _henderson_payload() -> list[dict]:
    """The canonical 3-fact note from docs/MURRAY_CONTRACT.md §6."""
    ref = "job:henderson"
    facts = [
        ("state", "Insurance claim is open on the roof", 0.95),
        ("relationship", "Spouse is the decision-maker", 0.9),
        ("state", "Soft decking on the north slope", 0.85),
    ]
    return [
        {
            "type": type_,
            "content": content,
            "confidence": confidence,
            "scope_tags": ["account"],
            "source": "murray_app",
            "source_ref": ref,
            "dedupe_key": _dedupe_key(content, ref, "murray_app"),
        }
        for type_, content, confidence in facts
    ]


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
        pytest.fail(f"Refusing to run mutating contract tests against non-local {url!r}.")
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
    user = make_test_user("contract-user")
    org = make_test_org(service, "contract-org")
    add_membership(service, org, user.sub, "rep")
    service.table("clients").insert(
        {
            "org_id": org,
            "user_id": user.sub,
            "oauth_client_id": CLIENT_MURRAY,
            "display_name": "Murray",
            "connector_source": "murray_app",
            "granted_scopes": ["account"],
        }
    ).execute()
    yield {"service": service, "user": user, "org": org}
    cleanup_orgs(service, [user.sub])


@pytest.fixture(scope="module")
def token(rsa_private_key, world):
    return mint_access_token(rsa_private_key, world["user"].sub, CLIENT_MURRAY)


def _structured(result: dict) -> dict:
    assert not result.get("isError"), result
    if "structuredContent" in result:
        return result["structuredContent"]
    return json.loads(result["content"][0]["text"])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_doc_dedupe_keys_match_derivation():
    """The published worked keys must equal the documented algorithm — guards
    the doc against drift."""
    for content, expected in DOC_DEDUPE_KEYS.items():
        assert _dedupe_key(content, "job:henderson", "murray_app") == expected


def test_payload_validates_against_fact_input():
    for fact in _henderson_payload():
        model = FactInput.model_validate(fact)
        assert model.source == "murray_app"


def test_henderson_round_trip(api, world, token):
    payload = _henderson_payload()
    summary = _structured(mcp_call_tool(api, token, "remember_facts", {"facts": payload}))

    # Accepted: all three created, none invalid, attributed to Murray.
    assert summary["counts"] == {"created": 3, "deduped": 0, "invalid": 0}
    assert summary["connector_source"] == "murray_app"
    created_ids = summary["created"]

    stored = (
        world["service"]
        .table("facts")
        .select("id,content,org_id,source,status")
        .in_("id", created_ids)
        .execute()
        .data
    )
    by_content = {row["content"]: row for row in stored}

    # Org-scoped + Murray-sourced.
    for row in stored:
        assert row["org_id"] == world["org"]
        assert row["source"] == "murray_app"

    # Confidence-based status: 0.95 -> active, 0.9 -> active, 0.85 -> pending_review.
    assert by_content["Insurance claim is open on the roof"]["status"] == "active"
    assert by_content["Spouse is the decision-maker"]["status"] == "active"
    assert by_content["Soft decking on the north slope"]["status"] == "pending_review"

    # Re-sending the identical payload no-ops all three.
    resend = _structured(mcp_call_tool(api, token, "remember_facts", {"facts": payload}))
    assert resend["counts"] == {"created": 0, "deduped": 3, "invalid": 0}
    assert set(resend["deduped"]) == set(created_ids)

    # Each fact is audited and attributable to Murray.
    audit = (
        world["service"]
        .table("audit_log")
        .select("fact_ids,client_id")
        .eq("user_id", world["user"].sub)
        .eq("tool", "remember_facts")
        .order("id")
        .execute()
        .data
    )
    assert audit, "the write must be audited"
    first_audit_ids = set(audit[0]["fact_ids"] or [])
    assert set(created_ids).issubset(first_audit_ids)
    client = (
        world["service"]
        .table("clients")
        .select("connector_source")
        .eq("id", audit[0]["client_id"])
        .execute()
        .data
    )
    assert client[0]["connector_source"] == "murray_app"
