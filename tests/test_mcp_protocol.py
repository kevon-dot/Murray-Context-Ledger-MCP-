"""MCP protocol-layer tests: handshake, tool listing, auth challenge, RFC 9728.

No database required — nothing here reaches a tool body. The Auth0 JWKS is
stubbed with a local RSA key, exactly as in test_auth.py.
"""

from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

import app.auth as app_auth
from app.config import get_settings
from app.mcp_server import (
    GET_PROFILE_DESCRIPTION,
    SEARCH_CONTEXT_DESCRIPTION,
)
from conftest import make_test_user, mcp_headers, mcp_rpc, mint_access_token

EXPECTED_TOOLS = {
    "get_profile",
    "search_context",
    "get_recent_activity",
    "search",
    "fetch",
    "ping",
    "remember_facts",
    "supersede_fact",
}

# The two spec-quoted descriptions are product surface; pin them verbatim so a
# rewording shows up as a test failure, not a silent behavior change in hosts.
SPEC_GET_PROFILE = (
    "Returns the user's core profile: identity, strongest preferences, and "
    "communication style. Call this once near the start of a conversation to "
    "personalize your responses."
)
SPEC_SEARCH_CONTEXT = (
    "Searches the user's full memory for facts relevant to a topic. Call "
    "whenever the user references something you don't know about them — a "
    "project, a person, a plan, a preference."
)


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
def token(rsa_private_key):
    return mint_access_token(rsa_private_key, make_test_user("proto").sub, "client-proto-test")


def test_protected_resource_metadata_root(api):
    settings = get_settings()
    response = api.get("/.well-known/oauth-protected-resource")
    assert response.status_code == 200
    document = response.json()
    assert document["resource"] == settings.resource_server_url
    assert document["authorization_servers"] == [settings.auth0_issuer]
    assert document["bearer_methods_supported"] == ["header"]


def test_protected_resource_metadata_path_inserted(api):
    settings = get_settings()
    response = api.get("/.well-known/oauth-protected-resource/mcp")
    assert response.status_code == 200
    document = response.json()
    assert document["resource"].rstrip("/") == settings.resource_server_url.rstrip("/")
    assert settings.auth0_issuer in document["authorization_servers"]


def test_unauthenticated_request_gets_401_with_challenge(api):
    response = mcp_rpc(api, "initialize", {"protocolVersion": "2025-06-18"})
    assert response.status_code == 401
    challenge = response.headers.get("WWW-Authenticate", "")
    assert challenge.startswith("Bearer ")
    assert 'resource_metadata="' in challenge
    assert "/.well-known/oauth-protected-resource/mcp" in challenge


def test_garbage_token_gets_401(api):
    response = api.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers=mcp_headers("not-a-real-token"),
    )
    assert response.status_code == 401
    assert "WWW-Authenticate" in response.headers


def test_initialize_handshake(api, token):
    response = mcp_rpc(
        api,
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "0"},
        },
        token,
    )
    assert response.status_code == 200
    result = response.json()["result"]
    assert result["serverInfo"]["name"] == "Murray Context Ledger"
    assert "tools" in result["capabilities"]


def test_tools_list_exact(api, token):
    response = mcp_rpc(api, "tools/list", token=token)
    assert response.status_code == 200
    tools = {tool["name"]: tool for tool in response.json()["result"]["tools"]}

    assert set(tools) == EXPECTED_TOOLS
    assert tools["get_profile"]["description"] == GET_PROFILE_DESCRIPTION == SPEC_GET_PROFILE
    assert (
        tools["search_context"]["description"] == SEARCH_CONTEXT_DESCRIPTION == SPEC_SEARCH_CONTEXT
    )
    for name in EXPECTED_TOOLS:
        assert tools[name]["description"], f"{name} must carry a description"
    # search/fetch must accept the arguments ChatGPT sends.
    assert tools["search"]["inputSchema"]["required"] == ["query"]
    assert tools["fetch"]["inputSchema"]["required"] == ["id"]
