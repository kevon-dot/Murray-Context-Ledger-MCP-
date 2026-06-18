"""MCP protocol layer (P1).

The ledger is an OAuth 2.1 *resource server*; Auth0 is the authorization
server. The MCP Python SDK provides the transport (Streamable HTTP, stateless,
JSON responses) and the auth plumbing: bearer validation via our
``Auth0AccessTokenVerifier``, 401 challenges carrying the RFC 9728 resource
metadata URL, and the protected-resource metadata route itself.

Request flow per tool call:

1. SDK middleware verifies the Auth0 access token (RS256, tenant JWKS,
   audience + issuer) — unauthenticated requests never reach a tool.
2. ``_begin`` exchanges the verified subject for a short-lived caller-scoped
   DB token (RLS enforced by Postgres; see app/db.py), registers/looks up the
   OAuth client in ``clients``, and rejects revoked clients.
3. The tool reads facts through the caller-scoped client, filtered by the
   client's granted scopes (one shared filter).
4. ``_finish`` appends the audit row. Audit failures fail the request — an
   unaudited read is a bug, not a degraded mode.
"""

import hashlib
import json
import math
import uuid as uuid_module
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from postgrest.exceptions import APIError
from supabase import Client

from app.auth import verify_token
from app.config import get_settings
from app.db import client_for_subject

# ---------------------------------------------------------------------------
# Tool descriptions — product surface, written to steer host-model behavior.
# get_profile and search_context are verbatim from the product spec.
# ---------------------------------------------------------------------------

GET_PROFILE_DESCRIPTION = (
    "Returns the user's core profile: identity, strongest preferences, and "
    "communication style. Call this once near the start of a conversation to "
    "personalize your responses."
)
SEARCH_CONTEXT_DESCRIPTION = (
    "Searches the user's full memory for facts relevant to a topic. Call "
    "whenever the user references something you don't know about them — a "
    "project, a person, a plan, a preference."
)
GET_RECENT_ACTIVITY_DESCRIPTION = (
    "Returns the user's recent activity: current state, recent events, and "
    "observed behaviors, newest first. Optionally filter to one life domain "
    "such as 'work' or 'personal'."
)
SEARCH_DESCRIPTION = (
    "Searches the user's memory ledger and returns matching facts as search "
    "results. Use the fetch tool to retrieve the full content of a result by id."
)
FETCH_DESCRIPTION = (
    "Fetches the full content of a single fact from the user's memory ledger "
    "by its id, as returned by the search tool."
)
PING_DESCRIPTION = (
    "Verifies the connection to the user's memory ledger. Returns a short "
    "status line including how many active facts the ledger holds."
)

PROFILE_TOKEN_BUDGET = 400
PROFILE_FACT_CAP = 30
SEARCH_CONTEXT_LIMIT = 12
RECENT_ACTIVITY_LIMIT = 10
SNIPPET_CHARS = 200

REVOKED_CLIENT_MESSAGE = (
    "This client's access to the ledger has been revoked. Ask the user to "
    "re-enable it in their ledger dashboard, then try again."
)
NO_ORG_MESSAGE = (
    "This account is not a member of any ledger org yet. Ask an admin to "
    "provision a seat for you, then try again."
)
MULTI_ORG_MESSAGE = (
    "This account belongs to more than one org, which is not supported in v1. "
    "Each user must map to exactly one org."
)


class Auth0AccessTokenVerifier:
    """SDK TokenVerifier backed by app.auth's Auth0 validation."""

    async def verify_token(self, token: str) -> AccessToken | None:
        from fastapi import HTTPException

        settings = get_settings()
        try:
            claims = verify_token(token, settings)
        except HTTPException:
            return None
        return AccessToken(
            token=token,
            client_id=_oauth_client_identity(claims),
            scopes=str(claims.get("scope", "")).split(),
            expires_at=claims.get("exp"),
            subject=claims["sub"],
            claims=claims,
        )


def _oauth_client_identity(claims: dict[str, Any]) -> str:
    """Stable identity for the OAuth client that obtained the token.

    Auth0 access tokens carry the client ID in ``azp``. If it is ever absent,
    fall back to a stable hash of the token's client-describing metadata so
    repeat calls map to the same ledger client row.
    """
    azp = claims.get("azp")
    if azp:
        return str(azp)
    aud = claims.get("aud")
    aud_text = ",".join(aud) if isinstance(aud, list) else str(aud)
    basis = f"{claims.get('iss', '')}|{aud_text}"
    return "anon-" + hashlib.sha256(basis.encode()).hexdigest()[:16]


def build_mcp() -> FastMCP:
    """Build a fresh FastMCP instance with all six tools registered.

    A factory rather than a module singleton because the SDK's session
    manager is single-use: every app (each test app, each worker) needs its
    own instance.
    """
    settings = get_settings()
    mcp = FastMCP(
        name="Murray Context Ledger",
        instructions=(
            "Personal memory ledger for this user. Call get_profile early in a "
            "conversation; call search_context when the user mentions something "
            "you don't know about them."
        ),
        stateless_http=True,
        json_response=True,
        streamable_http_path="/mcp",
        token_verifier=Auth0AccessTokenVerifier(),
        auth=AuthSettings(
            issuer_url=settings.auth0_issuer,
            resource_server_url=settings.resource_server_url,
        ),
        # The endpoint is reached through tunnels/proxies whose Host varies per
        # run, so the SDK's Host-header allowlist (DNS-rebinding protection) is
        # off: bearer-token auth is the gate, and Host trust belongs to the
        # deployment edge. Browser-credential CSRF does not apply here.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    _register_tools(mcp)
    return mcp


# ---------------------------------------------------------------------------
# Per-call context: caller-scoped DB, client registry, audit
# ---------------------------------------------------------------------------


@dataclass
class ToolContext:
    db: Client
    user_sub: str
    org_id: str
    role: str
    client_row_id: str
    granted_scopes: list[str]
    tool: str
    arguments: dict[str, Any]


def _begin(tool: str, arguments: dict[str, Any]) -> ToolContext:
    token = get_access_token()
    if token is None or not token.subject:
        # The SDK auth middleware should make this unreachable; fail closed.
        raise ValueError("Unauthenticated MCP request reached a tool handler.")
    claims = token.claims or {}
    db = client_for_subject(token.subject, claims.get("email"))
    # Resolve the caller's single org + role BEFORE touching any org-scoped
    # table — the audit row itself carries org_id, so there is nothing to write
    # until this succeeds. Fails closed on 0 or >1 memberships.
    org_id, role = _resolve_membership(db, token.subject)
    client_row = _resolve_client(db, org_id, token.subject, token.client_id)
    ctx = ToolContext(
        db=db,
        user_sub=token.subject,
        org_id=org_id,
        role=role,
        client_row_id=client_row["id"],
        granted_scopes=list(client_row["granted_scopes"]),
        tool=tool,
        arguments=arguments,
    )
    if client_row["status"] == "revoked":
        _finish(ctx, fact_ids=[])  # rejected calls are audited too
        raise ValueError(REVOKED_CLIENT_MESSAGE)
    return ctx


def _resolve_membership(db: Client, user_sub: str) -> tuple[str, str]:
    """Resolve the caller's (org_id, role) from their memberships.

    Read through the caller-scoped client: the ``memberships_select_self`` RLS
    policy returns exactly this user's rows, so no service-role read is needed
    on the request path. v1 binds exactly one org and fails closed otherwise.
    """
    rows = db.table("memberships").select("org_id,role").eq("user_id", user_sub).execute().data
    if not rows:
        raise ValueError(NO_ORG_MESSAGE)
    if len(rows) > 1:
        # TODO(multi-org): v1 deliberately binds a single org. To support
        # switching, accept an org selector on the tool/connector and pick among
        # `rows` here instead of raising — auth.user_org_ids() already returns an
        # array, so the RLS layer needs no change.
        raise ValueError(MULTI_ORG_MESSAGE)
    return rows[0]["org_id"], rows[0]["role"]


def _resolve_client(db: Client, org_id: str, user_sub: str, oauth_client_id: str) -> dict[str, Any]:
    """Find or create the ledger `clients` row for this OAuth client identity.

    Connectors are per-org (keyed (org_id, oauth_client_id), matching
    clients_org_oauth_client_idx), so the same OAuth client is a distinct seat
    in each org. Existing rows are never modified here (in particular, a revoked
    client is not flipped back to active by reconnecting).
    """
    found = (
        db.table("clients")
        .select("id,granted_scopes,status")
        .eq("org_id", org_id)
        .eq("oauth_client_id", oauth_client_id)
        .execute()
        .data
    )
    if found:
        return found[0]
    try:
        inserted = (
            db.table("clients")
            .insert(
                {
                    "org_id": org_id,
                    "user_id": user_sub,
                    "oauth_client_id": oauth_client_id,
                    "display_name": oauth_client_id,
                }
            )
            .execute()
            .data
        )
        return inserted[0]
    except APIError as exc:
        if exc.code == "23505":  # unique violation: concurrent first contact
            return (
                db.table("clients")
                .select("id,granted_scopes,status")
                .eq("org_id", org_id)
                .eq("oauth_client_id", oauth_client_id)
                .execute()
                .data[0]
            )
        raise


def _finish(ctx: ToolContext, fact_ids: list[str]) -> None:
    """Append the audit row. Raises on failure, failing the whole request."""
    payload = json.dumps(ctx.arguments, sort_keys=True, separators=(",", ":"), default=str)
    ctx.db.table("audit_log").insert(
        {
            "user_id": ctx.user_sub,
            "org_id": ctx.org_id,
            "client_id": ctx.client_row_id,
            "tool": ctx.tool,
            "payload_hash": hashlib.sha256(payload.encode()).hexdigest(),
            "fact_ids": fact_ids,
        }
    ).execute()


# ---------------------------------------------------------------------------
# Shared query helpers
# ---------------------------------------------------------------------------


def _scoped_active_facts(ctx: ToolContext, columns: str, scopes: list[str] | None = None):
    """The one shared scope filter: facts whose scope_tags intersect the
    client's granted scopes (optionally narrowed further), active only."""
    effective = scopes if scopes is not None else ctx.granted_scopes
    return (
        ctx.db.table("facts")
        .select(columns)
        .eq("status", "active")
        .overlaps("scope_tags", effective)
    )


def _estimate_tokens(text: str) -> int:
    """Deliberately simple, deterministic budget estimate (~4 chars/token)."""
    return math.ceil(len(text) / 4)


def _fact_line(fact: dict[str, Any], max_chars: int = 300) -> str:
    content = fact["content"]
    if len(content) > max_chars:
        content = content[: max_chars - 1] + "…"
    return f"[{fact['type']}, {fact['confidence']:.2f}] {content}"


def _fact_url(fact_id: str) -> str:
    parsed = urlparse(get_settings().resource_server_url)
    return f"{parsed.scheme}://{parsed.netloc}/facts/{fact_id}"


def _search_facts(ctx: ToolContext, query: str, limit: int) -> list[dict[str, Any]]:
    """Full-text search over fact content, with an ilike fallback for terms
    the websearch parser yields nothing for (stop words, partial words)."""
    columns = "id,type,content,confidence"
    # text_search must terminate the chain (its builder exposes no limit/order)
    # and "web_search" selects PostgREST's wfts → websearch_to_tsquery, which
    # both tolerates free-form user queries and matches the 0002 index.
    rows = (
        _scoped_active_facts(ctx, columns)
        .limit(limit)
        .text_search("content", query, options={"type": "web_search", "config": "english"})
        .execute()
        .data
    )
    if rows:
        return rows
    pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    return (
        _scoped_active_facts(ctx, columns)
        .ilike("content", pattern)
        .order("confidence", desc=True)
        .order("id")
        .limit(limit)
        .execute()
        .data
    )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


def _register_tools(mcp: FastMCP) -> None:
    @mcp.tool(name="get_profile", description=GET_PROFILE_DESCRIPTION)
    def get_profile() -> str:
        ctx = _begin("get_profile", {})
        columns = "id,type,content,confidence"
        identity = (
            _scoped_active_facts(ctx, columns)
            .eq("type", "identity")
            .order("created_at")
            .order("id")
            .limit(PROFILE_FACT_CAP)
            .execute()
            .data
        )
        preferences = (
            _scoped_active_facts(ctx, columns)
            .in_("type", ["preference", "style"])
            .order("confidence", desc=True)
            .order("created_at")
            .order("id")
            .limit(PROFILE_FACT_CAP)
            .execute()
            .data
        )

        header = "Core profile for this user:"
        lines: list[str] = []
        fact_ids: list[str] = []
        budget_used = _estimate_tokens(header)
        for fact in [*identity, *preferences][:PROFILE_FACT_CAP]:
            line = _fact_line(fact)
            cost = _estimate_tokens(line)
            if budget_used + cost > PROFILE_TOKEN_BUDGET:
                break
            lines.append(line)
            fact_ids.append(fact["id"])
            budget_used += cost

        _finish(ctx, fact_ids)
        if not lines:
            return "The ledger holds no active profile facts for this user yet."
        return "\n".join([header, *lines])

    @mcp.tool(name="search_context", description=SEARCH_CONTEXT_DESCRIPTION)
    def search_context(query: str) -> str:
        ctx = _begin("search_context", {"query": query})
        rows = _search_facts(ctx, query, SEARCH_CONTEXT_LIMIT)
        _finish(ctx, [row["id"] for row in rows])
        if not rows:
            return f"No stored facts match '{query}'."
        lines = [_fact_line(row) for row in rows]
        return "\n".join([f"{len(rows)} stored facts match '{query}':", *lines])

    @mcp.tool(name="get_recent_activity", description=GET_RECENT_ACTIVITY_DESCRIPTION)
    def get_recent_activity(domain: str | None = None) -> str:
        ctx = _begin("get_recent_activity", {"domain": domain})
        if domain is not None and domain not in ctx.granted_scopes:
            _finish(ctx, [])
            return f"Domain '{domain}' is not within this client's granted scopes."
        scopes = [domain] if domain is not None else None
        rows = (
            _scoped_active_facts(ctx, "id,type,content,confidence,last_seen", scopes)
            .in_("type", ["state", "episodic", "behavioral"])
            .order("last_seen", desc=True)
            .order("id")
            .limit(RECENT_ACTIVITY_LIMIT)
            .execute()
            .data
        )
        _finish(ctx, [row["id"] for row in rows])
        if not rows:
            scope_note = f" in domain '{domain}'" if domain else ""
            return f"No recent activity facts{scope_note}."
        lines = [f"[{row['type']}, {row['last_seen'][:10]}] {row['content']}" for row in rows]
        return "\n".join(["Recent activity, newest first:", *lines])

    @mcp.tool(name="search", description=SEARCH_DESCRIPTION)
    def search(query: str) -> dict[str, Any]:
        """ChatGPT connector pairing (search half): returns the id/title/text/url
        result shape from OpenAI's connector contract."""
        ctx = _begin("search", {"query": query})
        rows = _search_facts(ctx, query, SEARCH_CONTEXT_LIMIT)
        _finish(ctx, [row["id"] for row in rows])
        results = [
            {
                "id": row["id"],
                "title": f"{row['type']}: {row['content'][:80]}",
                "text": row["content"][:SNIPPET_CHARS],
                "url": _fact_url(row["id"]),
            }
            for row in rows
        ]
        return {"results": results}

    @mcp.tool(name="fetch", description=FETCH_DESCRIPTION)
    def fetch(id: str) -> dict[str, Any]:
        """ChatGPT connector pairing (fetch half)."""
        ctx = _begin("fetch", {"id": id})
        try:
            uuid_module.UUID(id)
        except ValueError:
            _finish(ctx, [])
            raise ValueError(f"'{id}' is not a valid fact id.") from None
        rows = (
            _scoped_active_facts(
                ctx, "id,type,content,confidence,status,scope_tags,source,first_seen,last_seen"
            )
            .eq("id", id)
            .execute()
            .data
        )
        if not rows:
            _finish(ctx, [])
            raise ValueError("Fact not found or not accessible to this client.")
        fact = rows[0]
        _finish(ctx, [fact["id"]])
        return {
            "id": fact["id"],
            "title": f"{fact['type']}: {fact['content'][:80]}",
            "text": fact["content"],
            "url": _fact_url(fact["id"]),
            "metadata": {
                "type": fact["type"],
                "confidence": fact["confidence"],
                "scope_tags": fact["scope_tags"],
                "source": fact["source"],
                "first_seen": fact["first_seen"],
                "last_seen": fact["last_seen"],
            },
        }

    @mcp.tool(name="ping", description=PING_DESCRIPTION)
    def ping() -> str:
        ctx = _begin("ping", {})
        response = (
            ctx.db.table("facts")
            .select("id", count="exact", head=True)
            .eq("status", "active")
            .overlaps("scope_tags", ctx.granted_scopes)
            .execute()
        )
        _finish(ctx, [])
        return f"ledger ok — {response.count or 0} active facts for this user."
