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
from pydantic import ValidationError
from supabase import Client

from app.auth import verify_token
from app.config import get_settings
from app.db import client_for_subject
from app.schemas import FactInput

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
REMEMBER_FACTS_DESCRIPTION = (
    "Saves one or more already-structured facts about the account to the team's "
    "shared memory. Each fact needs a `type` (identity, preference, state, "
    "episodic, relationship, style, or behavioral), `content`, and a `confidence` "
    "0..1; optional `scope_tags`, `source`, `source_ref`, and a `dedupe_key` that "
    "makes re-sending the same fact a no-op. Facts at confidence >= 0.9 become "
    "active (team-visible) immediately; lower ones wait in pending_review. "
    "Returns a per-fact summary of what was created, deduped, or rejected."
)
SUPERSEDE_FACT_DESCRIPTION = (
    "Replaces an existing fact with a corrected one: writes the new fact and "
    "retires the old one (status 'superseded', linked via superseded_by). Use "
    "when the account's reality changed or a prior fact was wrong. Pass the old "
    "fact's id and the new fact in the same shape remember_facts accepts."
)

PROFILE_TOKEN_BUDGET = 400
PROFILE_FACT_CAP = 30
SEARCH_CONTEXT_LIMIT = 12
RECENT_ACTIVITY_LIMIT = 10
SNIPPET_CHARS = 200
# Facts at/above this confidence land 'active' (instantly team-visible); below,
# they wait in 'pending_review'. Tunable product knob, not a security boundary.
AUTO_PROMOTE_CONFIDENCE = 0.9

UNIQUE_VIOLATION = "23505"  # Postgres unique_violation (dedupe_key collision)
NOT_FOUND_IN_ORG_MESSAGE = "No fact with that id exists in your org."

# Role-aware read scoping (P6). Narrows what a seat SEES within its org by
# intersecting the client's granted_scopes with the role's allowed scopes. This
# is a product decision (which slice each role gets), NOT a security boundary —
# org isolation is the hard boundary, enforced in Postgres by the RLS policies
# from 0003. Tune freely here. None == no role narrowing (owner sees everything
# its granted_scopes allow).
ROLE_SCOPES: dict[str, set[str] | None] = {
    "owner": None,
    "office": {"account", "work"},
    "rep": {"account", "personal"},
}

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
    # The connector that owns this seat ('murray_app','claude',…), or None until
    # the clients row is registered/backfilled. Every write is attributable to it
    # via audit_log.client_id -> clients.connector_source.
    connector_source: str | None
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
        connector_source=client_row.get("connector_source"),
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
        .select("id,granted_scopes,status,connector_source")
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
                .select("id,granted_scopes,status,connector_source")
                .eq("org_id", org_id)
                .eq("oauth_client_id", oauth_client_id)
                .execute()
                .data[0]
            )
        raise


def _finish(ctx: ToolContext, fact_ids: list[str]) -> None:
    """Append the audit row. Raises on failure, failing the whole request.

    For writes, ``fact_ids`` carries the rows the call created/superseded; the
    connector that wrote them is attributable via client_id -> connector_source.
    """
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
# Write-path helpers (P4)
# ---------------------------------------------------------------------------


def _fact_status(confidence: float) -> str:
    return "active" if confidence >= AUTO_PROMOTE_CONFIDENCE else "pending_review"


def _fact_row(ctx: ToolContext, fact: FactInput) -> dict[str, Any]:
    """The DB row for an inbound fact, stamped with owner + org + auto-promoted
    status. org_id/user_id come from ToolContext, never from the client."""
    row: dict[str, Any] = {
        "org_id": ctx.org_id,
        "user_id": ctx.user_sub,
        "type": fact.type,
        "content": fact.content,
        "confidence": fact.confidence,
        "scope_tags": fact.scope_tags,
        "source": fact.source,
        "status": _fact_status(fact.confidence),
    }
    if fact.source_ref is not None:
        row["source_ref"] = fact.source_ref
    if fact.dedupe_key is not None:
        row["dedupe_key"] = fact.dedupe_key
    return row


def _insert_fact(ctx: ToolContext, fact: FactInput) -> tuple[str, str]:
    """Insert one stamped fact via the caller-scoped client (RLS enforces org
    membership + user_id=sub on the WITH CHECK). Returns (outcome, fact_id),
    outcome ∈ {'created','deduped'}: a dedupe_key collision (same org + key) is
    swallowed as a no-op and resolves to the existing fact's id."""
    try:
        inserted = ctx.db.table("facts").insert(_fact_row(ctx, fact)).execute().data
        return "created", inserted[0]["id"]
    except APIError as exc:
        if exc.code == UNIQUE_VIOLATION and fact.dedupe_key is not None:
            existing = (
                ctx.db.table("facts")
                .select("id")
                .eq("org_id", ctx.org_id)
                .eq("dedupe_key", fact.dedupe_key)
                .execute()
                .data
            )
            if existing:
                return "deduped", existing[0]["id"]
        raise


def _validation_errors(exc: ValidationError) -> list[dict[str, str]]:
    """Flatten a pydantic ValidationError into clear, client-facing entries."""
    return [
        {"field": ".".join(str(p) for p in err["loc"]) or "(root)", "message": err["msg"]}
        for err in exc.errors()
    ]


# ---------------------------------------------------------------------------
# Shared query helpers
# ---------------------------------------------------------------------------


def _effective_scopes(ctx: ToolContext, scopes: list[str] | None = None) -> list[str]:
    """The scopes a read may actually touch: the client's granted scopes (or an
    explicit narrower set), further intersected with the caller's role slice
    (ROLE_SCOPES). owner (None) is unrestricted; office/rep are narrowed. This is
    the single place role visibility is decided — never a cross-org boundary."""
    base = scopes if scopes is not None else ctx.granted_scopes
    role_scopes = ROLE_SCOPES.get(ctx.role)
    if role_scopes is None:
        return list(base)
    return [scope for scope in base if scope in role_scopes]


def _scoped_active_facts(ctx: ToolContext, columns: str, scopes: list[str] | None = None):
    """The one shared scope filter: active facts whose scope_tags intersect the
    caller's role-effective scopes. An empty effective set overlaps nothing, so
    a fully-narrowed seat correctly sees zero facts."""
    return (
        ctx.db.table("facts")
        .select(columns)
        .eq("status", "active")
        .overlaps("scope_tags", _effective_scopes(ctx, scopes))
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
            .overlaps("scope_tags", _effective_scopes(ctx))
            .execute()
        )
        _finish(ctx, [])
        return f"ledger ok — {response.count or 0} active facts for this user."

    @mcp.tool(name="remember_facts", description=REMEMBER_FACTS_DESCRIPTION)
    def remember_facts(facts: list[dict[str, Any]]) -> dict[str, Any]:
        """Batch write. Per-item: a malformed fact is reported and skipped so it
        never drops the rest of a voice note; each accepted fact commits atomically
        (created, or deduped on a dedupe_key collision). Every outcome is audited
        and attributed to the connector via the client row."""
        ctx = _begin("remember_facts", {"facts": facts})
        created: list[str] = []
        deduped: list[str] = []
        invalid: list[dict[str, Any]] = []
        touched: list[str] = []
        for index, raw in enumerate(facts):
            try:
                fact = FactInput.model_validate(raw)
            except ValidationError as exc:
                invalid.append({"index": index, "errors": _validation_errors(exc)})
                continue
            outcome, fact_id = _insert_fact(ctx, fact)
            touched.append(fact_id)
            (created if outcome == "created" else deduped).append(fact_id)
        _finish(ctx, touched)
        return {
            "created": created,
            "deduped": deduped,
            "invalid": invalid,
            "counts": {
                "created": len(created),
                "deduped": len(deduped),
                "invalid": len(invalid),
            },
            "connector_source": ctx.connector_source,
        }

    @mcp.tool(name="supersede_fact", description=SUPERSEDE_FACT_DESCRIPTION)
    def supersede_fact(old_fact_id: str, new_fact: dict[str, Any]) -> dict[str, Any]:
        """Retire one fact and replace it with a corrected one. Single fact, so
        all-or-nothing: an invalid new_fact or an old_fact_id outside the caller's
        org changes nothing. The org-member update policy lets any seat supersede
        any fact in its org (office correcting a rep's fact across a handoff)."""
        ctx = _begin("supersede_fact", {"old_fact_id": old_fact_id, "new_fact": new_fact})
        try:
            uuid_module.UUID(old_fact_id)
        except ValueError:
            _finish(ctx, [])
            raise ValueError(f"'{old_fact_id}' is not a valid fact id.") from None
        try:
            fact = FactInput.model_validate(new_fact)
        except ValidationError as exc:
            _finish(ctx, [])
            return {"superseded": None, "created": None, "invalid": _validation_errors(exc)}

        # Confirm the target is in the caller's org first (RLS-scoped read), so a
        # cross-org or unknown id never creates an orphan replacement.
        target = ctx.db.table("facts").select("id").eq("id", old_fact_id).execute().data
        if not target:
            _finish(ctx, [])
            return {"superseded": None, "created": None, "message": NOT_FOUND_IN_ORG_MESSAGE}

        outcome, new_id = _insert_fact(ctx, fact)
        ctx.db.table("facts").update({"superseded_by": new_id, "status": "superseded"}).eq(
            "id", old_fact_id
        ).execute()
        _finish(ctx, [new_id, old_fact_id])
        return {
            "superseded": old_fact_id,
            "created": new_id,
            "new_status": _fact_status(fact.confidence),
            "deduped": outcome == "deduped",
        }
