"""Operator-only provisioning + seat administration.

Provisioning orgs, memberships, and connectors is a service-role / admin action
in v1 — deliberately NOT an authenticated MCP tool, so nothing on the request
path can create an org, grant a seat, or attribute a connector. Every helper
here uses the RLS-bypassing service client and must never be called while
handling a user request. The operator entrypoint is ``scripts/ledger_admin.py``.

Model recap (see 0003/0004):
  * orgs / memberships carry the tenancy. A user is a member of exactly one org
    in v1, with a role in {owner, rep, office}.
  * A connector seat is one ``clients`` row, keyed (org_id, oauth_client_id).
    ``connector_source`` names the writer (e.g. 'murray_app') so the audit trail
    attributes every write via audit_log.client_id -> clients.connector_source.
    Reps share their org's Murray seat (keyed by Murray's OAuth client id); the
    row's ``user_id`` records who registered it, while each call's audit row
    records the actual rep.
"""

from datetime import UTC, datetime
from typing import Any

from app.db import service_client

MEMBERSHIP_ROLES = ("owner", "rep", "office")
SEAT_STATUSES = ("active", "revoked")


# ---------------------------------------------------------------------------
# Orgs + memberships
# ---------------------------------------------------------------------------


def create_org(name: str) -> dict[str, Any]:
    """Create an org and return its row (id, name, created_at)."""
    if not name or not name.strip():
        raise ValueError("org name must be non-empty")
    return service_client().table("orgs").insert({"name": name}).execute().data[0]


def list_orgs() -> list[dict[str, Any]]:
    return (
        service_client()
        .table("orgs")
        .select("id,name,created_at")
        .order("created_at")
        .execute()
        .data
    )


def add_member(org_id: str, user_sub: str, role: str) -> dict[str, Any]:
    """Add a user to an org with a role, or update their role if already a member.

    Idempotent on (org_id, user_id) so re-running with a new role is how you
    change someone's role.
    """
    if role not in MEMBERSHIP_ROLES:
        raise ValueError(f"role must be one of {MEMBERSHIP_ROLES}, got {role!r}")
    return (
        service_client()
        .table("memberships")
        .upsert(
            {"org_id": org_id, "user_id": user_sub, "role": role},
            on_conflict="org_id,user_id",
        )
        .execute()
        .data[0]
    )


def remove_member(org_id: str, user_sub: str) -> list[dict[str, Any]]:
    """Remove a user's membership in an org. Returns the removed rows (if any)."""
    return (
        service_client()
        .table("memberships")
        .delete()
        .eq("org_id", org_id)
        .eq("user_id", user_sub)
        .execute()
        .data
    )


def list_members(org_id: str) -> list[dict[str, Any]]:
    return (
        service_client()
        .table("memberships")
        .select("user_id,role,created_at")
        .eq("org_id", org_id)
        .order("created_at")
        .execute()
        .data
    )


# ---------------------------------------------------------------------------
# Connector seats
# ---------------------------------------------------------------------------


def register_connector(
    org_id: str,
    oauth_client_id: str,
    connector_source: str,
    registered_by_sub: str,
    display_name: str | None = None,
    granted_scopes: list[str] | None = None,
) -> dict[str, Any]:
    """Register (or re-register) a connector seat for an org with its
    connector_source set, so its writes are attributed from first contact.

    ``registered_by_sub`` records who provisioned the seat (clients.user_id is
    NOT NULL); for a shared app connector like Murray, pass the org owner's sub.
    Idempotent on (org_id, oauth_client_id): re-running updates connector_source
    / display_name / granted_scopes and (re)activates the seat. Uses a
    check-then-write rather than upsert because the clients uniqueness is a
    PARTIAL index (oauth_client_id is not null), which ON CONFLICT cannot infer.
    """
    if not connector_source or not connector_source.strip():
        raise ValueError("connector_source must be non-empty")
    service = service_client()
    row: dict[str, Any] = {
        "org_id": org_id,
        "oauth_client_id": oauth_client_id,
        "connector_source": connector_source,
        "status": "active",
        "revoked_at": None,
    }
    if display_name is not None:
        row["display_name"] = display_name
    if granted_scopes is not None:
        row["granted_scopes"] = granted_scopes

    existing = (
        service.table("clients")
        .select("id")
        .eq("org_id", org_id)
        .eq("oauth_client_id", oauth_client_id)
        .execute()
        .data
    )
    if existing:
        return service.table("clients").update(row).eq("id", existing[0]["id"]).execute().data[0]
    row.setdefault("display_name", display_name or oauth_client_id)
    row["user_id"] = registered_by_sub
    return service.table("clients").insert(row).execute().data[0]


def set_connector_source(
    org_id: str, oauth_client_id: str, connector_source: str
) -> list[dict[str, Any]]:
    """Backfill connector_source on an already-registered seat (e.g. one that a
    client auto-created on first contact with a null source)."""
    if not connector_source or not connector_source.strip():
        raise ValueError("connector_source must be non-empty")
    return (
        service_client()
        .table("clients")
        .update({"connector_source": connector_source})
        .eq("org_id", org_id)
        .eq("oauth_client_id", oauth_client_id)
        .execute()
        .data
    )


def list_connectors(org_id: str) -> list[dict[str, Any]]:
    return (
        service_client()
        .table("clients")
        .select("oauth_client_id,connector_source,status,granted_scopes,user_id")
        .eq("org_id", org_id)
        .order("created_at")
        .execute()
        .data
    )


def set_seat_status(org_id: str, oauth_client_id: str, status: str) -> list[dict[str, Any]]:
    """Set a single seat's status ('active' or 'revoked'); returns updated rows.

    A seat is one (org_id, oauth_client_id) row, so flipping it affects only that
    seat — other seats in the org (including the Murray connector) keep working.
    """
    if status not in SEAT_STATUSES:
        raise ValueError(f"status must be one of {SEAT_STATUSES}")
    revoked_at = datetime.now(UTC).isoformat() if status == "revoked" else None
    return (
        service_client()
        .table("clients")
        .update({"status": status, "revoked_at": revoked_at})
        .eq("org_id", org_id)
        .eq("oauth_client_id", oauth_client_id)
        .execute()
        .data
    )


def revoke_seat(org_id: str, oauth_client_id: str) -> list[dict[str, Any]]:
    """Revoke one connector seat. Other seats in the org are unaffected."""
    return set_seat_status(org_id, oauth_client_id, "revoked")


def reinstate_seat(org_id: str, oauth_client_id: str) -> list[dict[str, Any]]:
    """Re-enable a previously revoked seat."""
    return set_seat_status(org_id, oauth_client_id, "active")
