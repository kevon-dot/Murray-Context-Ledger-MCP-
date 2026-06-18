"""Operator-only seat administration (P6).

Revoking or reinstating a connector seat is a service-role / admin action in v1
— deliberately NOT an authenticated MCP tool, so no seat can mutate another.
These helpers use the RLS-bypassing service client and must never be called on
the request path.

A seat is one ``clients`` row, keyed (org_id, oauth_client_id). Flipping its
status affects only that seat: other seats in the same org (including the org's
Murray connector) keep working. ``_begin`` consults status on every call and
rejects revoked seats with guidance.

Equivalent raw SQL, for environments without this code path:

    update public.clients
       set status = 'revoked', revoked_at = now()
     where org_id = :org_id and oauth_client_id = :oauth_client_id;
"""

from datetime import UTC, datetime
from typing import Any

from app.db import service_client


def set_seat_status(org_id: str, oauth_client_id: str, status: str) -> list[dict[str, Any]]:
    """Set a single seat's status ('active' or 'revoked'); returns updated rows."""
    if status not in ("active", "revoked"):
        raise ValueError("status must be 'active' or 'revoked'")
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
