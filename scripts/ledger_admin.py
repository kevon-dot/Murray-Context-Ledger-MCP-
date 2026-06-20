#!/usr/bin/env python3
"""Operator CLI for ledger provisioning (service-role; never the request path).

Provisioning is service-role only in v1, so this is how an operator stands up an
org, grants seats, and registers connectors. It reads the same settings as the
app (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY / SUPABASE_JWT_SECRET / …) from the
environment or a local .env, and prints each result as JSON.

Examples:
    uv run python scripts/ledger_admin.py create-org --name "Henderson Roofing"
    uv run python scripts/ledger_admin.py add-member --org <ORG_ID> --user 'auth0|abc' --role owner
    uv run python scripts/ledger_admin.py register-connector --org <ORG_ID> \
        --client-id murray-prod --source murray_app --registered-by 'auth0|abc' \
        --scopes account,personal,work
    uv run python scripts/ledger_admin.py revoke-seat --org <ORG_ID> --client-id murray-prod
    uv run python scripts/ledger_admin.py list-members --org <ORG_ID>
"""

import argparse
import json
import os
import sys

# Make `app` importable whether run from the repo root or elsewhere.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "server"))

from app import admin  # noqa: E402


def _scopes(value: str | None) -> list[str] | None:
    if value is None:
        return None
    return [s.strip() for s in value.split(",") if s.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ledger_admin", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create-org", help="Create an org")
    p.add_argument("--name", required=True)
    p.set_defaults(func=lambda a: admin.create_org(a.name))

    sub.add_parser("list-orgs", help="List all orgs").set_defaults(func=lambda a: admin.list_orgs())

    p = sub.add_parser("add-member", help="Add or re-role a member")
    p.add_argument("--org", required=True)
    p.add_argument("--user", required=True, help="Auth0 sub")
    p.add_argument("--role", required=True, choices=admin.MEMBERSHIP_ROLES)
    p.set_defaults(func=lambda a: admin.add_member(a.org, a.user, a.role))

    p = sub.add_parser("remove-member", help="Remove a member")
    p.add_argument("--org", required=True)
    p.add_argument("--user", required=True, help="Auth0 sub")
    p.set_defaults(func=lambda a: admin.remove_member(a.org, a.user))

    p = sub.add_parser("list-members", help="List an org's members")
    p.add_argument("--org", required=True)
    p.set_defaults(func=lambda a: admin.list_members(a.org))

    p = sub.add_parser("register-connector", help="Register/attribute a connector seat")
    p.add_argument("--org", required=True)
    p.add_argument("--client-id", required=True, help="OAuth client id (azp)")
    p.add_argument("--source", required=True, help="connector_source, e.g. murray_app")
    p.add_argument("--registered-by", required=True, help="Auth0 sub provisioning the seat")
    p.add_argument("--display-name")
    p.add_argument("--scopes", help="comma-separated granted scopes")
    p.set_defaults(
        func=lambda a: admin.register_connector(
            a.org, a.client_id, a.source, a.registered_by, a.display_name, _scopes(a.scopes)
        )
    )

    p = sub.add_parser("set-connector-source", help="Backfill a seat's connector_source")
    p.add_argument("--org", required=True)
    p.add_argument("--client-id", required=True)
    p.add_argument("--source", required=True)
    p.set_defaults(func=lambda a: admin.set_connector_source(a.org, a.client_id, a.source))

    p = sub.add_parser("list-connectors", help="List an org's connector seats")
    p.add_argument("--org", required=True)
    p.set_defaults(func=lambda a: admin.list_connectors(a.org))

    p = sub.add_parser("revoke-seat", help="Revoke one connector seat")
    p.add_argument("--org", required=True)
    p.add_argument("--client-id", required=True)
    p.set_defaults(func=lambda a: admin.revoke_seat(a.org, a.client_id))

    p = sub.add_parser("reinstate-seat", help="Re-enable a revoked seat")
    p.add_argument("--org", required=True)
    p.add_argument("--client-id", required=True)
    p.set_defaults(func=lambda a: admin.reinstate_seat(a.org, a.client_id))

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = args.func(args)
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
