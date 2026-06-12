"""Murray Context Ledger pipeline package.

Intentionally empty in P0. Extraction/import jobs land in P5 and will run with
the service-role client (`server/app/db.py:service_client`) outside the
request path.
"""
