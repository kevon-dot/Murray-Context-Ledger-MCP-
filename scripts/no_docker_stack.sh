#!/usr/bin/env bash
# Stand up a Supabase-equivalent data plane WITHOUT Docker:
#   native PostgreSQL + the PostgREST static binary + a /rest/v1 prefix proxy.
#
# This exists for sandboxes/CI runners that cannot pull the Supabase images.
# The canonical local stack remains `supabase start` (see README); the test
# suite passes identically against either, with the same default env.
#
# Requires: a local PostgreSQL server (Debian/Ubuntu layout), the `postgrest`
# binary on PATH (https://github.com/PostgREST/postgrest/releases), python3.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_NAME="${LEDGER_DB_NAME:-ledger_local}"
DB_PORT="${LEDGER_DB_PORT:-5432}"
PGRST_PORT="${LEDGER_PGRST_PORT:-3001}"
API_PORT="${LEDGER_API_PORT:-54321}"
# The Supabase CLI's default local JWT secret, so the same test env works
# against both this stack and `supabase start`.
JWT_SECRET="super-secret-jwt-token-with-at-least-32-characters-long"
RUN_DIR="${TMPDIR:-/tmp}/ledger-no-docker-stack"
PGRST_BIN="${PGRST_BIN:-postgrest}"

mkdir -p "$RUN_DIR"

echo "==> PostgreSQL"
if ! pg_isready -q -p "$DB_PORT" 2>/dev/null; then
  service postgresql start || pg_ctlcluster 16 main start
  for _ in $(seq 1 30); do
    pg_isready -q -p "$DB_PORT" 2>/dev/null && break
    sleep 1
  done
fi
pg_isready -p "$DB_PORT"

psql_super() { sudo -u postgres psql -v ON_ERROR_STOP=1 -p "$DB_PORT" "$@"; }

echo "==> Supabase-compatible roles"
psql_super -d postgres -f "$REPO_ROOT/scripts/supabase_compat_roles.sql"

echo "==> Fresh database + auth shim + migrations (the 'supabase db reset' step)"
sudo -u postgres dropdb --if-exists -p "$DB_PORT" "$DB_NAME"
sudo -u postgres createdb -p "$DB_PORT" "$DB_NAME"
psql_super -d "$DB_NAME" -f "$REPO_ROOT/scripts/supabase_compat_auth.sql"
for migration in "$REPO_ROOT"/supabase/migrations/*.sql; do
  echo "    applying $(basename "$migration")"
  psql_super -d "$DB_NAME" -f "$migration" > /dev/null
done

echo "==> PostgREST on :$PGRST_PORT"
pkill -f "$RUN_DIR/postgrest.conf" 2>/dev/null || true
cat > "$RUN_DIR/postgrest.conf" <<EOF
db-uri = "postgres://authenticator:postgres@127.0.0.1:$DB_PORT/$DB_NAME"
db-schemas = "public"
db-anon-role = "anon"
jwt-secret = "$JWT_SECRET"
server-host = "127.0.0.1"
server-port = $PGRST_PORT
EOF
nohup "$PGRST_BIN" "$RUN_DIR/postgrest.conf" > "$RUN_DIR/postgrest.log" 2>&1 &
echo $! > "$RUN_DIR/postgrest.pid"

echo "==> /rest/v1 prefix proxy on :$API_PORT"
pkill -f rest_prefix_proxy.py 2>/dev/null || true
PROXY_PORT="$API_PORT" PGRST_HOST=127.0.0.1 PGRST_PORT="$PGRST_PORT" \
  nohup python3 "$REPO_ROOT/scripts/rest_prefix_proxy.py" > "$RUN_DIR/proxy.log" 2>&1 &
echo $! > "$RUN_DIR/proxy.pid"

echo "==> Waiting for readiness"
ready=""
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$API_PORT/rest/v1/" > /dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ -z "$ready" ]; then
  echo "stack failed to become ready; see $RUN_DIR/*.log" >&2
  exit 1
fi

echo "Stack ready at http://127.0.0.1:$API_PORT (PostgREST :$PGRST_PORT, database $DB_NAME)."
echo "The test suite's defaults already point here — run: uv run pytest"
