-- 0004_write_path — P4: make the ledger writable by AI clients.
--
-- Two additive columns on already-org-scoped tables (0003). No RLS change: the
-- org-member policies from 0003 already govern who may insert/update facts, and
-- the write tools go through the caller-scoped client so Postgres stays the
-- enforcement boundary.
--
--   * facts.dedupe_key + a partial unique index (org_id, dedupe_key) is the
--     idempotency mechanism. A client supplies a stable key per spoken fact;
--     an identical re-send (same org + key) raises a unique violation that
--     remember_facts swallows as a no-op. Scoped by org_id, so the same key in
--     a different org is a distinct fact. NULL keys are exempt (partial index),
--     so facts written without a key are never deduped.
--   * clients.connector_source names the connector that owns a seat
--     ('murray_app','claude','chatgpt', …) so the audit trail — which already
--     references clients via audit_log.client_id — attributes every write to a
--     writer. Nullable; set at registration / backfilled over time.
--
-- facts.source already enumerates murray_app/murray_clip/mcp_writeback/
-- save_session etc. (0001); it is NOT touched here.

alter table public.facts add column dedupe_key text;

create unique index facts_org_dedupe_idx
  on public.facts(org_id, dedupe_key)
  where dedupe_key is not null;

alter table public.clients add column connector_source text;
