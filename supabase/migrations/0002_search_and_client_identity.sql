-- 0002_search_and_client_identity — P1 (MCP layer) schema additions.
--
--   * Full-text search index for search_context/search tools. The expression
--     matches what PostgREST generates for `content=wfts(english).<query>`
--     (to_tsvector('english', content) @@ websearch_to_tsquery('english', q)),
--     so the planner can use it.
--   * clients.oauth_client_id ties a ledger client row to the OAuth client
--     identity presented in the access token (azp claim, or a stable hash when
--     absent). One row per (user, OAuth client); the MCP layer upserts on
--     first contact and consults status on every call.
--     The column is NOT NULL without a default: nothing has ever written to
--     clients before P1 (the table is empty in every environment), and every
--     P1+ writer must supply the identity.

create index facts_content_fts_idx
  on public.facts
  using gin (to_tsvector('english', content));

alter table public.clients
  add column oauth_client_id text not null;

create unique index clients_user_oauth_client_idx
  on public.clients (user_id, oauth_client_id);
