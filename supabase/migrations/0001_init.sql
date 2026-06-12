-- 0001_init — Murray Context Ledger core schema + row-level security.
--
-- Contract notes (downstream phases depend on these):
--   * user_id is text and stores the Auth0 `sub` claim verbatim. We do NOT use
--     Supabase auth.users, so there are no FKs to auth schema and auth.uid()
--     (which casts to uuid) must never be used in policies — Auth0 subs are not
--     UUIDs. Policies compare against auth.jwt()->>'sub'.
--   * The `authenticated` Postgres role is what PostgREST assumes for any JWT
--     carrying role=authenticated (Auth0 ID tokens get this claim via an Auth0
--     Action — see /docs/AUTH.md). The `service_role` has BYPASSRLS and is
--     reserved for pipeline jobs; it never serves request-path traffic.

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------

create table public.facts (
  id            uuid primary key default gen_random_uuid(),
  user_id       text not null,
  type          text not null check (type in
                  ('identity','preference','state','episodic','relationship','style','behavioral')),
  content       text not null,
  confidence    real not null default 0.5 check (confidence >= 0 and confidence <= 1),
  evidence_count int not null default 1,
  source        text not null check (source in
                  ('import_chatgpt','import_claude','dump_prompt','mcp_writeback',
                   'save_session','refresh_diff','murray_app','murray_clip','user_manual')),
  source_ref    text,
  scope_tags    text[] not null default '{personal}',
  status        text not null default 'pending_review'
                  check (status in ('pending_review','active','superseded','rejected','archived')),
  superseded_by uuid references public.facts(id),
  first_seen    timestamptz not null default now(),
  last_seen     timestamptz not null default now(),
  created_at    timestamptz not null default now()
);

create table public.clients (
  id           uuid primary key default gen_random_uuid(),
  user_id      text not null,
  display_name text not null,
  granted_scopes text[] not null default '{personal,work}',
  status       text not null default 'active' check (status in ('active','revoked')),
  created_at   timestamptz not null default now(),
  revoked_at   timestamptz
);

create table public.audit_log (
  id          bigint generated always as identity primary key,
  user_id     text not null,
  client_id   uuid references public.clients(id),
  tool        text not null,
  payload_hash text,
  fact_ids    uuid[],
  ts          timestamptz not null default now()
);

create table public.jobs (
  id         uuid primary key default gen_random_uuid(),
  user_id    text not null,
  kind       text not null check (kind in ('import_extraction','refresh_diff')),
  state      text not null default 'uploaded' check (state in
               ('uploaded','parsed','triaged','extracted','merged','review_ready','live','failed')),
  detail     jsonb not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------

create index facts_user_id_status_idx on public.facts (user_id, status);
create index facts_user_id_type_idx   on public.facts (user_id, type);
create index audit_log_user_id_ts_idx on public.audit_log (user_id, ts desc);
create index jobs_user_id_state_idx   on public.jobs (user_id, state);

-- ---------------------------------------------------------------------------
-- Data API privileges
--
-- Current Supabase defaults no longer auto-grant privileges on new public
-- tables to the Data API roles (anon/authenticated/service_role), so grants
-- are explicit. Grants set the ceiling; RLS policies below scope rows within
-- it. The gaps are deliberate:
--   * no DELETE for authenticated anywhere (facts lifecycle is status-driven),
--   * no UPDATE/DELETE on audit_log (append-only, fails loudly with 42501),
--   * nothing at all for anon — unauthenticated requests are hard errors.
-- ---------------------------------------------------------------------------

grant usage on schema public to authenticated, service_role;

grant select, insert, update on table public.facts     to authenticated;
grant select, insert, update on table public.clients   to authenticated;
grant select, insert         on table public.audit_log to authenticated;
grant select, insert, update on table public.jobs      to authenticated;

grant all on table public.facts, public.clients, public.audit_log, public.jobs
  to service_role;

-- ---------------------------------------------------------------------------
-- Row-level security
--
-- RLS is the isolation boundary: request-path access always goes through the
-- anon-key client with the caller's JWT, so Postgres — not application code —
-- enforces per-user ownership. FORCE keeps the table owner subject to RLS as
-- well (BYPASSRLS roles such as service_role are exempt by design).
--
-- Per table, `authenticated` gets select/insert/update scoped to its own rows.
-- There is intentionally NO delete policy on any table (facts lifecycle is
-- status-driven: superseded/archived), and NO update policy on audit_log.
-- ---------------------------------------------------------------------------

alter table public.facts     enable row level security;
alter table public.facts     force  row level security;
alter table public.clients   enable row level security;
alter table public.clients   force  row level security;
alter table public.audit_log enable row level security;
alter table public.audit_log force  row level security;
alter table public.jobs      enable row level security;
alter table public.jobs      force  row level security;

-- facts -----------------------------------------------------------------------

create policy facts_select_own on public.facts
  for select to authenticated
  using (user_id = (select auth.jwt() ->> 'sub'));

create policy facts_insert_own on public.facts
  for insert to authenticated
  with check (user_id = (select auth.jwt() ->> 'sub'));

create policy facts_update_own on public.facts
  for update to authenticated
  using (user_id = (select auth.jwt() ->> 'sub'))
  with check (user_id = (select auth.jwt() ->> 'sub'));

-- clients ---------------------------------------------------------------------

create policy clients_select_own on public.clients
  for select to authenticated
  using (user_id = (select auth.jwt() ->> 'sub'));

create policy clients_insert_own on public.clients
  for insert to authenticated
  with check (user_id = (select auth.jwt() ->> 'sub'));

create policy clients_update_own on public.clients
  for update to authenticated
  using (user_id = (select auth.jwt() ->> 'sub'))
  with check (user_id = (select auth.jwt() ->> 'sub'));

-- audit_log (append-only: select + insert, nothing else) -----------------------

create policy audit_log_select_own on public.audit_log
  for select to authenticated
  using (user_id = (select auth.jwt() ->> 'sub'));

create policy audit_log_insert_own on public.audit_log
  for insert to authenticated
  with check (user_id = (select auth.jwt() ->> 'sub'));

-- Append-only is enforced at two layers: no update/delete policy here, and no
-- update/delete privilege granted above. service_role keeps full privileges
-- for retention jobs.

-- jobs ------------------------------------------------------------------------

create policy jobs_select_own on public.jobs
  for select to authenticated
  using (user_id = (select auth.jwt() ->> 'sub'));

create policy jobs_insert_own on public.jobs
  for insert to authenticated
  with check (user_id = (select auth.jwt() ->> 'sub'));

create policy jobs_update_own on public.jobs
  for update to authenticated
  using (user_id = (select auth.jwt() ->> 'sub'))
  with check (user_id = (select auth.jwt() ->> 'sub'));
