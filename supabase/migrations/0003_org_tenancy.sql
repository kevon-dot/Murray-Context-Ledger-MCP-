-- 0003_org_tenancy — P2: multi-tenant re-key (user-within-org).
--
-- Turns the single-user ledger into a team memory without weakening the
-- isolation guarantee. Each fact keeps its owner (user_id, the Auth0 sub) AND
-- gains an org_id; org members share reads; the audit trail stays per-person.
--
-- Isolation moves from per-user to per-org but still lives entirely in
-- Postgres. The new boundary is resolved by ONE function, public.user_org_ids()
-- (security invoker; see section 2), which can only ever return the *calling*
-- user's orgs — it filters on auth.jwt()->>'sub' and reads memberships through
-- that user's own RLS policy. service_role never touches the request path.
--
-- ASSUMPTION: the data tables (facts/clients/audit_log/jobs) are EMPTY
-- (pre-launch). The guard below raises loudly if that is not true, so we never
-- strand un-orged rows behind a NOT NULL org_id. To re-key a populated DB,
-- backfill org_id first and remove the guard.

-- ---------------------------------------------------------------------------
-- 1. Tenancy tables
-- ---------------------------------------------------------------------------

create table public.orgs (
  id         uuid primary key default gen_random_uuid(),
  name       text not null,
  created_at timestamptz not null default now()
);

create table public.memberships (
  id         uuid primary key default gen_random_uuid(),
  org_id     uuid not null references public.orgs(id) on delete cascade,
  user_id    text not null,                       -- Auth0 sub
  role       text not null check (role in ('owner','rep','office')),
  created_at timestamptz not null default now(),
  unique (org_id, user_id)
);

create index memberships_user_idx on public.memberships(user_id);

-- ---------------------------------------------------------------------------
-- 2. Membership resolution — the single most security-sensitive object here.
--
-- Returns ONLY the calling user's org ids. Two deliberate choices, both forced
-- by how Supabase actually runs migrations (and both improvements):
--
--   * In `public`, not `auth`. The migration role cannot create objects in
--     Supabase's managed `auth` schema (permission denied for schema auth), and
--     a `public` function is exactly what makes it observable over the Data API
--     for the function-safety test — PostgREST exposes RPC for `public` only.
--   * SECURITY INVOKER, not definer. The migration role is not a superuser (see
--     above) and therefore has no BYPASSRLS, so a definer function owned by it
--     would still be subject to the force-RLS on memberships and read nothing.
--     As invoker it runs as the caller and reads memberships through the narrow
--     memberships_select_self policy, so it can STRUCTURALLY only ever see the
--     caller's own rows — strictly safer than bypassing RLS (the result is
--     pinned to auth.jwt()->>'sub' by this WHERE clause AND the row policy) and
--     it needs no privileged owner. memberships_select_self also has no
--     recursion risk: that policy does not call this function.
--
-- STABLE so the planner caches it as a once-per-query InitPlan; empty
-- search_path + schema-qualified names so nothing can be shadowed. Do not relax
-- STABLE / search_path / schema-qualification.
-- ---------------------------------------------------------------------------

create or replace function public.user_org_ids()
returns uuid[]
language sql
stable
security invoker
set search_path = ''
as $$
  select coalesce(array_agg(m.org_id), array[]::uuid[])
  from public.memberships m
  where m.user_id = (auth.jwt() ->> 'sub')
$$;

revoke all on function public.user_org_ids() from public;
grant execute on function public.user_org_ids() to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- 3. Empty-table guard — MUST precede the NOT NULL org_id columns.
-- ---------------------------------------------------------------------------

do $$
begin
  if exists (select 1 from public.facts limit 1)
     or exists (select 1 from public.clients limit 1)
     or exists (select 1 from public.audit_log limit 1)
     or exists (select 1 from public.jobs limit 1)
  then
    raise exception
      'P2/0003 assumes empty data tables (pre-launch). Found existing rows. Backfill org_id and remove this guard before applying.';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- 4. org_id on the four data tables (orgs must already exist for the FK).
-- ---------------------------------------------------------------------------

alter table public.facts     add column org_id uuid not null references public.orgs(id);
alter table public.clients   add column org_id uuid not null references public.orgs(id);
alter table public.audit_log add column org_id uuid not null references public.orgs(id);
alter table public.jobs      add column org_id uuid not null references public.orgs(id);

create index facts_org_idx     on public.facts(org_id);
create index clients_org_idx   on public.clients(org_id);
create index audit_log_org_idx on public.audit_log(org_id);
create index jobs_org_idx      on public.jobs(org_id);

-- ---------------------------------------------------------------------------
-- 5. Re-key RLS from per-user to per-org-member.
--
-- Drop every per-user policy, then create org-member policies.
--
-- Membership test idiom: `col = any ((select public.user_org_ids())::uuid[])`.
-- The scalar subselect makes the function an InitPlan the planner evaluates
-- ONCE per query (the same caching trick 0001 uses for auth.jwt()), and the
-- ::uuid[] cast is load-bearing: it forces ANY's array form (membership in the
-- returned uuid[]). Without the cast Postgres parses `(select …)` as a
-- subquery whose single row is a uuid[], and `uuid = uuid[]` fails to typecheck.
-- Inserts still stamp the caller as the row owner (user_id = sub) so the audit
-- trail stays per-person; updates are open to any org member so office can
-- correct/supersede a rep's fact.
-- ---------------------------------------------------------------------------

-- facts -----------------------------------------------------------------------
drop policy facts_select_own on public.facts;
drop policy facts_insert_own on public.facts;
drop policy facts_update_own on public.facts;

create policy facts_select_org on public.facts
  for select to authenticated
  using ( org_id = any ((select public.user_org_ids())::uuid[]) );

create policy facts_insert_org on public.facts
  for insert to authenticated
  with check (
    org_id = any ((select public.user_org_ids())::uuid[])
    and user_id = (select auth.jwt() ->> 'sub')
  );

create policy facts_update_org on public.facts
  for update to authenticated
  using ( org_id = any ((select public.user_org_ids())::uuid[]) )
  with check ( org_id = any ((select public.user_org_ids())::uuid[]) );

-- clients ---------------------------------------------------------------------
drop policy clients_select_own on public.clients;
drop policy clients_insert_own on public.clients;
drop policy clients_update_own on public.clients;

create policy clients_select_org on public.clients
  for select to authenticated
  using ( org_id = any ((select public.user_org_ids())::uuid[]) );

create policy clients_insert_org on public.clients
  for insert to authenticated
  with check (
    org_id = any ((select public.user_org_ids())::uuid[])
    and user_id = (select auth.jwt() ->> 'sub')
  );

create policy clients_update_org on public.clients
  for update to authenticated
  using ( org_id = any ((select public.user_org_ids())::uuid[]) )
  with check ( org_id = any ((select public.user_org_ids())::uuid[]) );

-- audit_log (append-only: select + insert, nothing else) ----------------------
drop policy audit_log_select_own on public.audit_log;
drop policy audit_log_insert_own on public.audit_log;

create policy audit_select_org on public.audit_log
  for select to authenticated
  using ( org_id = any ((select public.user_org_ids())::uuid[]) );

create policy audit_insert_org on public.audit_log
  for insert to authenticated
  with check (
    org_id = any ((select public.user_org_ids())::uuid[])
    and user_id = (select auth.jwt() ->> 'sub')
  );

-- jobs ------------------------------------------------------------------------
drop policy jobs_select_own on public.jobs;
drop policy jobs_insert_own on public.jobs;
drop policy jobs_update_own on public.jobs;

create policy jobs_select_org on public.jobs
  for select to authenticated
  using ( org_id = any ((select public.user_org_ids())::uuid[]) );

create policy jobs_insert_org on public.jobs
  for insert to authenticated
  with check (
    org_id = any ((select public.user_org_ids())::uuid[])
    and user_id = (select auth.jwt() ->> 'sub')
  );

create policy jobs_update_org on public.jobs
  for update to authenticated
  using ( org_id = any ((select public.user_org_ids())::uuid[]) )
  with check ( org_id = any ((select public.user_org_ids())::uuid[]) );

-- ---------------------------------------------------------------------------
-- 6. RLS + grants on the tenancy tables.
--
-- Provisioning is service-role only in v1: authenticated gets SELECT (self /
-- member scoped) and NO insert/update/delete policy. memberships_select_self
-- is what lets the app read the caller's own memberships on the request path
-- (P3) via the caller-scoped client — no service role needed. The SECURITY
-- DEFINER function reads memberships under its owner and is unaffected; do NOT
-- add a broad memberships select policy.
-- ---------------------------------------------------------------------------

alter table public.orgs        enable row level security;
alter table public.orgs        force  row level security;
alter table public.memberships enable row level security;
alter table public.memberships force  row level security;

create policy orgs_select_member on public.orgs
  for select to authenticated
  using ( id = any ((select public.user_org_ids())::uuid[]) );

create policy memberships_select_self on public.memberships
  for select to authenticated
  using ( user_id = (select auth.jwt() ->> 'sub') );

grant select on public.orgs        to authenticated;
grant select on public.memberships to authenticated;
grant all    on public.orgs        to service_role;
grant all    on public.memberships to service_role;

-- ---------------------------------------------------------------------------
-- 7. Re-key client uniqueness from per-user to per-org.
--
-- 0002 keyed clients (user_id, oauth_client_id); connectors are per-org now,
-- so a member registers/updates their org's connector row. oauth_client_id is
-- NOT NULL, so the partial predicate is always true today — it is future-proof
-- against ever relaxing that column.
-- ---------------------------------------------------------------------------

drop index if exists clients_user_oauth_client_idx;
create unique index clients_org_oauth_client_idx
  on public.clients(org_id, oauth_client_id)
  where oauth_client_id is not null;
