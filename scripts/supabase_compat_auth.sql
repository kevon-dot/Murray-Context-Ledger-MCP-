-- The auth.jwt() helper exactly as Supabase defines it, for a plain Postgres
-- database (scripts/no_docker_stack.sh). PostgREST publishes the verified JWT
-- claims in the request.jwt.claims GUC; RLS policies read them through this
-- function. Run once per database, before applying migrations.

create schema if not exists auth;

create or replace function auth.jwt()
returns jsonb
language sql
stable
as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')
  )::jsonb
$$;

grant usage on schema auth to anon, authenticated, service_role;
grant execute on function auth.jwt() to anon, authenticated, service_role;
