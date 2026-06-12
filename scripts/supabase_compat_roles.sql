-- Supabase-compatible Data API roles for a plain Postgres cluster, used by
-- scripts/no_docker_stack.sh. Mirrors what a real Supabase project provides
-- out of the box: PostgREST logs in as `authenticator` and switches into the
-- role named by the JWT's `role` claim; `service_role` carries BYPASSRLS.
-- Idempotent: safe to run repeatedly.

do $$
begin
  if not exists (select from pg_roles where rolname = 'anon') then
    create role anon nologin noinherit;
  end if;
  if not exists (select from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin noinherit;
  end if;
  if not exists (select from pg_roles where rolname = 'service_role') then
    create role service_role nologin noinherit bypassrls;
  end if;
  if not exists (select from pg_roles where rolname = 'authenticator') then
    -- Local-only password; the no-Docker stack binds to 127.0.0.1.
    create role authenticator login noinherit password 'postgres';
  end if;
end
$$;

grant anon, authenticated, service_role to authenticator;
