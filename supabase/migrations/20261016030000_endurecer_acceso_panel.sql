alter table public.panel_admins
  add column if not exists failed_attempts smallint not null default 0
    check (failed_attempts between 0 and 5),
  add column if not exists locked_until timestamptz;

create or replace function public.registrar_fallo_login_panel(p_username text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_bloqueado boolean;
begin
  update public.panel_admins
  set failed_attempts = least(failed_attempts + 1, 5),
      locked_until = case
        when failed_attempts + 1 >= 5 then now() + interval '15 minutes'
        else locked_until
      end
  where username = p_username
  returning locked_until > now() into v_bloqueado;

  return coalesce(v_bloqueado, false);
end;
$$;

revoke all on function public.registrar_fallo_login_panel(text) from public, anon, authenticated;
grant execute on function public.registrar_fallo_login_panel(text) to service_role;
