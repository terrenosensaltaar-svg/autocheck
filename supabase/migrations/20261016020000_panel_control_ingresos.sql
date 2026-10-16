alter table public.ingresos_vehiculos
  add column if not exists estado_reparacion text not null default 'Recibido'
    check (estado_reparacion in ('Recibido', 'En diagnóstico', 'Esperando aprobación', 'Esperando repuestos', 'En reparación', 'Listo para retirar', 'Entregado', 'Cancelado')),
  add column if not exists notas_taller text not null default '',
  add column if not exists updated_at timestamptz not null default now();

create index if not exists ingresos_vehiculos_created_at_idx
  on public.ingresos_vehiculos (created_at desc);

create table if not exists public.panel_admins (
  username text primary key check (char_length(trim(username)) between 3 and 40),
  password_salt text not null,
  password_hash text not null,
  must_change_password boolean not null default true,
  created_at timestamptz not null default now()
);

alter table public.panel_admins enable row level security;
revoke all on table public.panel_admins from public, anon, authenticated;
grant all on table public.panel_admins to service_role;

insert into public.panel_admins (username, password_salt, password_hash, must_change_password)
values ('autocheck-admin', '66c7d1bcc11e6b35ea7d7501729bc2ca', 'e537e4bd417bad3b066bea79186694ea28763bc56e94ff832537a459355b75aa', true)
on conflict (username) do nothing;
