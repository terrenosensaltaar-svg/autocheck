create table if not exists public.ingresos_vehiculos (
  id uuid primary key default gen_random_uuid(),
  cliente_nombre text not null check (char_length(trim(cliente_nombre)) between 1 and 160),
  cliente_telefono text not null check (char_length(trim(cliente_telefono)) between 1 and 40),
  vehiculo_marca text not null check (char_length(trim(vehiculo_marca)) between 1 and 80),
  vehiculo_modelo text not null check (char_length(trim(vehiculo_modelo)) between 1 and 120),
  vehiculo_patente text not null default 'A confirmar' check (char_length(trim(vehiculo_patente)) between 1 and 20),
  combustible text not null check (char_length(trim(combustible)) between 1 and 40),
  estado_arranque text not null check (char_length(trim(estado_arranque)) between 1 and 160),
  motivo text not null check (char_length(trim(motivo)) between 1 and 3000),
  modo_llegada text not null check (char_length(trim(modo_llegada)) between 1 and 100),
  fecha_turno date not null,
  franja_turno text not null check (char_length(trim(franja_turno)) between 1 and 100),
  firma_data_url text not null check (char_length(firma_data_url) between 1 and 1000000),
  consentimiento boolean not null check (consentimiento is true),
  fecha_hora_firma timestamptz not null,
  created_at timestamptz not null default now()
);

alter table public.ingresos_vehiculos enable row level security;

revoke all on table public.ingresos_vehiculos from anon, authenticated;
grant insert on table public.ingresos_vehiculos to anon;
grant usage on schema public to anon;

drop policy if exists "Permitir registrar ingresos desde el formulario" on public.ingresos_vehiculos;
create policy "Permitir registrar ingresos desde el formulario"
on public.ingresos_vehiculos
for insert
to anon
with check (consentimiento is true);
