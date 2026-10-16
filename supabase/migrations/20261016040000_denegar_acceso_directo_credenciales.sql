create policy "Denegar acceso directo a credenciales del panel"
on public.panel_admins
for all
to anon, authenticated
using (false)
with check (false);
