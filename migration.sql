-- Run once in Supabase > SQL Editor
alter table public.orders add column if not exists deposit numeric not null default 0;
alter table public.orders add column if not exists is_cancelled boolean not null default false;
-- Make sure shop and admin staff may update orders (adjust to your existing policies):
-- create policy "shop_admin_update_orders" on public.orders for update to authenticated
--   using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role in ('shop','admin') and p.is_active))
--   with check (true);
