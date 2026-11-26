-- Jalabiya workshop: full schema migration (Supabase SQL editor).
-- Run the first statement ALONE, then run the rest.
alter type public.order_status add value if not exists 'new' before 'received';

-- ===== part 2 =====
alter table public.orders add column if not exists deposit numeric not null default 0;
alter table public.orders add column if not exists is_cancelled boolean not null default false;
-- Schema reconciliation with the app (additive; tables were empty when applied)
create table if not exists public.customers (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  phone text not null unique,
  created_at timestamptz not null default now()
);
alter table public.customers enable row level security;
drop policy if exists customers_select on public.customers;
drop policy if exists customers_insert on public.customers;
create policy customers_select on public.customers for select using (auth.uid() is not null);
create policy customers_insert on public.customers for insert with check (public.current_role_name() in ('shop','admin'));

do $$ begin
  if exists (select 1 from information_schema.columns where table_schema='public' and table_name='orders' and column_name='phone') then
    alter table public.orders rename column phone to customer_phone;
  end if;
  if exists (select 1 from information_schema.columns where table_schema='public' and table_name='notifications' and column_name='read') then
    alter table public.notifications rename column "read" to is_read;
  end if;
end $$;
alter table public.orders add column if not exists customer_id uuid references public.customers(id);
alter table public.orders add column if not exists photos text[] not null default '{}';
alter table public.orders alter column status set default 'new';

-- Only active staff have a role
create or replace function public.current_role_name() returns public.user_role
language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid() and is_active
$$;

-- New sign-ups never choose their own role; they start inactive until an admin activates them
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, full_name, role, is_active)
  values (new.id, coalesce(new.raw_user_meta_data->>'full_name', new.email), 'shop', false);
  return new;
end $$;

-- Status trigger: notify the right department, run as definer so clients need no insert rights
create or replace function public.on_order_status_change() returns trigger
language plpgsql security definer set search_path = public as $$
declare next_role public.user_role; msg text;
begin
  if (tg_op = 'UPDATE' and old.status is distinct from new.status) or tg_op = 'INSERT' then
    insert into public.order_events (order_id, status, created_by) values (new.id, new.status, auth.uid());
    next_role := case new.status
      when 'new' then 'workshop' when 'received' then 'workshop' when 'cutting' then 'workshop' when 'sewing' then 'workshop'
      when 'finished_sewing' then 'buttons' when 'buttons_in_progress' then 'buttons'
      when 'buttons_finished' then 'shop' when 'ready_for_pickup' then 'shop' when 'delivered' then 'shop' end;
    msg := 'الطلب ' || new.order_number || ' — ' || new.customer_name || ' انتقل إلى حالة جديدة';
    insert into public.notifications (order_id, target_role, message) values (new.id, next_role, msg);
  end if;
  return new;
end $$;
drop policy if exists notifications_insert_all on public.notifications;
drop policy if exists events_insert_all on public.order_events;

-- Profiles: only admins may change role/active; only admins may insert profiles
drop policy if exists profiles_insert_admin on public.profiles;
create policy profiles_insert_admin on public.profiles for insert with check (public.current_role_name() = 'admin');
create or replace function public.guard_profiles() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null and public.current_role_name() is distinct from 'admin'
     and (new.role is distinct from old.role or new.is_active is distinct from old.is_active or new.id is distinct from old.id) then
    raise exception 'only admin can change role or activation';
  end if;
  return new;
end $$;
drop trigger if exists trg_guard_profiles on public.profiles;
create trigger trg_guard_profiles before update on public.profiles for each row execute function public.guard_profiles();

-- Orders: non-shop roles may only advance their own stages and edit their own notes
create or replace function public.guard_orders() returns trigger
language plpgsql security definer set search_path = public as $$
declare r public.user_role := public.current_role_name(); allowed public.order_status[];
begin
  if auth.uid() is null or r = 'admin' then return new; end if;
  if r is null then raise exception 'not allowed'; end if;
  if r = 'shop' then
    if new.status < old.status then raise exception 'only admin can move an order back'; end if;
    return new;
  end if;
  if (to_jsonb(new) - array['status','workshop_notes','buttons_notes','updated_at']) is distinct from (to_jsonb(old) - array['status','workshop_notes','buttons_notes','updated_at']) then
    raise exception 'role % may only change status and its notes', r;
  end if;
  if r <> 'workshop' and new.workshop_notes is distinct from old.workshop_notes then raise exception 'not allowed'; end if;
  if r <> 'buttons' and new.buttons_notes is distinct from old.buttons_notes then raise exception 'not allowed'; end if;
  if new.status is distinct from old.status then
    allowed := case r
      when 'workshop' then array['new','received','cutting','sewing','finished_sewing']::public.order_status[]
      when 'buttons' then array['finished_sewing','buttons_in_progress','buttons_finished']::public.order_status[]
      when 'delivery' then array['ready_for_pickup','delivered']::public.order_status[] end;
    if not (old.status = any(allowed)) or new.status < old.status then raise exception 'stage change not allowed for role %', r; end if;
  end if;
  return new;
end $$;
drop trigger if exists trg_guard_orders on public.orders;
create trigger trg_guard_orders before update on public.orders for each row execute function public.guard_orders();

-- Photo uploads: shop/admin only (bucket stays public-read because the app uses public URLs)
drop policy if exists order_photos_auth_upload on storage.objects;
create policy order_photos_auth_upload on storage.objects for insert with check (bucket_id = 'order-photos' and public.current_role_name() in ('shop','admin'));

do $$ begin
  begin alter publication supabase_realtime add table public.notifications; exception when duplicate_object then null; end;
end $$;

-- Hardening round 2: strict next-stage rule and active-staff-only reads
create or replace function public.guard_orders() returns trigger
language plpgsql security definer set search_path = public as $$
declare r public.user_role := public.current_role_name(); allowed public.order_status[];
begin
  if auth.uid() is null or r = 'admin' then return new; end if;
  if r is null then raise exception 'not allowed'; end if;
  if r = 'shop' then
    if new.status < old.status then raise exception 'only admin can move an order back'; end if;
    return new;
  end if;
  if (to_jsonb(new) - array['status','workshop_notes','buttons_notes','updated_at']) is distinct from (to_jsonb(old) - array['status','workshop_notes','buttons_notes','updated_at']) then
    raise exception 'role % may only change status and its notes', r;
  end if;
  if r <> 'workshop' and new.workshop_notes is distinct from old.workshop_notes then raise exception 'not allowed'; end if;
  if r <> 'buttons' and new.buttons_notes is distinct from old.buttons_notes then raise exception 'not allowed'; end if;
  if new.status is distinct from old.status then
    allowed := case r
      when 'workshop' then array['new','received','cutting','sewing']::public.order_status[]
      when 'buttons' then array['finished_sewing','buttons_in_progress','buttons_finished']::public.order_status[]
      when 'delivery' then array['ready_for_pickup']::public.order_status[] end;
    if not (old.status = any(allowed)) or new.status is distinct from (enum_range(old.status, null))[2] then
      raise exception 'stage change not allowed for role %', r;
    end if;
  end if;
  return new;
end $$;
drop policy if exists orders_select_all on public.orders;
create policy orders_select_all on public.orders for select using (public.current_role_name() is not null);
drop policy if exists customers_select on public.customers;
create policy customers_select on public.customers for select using (public.current_role_name() is not null);
drop policy if exists photos_select_all on public.order_photos;
create policy photos_select_all on public.order_photos for select using (public.current_role_name() is not null);
drop policy if exists events_select_all on public.order_events;
create policy events_select_all on public.order_events for select using (public.current_role_name() is not null);
drop policy if exists profiles_select_all on public.profiles;
create policy profiles_select_all on public.profiles for select using (auth.uid() = id or public.current_role_name() is not null);

-- Private photos: bucket is private; only active staff can read objects (via signed URLs)
update storage.buckets set public = false where id = 'order-photos';
drop policy if exists order_photos_public_read on storage.objects;
drop policy if exists order_photos_staff_read on storage.objects;
create policy order_photos_staff_read on storage.objects for select using (bucket_id = 'order-photos' and public.current_role_name() is not null);


-- ===== Short-ID login (added 2026-11-26) =====
-- profiles.username holds the short login ID. Workers created by ID get auth email <id>@jalabiya.test.
-- (column + trigger change were applied earlier in the SQL editor: alter table public.profiles add column if not exists username text;
--  and handle_new_user() sets username from the ID.)

-- ===== Privacy fix: login_email no longer discloses private emails (2026-11-26) =====
-- Before: login_email(u) looked up auth.users by profiles.username and returned the real email (leaked owner email behind 'admin').
-- After: it derives the login email from the ID only, with no table lookup, so nothing private is returned to anon callers.
create or replace function public.login_email(u text) returns text
language sql immutable set search_path = public as $$ select lower(btrim(u)) || '@jalabiya.test' $$;
-- Owner login email moved to the ID-derived address so ID 'admin' + same password keeps working:
update auth.users set email = 'admin@jalabiya.test', updated_at = now()
  where id = '99d647cc-e180-4fde-a8f3-223bea326684' and email = 'binomer1999@gmail.com';
update auth.identities set identity_data = jsonb_set(identity_data, '{email}', '"admin@jalabiya.test"'), updated_at = now()
  where user_id = '99d647cc-e180-4fde-a8f3-223bea326684' and provider = 'email';

-- ===== ROLLBACK (restores previous behavior and owner access by real email) =====
-- update auth.users set email = 'binomer1999@gmail.com', updated_at = now() where id = '99d647cc-e180-4fde-a8f3-223bea326684';
-- update auth.identities set identity_data = jsonb_set(identity_data, '{email}', '"binomer1999@gmail.com"'), updated_at = now() where user_id = '99d647cc-e180-4fde-a8f3-223bea326684' and provider = 'email';
-- create or replace function public.login_email(u text) returns text language sql stable security definer set search_path to 'public','auth' as $$
--   select a.email::text from auth.users a join public.profiles p on p.id = a.id where lower(p.username) = lower(trim(u)) and p.is_active limit 1 $$;

-- ===== Per-worker order assignment (added 2026-11-26) =====
-- Each order can be assigned to one specific worker per department. NULL = any worker in that department (old behavior).
alter table public.orders add column if not exists assigned_workshop uuid references public.profiles(id) on delete set null;
alter table public.orders add column if not exists assigned_buttons  uuid references public.profiles(id) on delete set null;
alter table public.orders add column if not exists assigned_delivery uuid references public.profiles(id) on delete set null;

create or replace function public.can_see_order(o public.orders) returns boolean
language sql stable security definer set search_path = public as $$
  select case public.current_role_name()
    when 'admin' then true
    when 'shop' then true
    when 'workshop' then o.assigned_workshop is null or o.assigned_workshop = auth.uid()
    when 'buttons'  then o.assigned_buttons  is null or o.assigned_buttons  = auth.uid()
    when 'delivery' then o.assigned_delivery is null or o.assigned_delivery = auth.uid()
    else false end
$$;

drop policy if exists orders_select_all on public.orders;
drop policy if exists orders_select_assigned on public.orders;
create policy orders_select_assigned on public.orders for select using (public.can_see_order(orders));
drop policy if exists orders_update_by_role on public.orders;
create policy orders_update_by_role on public.orders for update using (public.can_see_order(orders));

-- Notifications: department workers only see notifications for orders they can see
drop policy if exists notifications_select_own_role on public.notifications;
create policy notifications_select_own_role on public.notifications for select using (
  public.current_role_name() = 'admin'
  or (target_role = public.current_role_name() and exists (select 1 from public.orders o where o.id = notifications.order_id))
);

-- ROLLBACK:
-- drop policy if exists orders_select_assigned on public.orders;
-- create policy orders_select_all on public.orders for select using (public.current_role_name() is not null);
-- drop policy if exists orders_update_by_role on public.orders;
-- create policy orders_update_by_role on public.orders for update using (public.current_role_name() is not null);
-- drop policy if exists notifications_select_own_role on public.notifications;
-- create policy notifications_select_own_role on public.notifications for select using ((target_role = public.current_role_name()) or (public.current_role_name() = 'admin'));
