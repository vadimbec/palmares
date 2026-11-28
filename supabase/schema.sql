-- Palmarès Séries : schéma Supabase
-- À coller une fois dans Supabase › SQL Editor › New query › Run.
-- Données : un état complet privé par compte (séries, duels, historique) + une « photo » de classement
-- visible seulement par tes amis acceptés et les membres de tes groupes.

-- ============ Tables ============
create table if not exists public.profiles (
  id uuid primary key references auth.users on delete cascade,
  pseudo text not null check (char_length(pseudo) between 2 and 30 and pseudo !~ '@'),
  created_at timestamptz not null default now()
);
create unique index if not exists profiles_pseudo_key on public.profiles (lower(pseudo));

-- état complet, privé (ce que l'appli garde aujourd'hui dans le navigateur)
create table if not exists public.states (
  user_id uuid primary key references auth.users on delete cascade,
  data jsonb not null,
  updated_at timestamptz not null default now()
);

-- photo du classement (ordre + notes), lisible par les amis et les groupes
create table if not exists public.rankings (
  user_id uuid primary key references auth.users on delete cascade,
  profile jsonb not null,
  updated_at timestamptz not null default now()
);

-- amitiés : a demande, b accepte
create table if not exists public.friendships (
  a uuid not null references auth.users on delete cascade,
  b uuid not null references auth.users on delete cascade,
  status text not null default 'pending' check (status in ('pending', 'accepted')),
  created_at timestamptz not null default now(),
  primary key (a, b),
  check (a <> b)
);

create table if not exists public.groups (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 60),
  invite text not null unique default substr(replace(gen_random_uuid()::text, '-', ''), 1, 16),
  owner uuid references auth.users on delete set null,
  created_at timestamptz not null default now()
);

create table if not exists public.group_members (
  group_id uuid not null references public.groups on delete cascade,
  user_id uuid not null references auth.users on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (group_id, user_id)
);

-- accès explicite : seulement les comptes connectés, jamais les visiteurs anonymes (les règles RLS ci-dessous filtrent les lignes)
revoke all on public.profiles, public.states, public.rankings, public.friendships, public.groups, public.group_members from anon;
grant select, insert, update, delete on public.profiles, public.states, public.rankings to authenticated;
grant select, update, delete on public.friendships to authenticated;
grant select, update on public.groups to authenticated;
grant select, delete on public.group_members to authenticated;

-- ============ Qui voit qui ============
create or replace function public.my_groups() returns setof uuid
language sql stable security definer set search_path = public as $$
  select group_id from group_members where user_id = auth.uid()
$$;

create or replace function public.can_see(owner uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select owner = auth.uid()
    or exists (select 1 from friendships f where f.status = 'accepted'
               and ((f.a = auth.uid() and f.b = owner) or (f.b = auth.uid() and f.a = owner)))
    or exists (select 1 from group_members m where m.user_id = owner and m.group_id in (select my_groups()))
$$;

alter table public.profiles enable row level security;
alter table public.states enable row level security;
alter table public.rankings enable row level security;
alter table public.friendships enable row level security;
alter table public.groups enable row level security;
alter table public.group_members enable row level security;

-- pseudos visibles par les comptes connectés (jamais les adresses mail)
drop policy if exists "profiles lecture" on public.profiles;
create policy "profiles lecture" on public.profiles for select to authenticated using (true);
drop policy if exists "profiles le sien" on public.profiles;
create policy "profiles le sien" on public.profiles for all to authenticated using (id = auth.uid()) with check (id = auth.uid());

drop policy if exists "states le sien" on public.states;
create policy "states le sien" on public.states for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

drop policy if exists "rankings lecture" on public.rankings;
create policy "rankings lecture" on public.rankings for select to authenticated using (public.can_see(user_id));
drop policy if exists "rankings le sien" on public.rankings;
create policy "rankings le sien" on public.rankings for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

drop policy if exists "amities les miennes" on public.friendships;
create policy "amities les miennes" on public.friendships for select to authenticated using (a = auth.uid() or b = auth.uid());
drop policy if exists "amities accepter" on public.friendships;
create policy "amities accepter" on public.friendships for update to authenticated using (b = auth.uid()) with check (b = auth.uid());
drop policy if exists "amities retirer" on public.friendships;
create policy "amities retirer" on public.friendships for delete to authenticated using (a = auth.uid() or b = auth.uid());

drop policy if exists "groupes membres" on public.groups;
create policy "groupes membres" on public.groups for select to authenticated using (id in (select public.my_groups()));
drop policy if exists "groupes proprietaire" on public.groups;
create policy "groupes proprietaire" on public.groups for update to authenticated using (owner = auth.uid()) with check (owner = auth.uid());

drop policy if exists "membres lecture" on public.group_members;
create policy "membres lecture" on public.group_members for select to authenticated using (group_id in (select public.my_groups()));
drop policy if exists "membres quitter" on public.group_members;
create policy "membres quitter" on public.group_members for delete to authenticated using (user_id = auth.uid());

-- ============ Actions (passent par des fonctions pour ne jamais exposer les adresses) ============
-- Demande d'ami par adresse mail ou pseudo. Si l'autre t'avait déjà demandé, l'amitié est acceptée.
create or replace function public.request_friend(target text) returns text
language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid(); other uuid;
begin
  if me is null then return 'non_connecte'; end if;
  select id into other from auth.users where lower(email) = lower(trim(target));
  if other is null then select id into other from profiles where lower(pseudo) = lower(trim(target)); end if;
  if other is null then return 'introuvable'; end if;
  if other = me then return 'toi'; end if;
  if exists (select 1 from friendships where a = other and b = me) then
    update friendships set status = 'accepted' where a = other and b = me; return 'acceptee';
  end if;
  insert into friendships (a, b) values (me, other) on conflict do nothing;
  return 'envoyee';
end $$;

create or replace function public.create_group(gname text) returns text
language plpgsql security definer set search_path = public as $$
declare g groups;
begin
  if auth.uid() is null then raise exception 'non_connecte'; end if;
  insert into groups (name, owner) values (gname, auth.uid()) returning * into g;
  insert into group_members (group_id, user_id) values (g.id, auth.uid());
  return g.invite;
end $$;

create or replace function public.join_group(code text) returns text
language plpgsql security definer set search_path = public as $$
declare g groups;
begin
  if auth.uid() is null then raise exception 'non_connecte'; end if;
  select * into g from groups where invite = code;
  if g.id is null then return null; end if;
  insert into group_members (group_id, user_id) values (g.id, auth.uid()) on conflict do nothing;
  return g.name;
end $$;

revoke all on function public.request_friend(text), public.create_group(text), public.join_group(text) from public, anon;
grant execute on function public.request_friend(text), public.create_group(text), public.join_group(text) to authenticated;
