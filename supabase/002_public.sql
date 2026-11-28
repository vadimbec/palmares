-- Palmarès : classement public (au choix de chacun). À coller dans SQL Editor › New query › Run.
-- Visible par : soi-même, ses amis acceptés, les membres de ses groupes, et tous les comptes connectés si le classement est public.
alter table public.profiles add column if not exists is_public boolean not null default false;

create or replace function public.can_see(owner uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select owner = auth.uid()
    or exists (select 1 from profiles p where p.id = owner and p.is_public)
    or exists (select 1 from friendships f where f.status = 'accepted'
               and ((f.a = auth.uid() and f.b = owner) or (f.b = auth.uid() and f.a = owner)))
    or exists (select 1 from group_members m where m.user_id = owner and m.group_id in (select my_groups()))
$$;
