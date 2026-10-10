-- Painel 5W2H — estrutura do banco no Supabase
-- Como usar: Supabase > SQL Editor > New query > cole este arquivo inteiro > Run.
-- Regras: cada usuário vê e edita só os próprios trabalhos; o administrador vê e edita todos.
-- O primeiro usuário cadastrado vira administrador automaticamente.

-- Perfis (um por conta) ------------------------------------------------------
create table if not exists public.perfis (
  id uuid primary key references auth.users on delete cascade,
  nome text not null default '',
  email text not null default '',
  papel text not null default 'usuario' check (papel in ('usuario', 'admin')),
  criado_em timestamptz not null default now()
);

-- Trabalhos (um por profissional analisado) ----------------------------------
create table if not exists public.profissionais (
  id text primary key,
  owner uuid not null default auth.uid() references auth.users on delete cascade,
  dados jsonb not null default '{}'::jsonb,
  atualizado_em timestamptz not null default now()
);
create index if not exists profissionais_owner_idx on public.profissionais (owner);

-- Histórico diário de evolução (alimenta a curva do administrador) ------------
create table if not exists public.historico (
  prof_id text not null references public.profissionais (id) on delete cascade,
  dia date not null default current_date,
  owner uuid not null references auth.users on delete cascade,
  maturidade int not null default 0,
  acoes int not null default 0,
  concluidas int not null default 0,
  primary key (prof_id, dia)
);
create index if not exists historico_owner_idx on public.historico (owner, dia);

-- Configuração do programa (título, empresa, parecer) — só o admin altera ----
create table if not exists public.config (
  id text primary key,
  dados jsonb not null default '{}'::jsonb
);

-- Funções ---------------------------------------------------------------------
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.perfis where id = auth.uid() and papel = 'admin')
$$;

create or replace function public.novo_usuario() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.perfis (id, nome, email, papel)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'nome', ''),
    coalesce(new.email, ''),
    case when exists (select 1 from public.perfis where papel = 'admin') then 'usuario' else 'admin' end
  );
  return new;
end $$;

drop trigger if exists ao_criar_usuario on auth.users;
create trigger ao_criar_usuario after insert on auth.users
  for each row execute function public.novo_usuario();

create or replace function public.protege_papel() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.papel is distinct from old.papel then
    if not public.is_admin() then
      raise exception 'Somente o administrador altera papéis';
    end if;
    if old.id = auth.uid() and new.papel <> 'admin' then
      raise exception 'Você não pode remover o seu próprio acesso de administrador';
    end if;
  end if;
  if new.id is distinct from old.id or new.email is distinct from old.email then
    raise exception 'Campo não pode ser alterado';
  end if;
  return new;
end $$;

drop trigger if exists protege_papel on public.perfis;
create trigger protege_papel before update on public.perfis
  for each row execute function public.protege_papel();

-- Segurança por linha (RLS) ----------------------------------------------------
alter table public.perfis enable row level security;
alter table public.profissionais enable row level security;
alter table public.historico enable row level security;
alter table public.config enable row level security;

drop policy if exists perfis_ler on public.perfis;
create policy perfis_ler on public.perfis for select
  using (id = auth.uid() or public.is_admin());
drop policy if exists perfis_editar on public.perfis;
create policy perfis_editar on public.perfis for update
  using (id = auth.uid() or public.is_admin())
  with check (id = auth.uid() or public.is_admin());

drop policy if exists prof_ler on public.profissionais;
create policy prof_ler on public.profissionais for select
  using (owner = auth.uid() or public.is_admin());
drop policy if exists prof_criar on public.profissionais;
create policy prof_criar on public.profissionais for insert
  with check (owner = auth.uid() or public.is_admin());
drop policy if exists prof_editar on public.profissionais;
create policy prof_editar on public.profissionais for update
  using (owner = auth.uid() or public.is_admin())
  with check (owner = auth.uid() or public.is_admin());
drop policy if exists prof_excluir on public.profissionais;
create policy prof_excluir on public.profissionais for delete
  using (owner = auth.uid() or public.is_admin());

drop policy if exists hist_ler on public.historico;
create policy hist_ler on public.historico for select
  using (owner = auth.uid() or public.is_admin());
drop policy if exists hist_criar on public.historico;
create policy hist_criar on public.historico for insert
  with check (owner = auth.uid() or public.is_admin());
drop policy if exists hist_editar on public.historico;
create policy hist_editar on public.historico for update
  using (owner = auth.uid() or public.is_admin())
  with check (owner = auth.uid() or public.is_admin());

drop policy if exists config_ler on public.config;
create policy config_ler on public.config for select
  using (auth.uid() is not null);
drop policy if exists config_criar on public.config;
create policy config_criar on public.config for insert
  with check (public.is_admin());
drop policy if exists config_editar on public.config;
create policy config_editar on public.config for update
  using (public.is_admin()) with check (public.is_admin());

-- Atualização em tempo real (o admin vê a evolução sem recarregar) -------------
do $$ begin
  alter publication supabase_realtime add table public.profissionais;
exception when duplicate_object then null; end $$;
