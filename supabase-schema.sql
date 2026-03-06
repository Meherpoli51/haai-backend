-- ══════════════════════════════════════════════════════════════
-- HA.AI Supabase Schema
-- Run this entire file in: Supabase Dashboard → SQL Editor → New Query
-- ══════════════════════════════════════════════════════════════

-- ── 1. User profiles table ────────────────────────────────────
create table if not exists public.profiles (
  id              uuid primary key references auth.users(id) on delete cascade,
  email           text not null,
  name            text,
  avatar_url      text,
  credits_remaining   integer not null default 100,
  credits_total_used  integer not null default 0,
  plan            text not null default 'free',  -- 'free' | 'solo' | 'team' | 'agency'
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

-- ── 2. Usage logs table ───────────────────────────────────────
create table if not exists public.usage_logs (
  id          bigserial primary key,
  user_id     uuid not null references public.profiles(id) on delete cascade,
  action_type text not null,  -- 'decode' | 'screen' | 'boolean' | 'quick_score' | 'chat'
  credits_used integer not null,
  metadata    jsonb default '{}',
  created_at  timestamptz not null default now()
);

-- ── 3. RLS (Row Level Security) ───────────────────────────────
-- Users can only read their own profile and usage logs
alter table public.profiles   enable row level security;
alter table public.usage_logs enable row level security;

-- Profiles: user can read/update their own row
create policy "Users can view own profile"
  on public.profiles for select
  using (auth.uid() = id);

create policy "Users can update own profile"
  on public.profiles for update
  using (auth.uid() = id);

-- Usage logs: user can read their own logs
create policy "Users can view own usage"
  on public.usage_logs for select
  using (auth.uid() = user_id);

-- Service role bypasses RLS (backend uses service role key — this is correct)

-- ── 4. deduct_credits RPC function ───────────────────────────
-- Called from backend after successful API call
-- Uses atomic update to prevent race conditions
create or replace function public.deduct_credits(user_id uuid, amount integer)
returns void
language plpgsql
security definer
as $$
begin
  update public.profiles
  set
    credits_remaining   = greatest(0, credits_remaining - amount),
    credits_total_used  = credits_total_used + amount,
    updated_at          = now()
  where id = user_id;
end;
$$;

-- ── 5. Auto-update updated_at on profiles ────────────────────
create or replace function public.handle_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger profiles_updated_at
  before update on public.profiles
  for each row execute function public.handle_updated_at();

-- ── 6. Indexes for performance ────────────────────────────────
create index if not exists usage_logs_user_id_idx on public.usage_logs(user_id);
create index if not exists usage_logs_created_at_idx on public.usage_logs(created_at desc);
create index if not exists profiles_email_idx on public.profiles(email);

-- ── 7. Candidate memory table ────────────────────────────────
create table if not exists public.candidates (
  id              bigserial primary key,
  user_id         uuid not null references public.profiles(id) on delete cascade,
  fingerprint     text not null,           -- name|exp|company dedup key
  name            text not null,
  score           integer not null default 0,
  verdict         text default '',
  hire_decision   text default '',
  jd_snippet      text default '',          -- first 200 chars of JD it was scored against
  metadata        jsonb default '{}',       -- brutal_truth, notice_period etc
  seen_at         timestamptz not null default now(),
  unique(user_id, fingerprint)              -- one record per user per candidate
);

alter table public.candidates enable row level security;

create policy "Users can manage own candidates"
  on public.candidates for all
  using (auth.uid() = user_id);

create index if not exists candidates_user_id_idx on public.candidates(user_id);
create index if not exists candidates_fingerprint_idx on public.candidates(user_id, fingerprint);
create index if not exists candidates_score_idx on public.candidates(user_id, score desc);

-- ══════════════════════════════════════════════════════════════
-- Done. Your schema is ready.
-- Credit costs (set in server.js):
--   decode       = 10 credits
--   screen       = 3 credits per CV
--   boolean      = 5 credits
--   quick_score  = 2 credits
--   chat         = 1 credit
-- New users get 100 free credits on first login.
-- ══════════════════════════════════════════════════════════════
