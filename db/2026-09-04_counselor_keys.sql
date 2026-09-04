-- 이어짐: 상담원 개인별 비밀키(봉투 암호화)용 키 보관 테이블
-- 설계: 보안_비밀키_복구_설계.md 참고
-- 실행: Supabase 대시보드 → SQL Editor → 붙여넣고 RUN (구흥모 쌤)
-- 핵심: 서버는 '암호문(wrapped DEK)'만 저장. 비밀키·복구코드·DEK 원본은 절대 저장하지 않음.
--       (암복호화는 브라우저 Web Crypto에서만 수행 = 제로지식)

create table if not exists public.counselor_keys (
  counselor_id     uuid primary key references auth.users(id) on delete cascade,
  dek_by_pass      text not null,   -- base64( salt(16) | iv(12) | AES-GCM(DEK, 비밀키유도키) )
  dek_by_recovery  text not null,   -- base64( salt(16) | iv(12) | AES-GCM(DEK, 복구코드유도키) )
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);

-- 자동 updated_at 갱신
create or replace function public.touch_counselor_keys()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end; $$;

drop trigger if exists trg_touch_counselor_keys on public.counselor_keys;
create trigger trg_touch_counselor_keys
  before update on public.counselor_keys
  for each row execute function public.touch_counselor_keys();

-- RLS: 본인 것만 접근 (wrapped DEK는 비밀키/복구코드 없이는 무용지물이라 읽혀도 정보 유출 없음)
alter table public.counselor_keys enable row level security;

drop policy if exists "본인 키 조회" on public.counselor_keys;
create policy "본인 키 조회" on public.counselor_keys
  for select using (auth.uid() = counselor_id);

drop policy if exists "본인 키 생성" on public.counselor_keys;
create policy "본인 키 생성" on public.counselor_keys
  for insert with check (auth.uid() = counselor_id);

drop policy if exists "본인 키 수정" on public.counselor_keys;
create policy "본인 키 수정" on public.counselor_keys
  for update using (auth.uid() = counselor_id) with check (auth.uid() = counselor_id);

drop policy if exists "본인 키 삭제" on public.counselor_keys;
create policy "본인 키 삭제" on public.counselor_keys
  for delete using (auth.uid() = counselor_id);

-- 접근 권한: 로그인 사용자만 (anon 차단)
revoke all on table public.counselor_keys from anon;
grant select, insert, update, delete on table public.counselor_keys to authenticated;

-- 확인용(선택): 아래 실행 시 RLS=true, 정책 4개가 보여야 함
-- select relname, relrowsecurity from pg_class where relname='counselor_keys';
-- select policyname, cmd from pg_policies where tablename='counselor_keys';
