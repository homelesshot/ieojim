-- 이어짐: 적대적 리뷰(2026-09-09) 보류 항목 중 "DB 작업" 부분 착수용
-- 문서: 이어짐_적대적리뷰_2026-09-09.md, 보류항목_착수_체크리스트.md 참고
-- 실행: Supabase 대시보드 → SQL Editor → 아래를 "구역별로" 확인하며 실행 (구흥모 쌤)
--
-- ⚠️ 원칙: 이 파일은 통째로 한 번에 RUN하지 말 것. 구역([A]~[C])마다 주의사항을 읽고
--          현재 라이브(homelesshot.github.io, 현장 담당자 실사용 중)를 깨지 않는지 확인 후
--          한 구역씩 실행하세요. [C]는 지금 실행하면 안 되는 항목(경고 블록)입니다.
--
-- 실제 스키마(2026-09-09, 이어짐_v4.html 클라이언트 코드 기준 확인):
--   counselor_profiles(id uuid = auth.uid(), display_name, org, ...)   ← PK 컬럼은 id
--   cases(counselor_id uuid, state_json_enc, ...)
--   counselor_keys(counselor_id uuid, ...)
--   RPC: encrypt_case_field, decrypt_case_field  (decrypt는 클라이언트가 직접 호출함! [C] 참고)


-- ============================================================
-- [A] 🟢 낮음 — Supabase 어드바이저: 함수 search_path 미고정 (안전, 지금 실행 가능)
-- ------------------------------------------------------------
-- 기존 touch_counselor_keys 정의(2026-09-04_counselor_keys.sql)에 search_path 한 줄만 추가.
-- 나머지는 원본과 동일 — security definer로 바꾸지 않음(원래 없었음), 동작 변화 없음.
create or replace function public.touch_counselor_keys()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- (또 다른 어드바이저 경고 "유출된 비밀번호 차단 꺼짐"은 SQL이 아니라 대시보드 토글입니다 →
--  Authentication → Policies/Password → "Leaked password protection" ON. 체크리스트 8번.)


-- ============================================================
-- [B] 🟠 높음 — "조직도 접근 가능" 정책 구현 (SELECT만, 순수 추가 = 비파괴적)
-- ------------------------------------------------------------
-- 목적: 담당자 퇴사·부재 시 관리자(admin)가 그 사례를 "조회"로 인계받을 수 있게.
-- 방식: counselor_profiles에 is_admin 플래그 추가 + cases에 "admin이면 조회" SELECT 정책을
--       "추가"(기존 '본인만 조회' 정책은 그대로 둠 — Postgres는 permissive 정책을 OR로 합치므로
--        본인 접근은 그대로 유지되고, admin 접근만 얹힌다 = 라이브 깨지지 않음).
alter table public.counselor_profiles
  add column if not exists is_admin boolean not null default false;

drop policy if exists "관리자 사례 조회" on public.cases;
create policy "관리자 사례 조회" on public.cases
  for select using (
    exists (
      select 1 from public.counselor_profiles p
      where p.id = auth.uid() and p.is_admin = true
    )
  );

-- 관리자 지정(실제 관리자 계정 uuid로 바꿔서 실행). auth.users에서 uuid 확인 가능.
--   update public.counselor_profiles set is_admin = true where id = '여기에-관리자-uuid';
--
-- ※ 지금은 "조회(SELECT)"만 열었습니다. 관리자가 남의 사례를 "수정"까지 해야 하면 update 정책도
--   같은 방식으로 추가 결정 필요(인계 시나리오상 보통 조회면 충분 → 별도 논의).
-- 확인:  select policyname, cmd from pg_policies where tablename='cases';


-- ============================================================
-- [C] 🟡 중간 — 암호화 함수 SPOF (⚠️ 지금 실행 금지 — 그대로 두면 라이브가 깨짐)
-- ------------------------------------------------------------
-- 리뷰 권고: REVOKE EXECUTE ON FUNCTION decrypt_case_field FROM authenticated
--            (REST를 통한 직접 호출 차단, 서버 내부에서만 복호화)
--
-- ⚠️ 하지만 현재 이어짐_v4.html 클라이언트가 "이어하기(재개)" 시 decrypt_case_field 를
--    RPC로 "직접" 호출합니다(이어짐_v4.html 약 1714행). 지금 REVOKE하면 현장 담당자의
--    이어하기 복호화가 그 즉시 실패합니다. → 실행하기 전에 반드시 먼저:
--      (1) 복호화를 Edge Function(service_role)으로 옮기고 클라는 그 함수를 호출하도록 변경,
--          또는 (2) decrypt 시 소유권(auth.uid()=counselor_id 행의 state_json_enc와 일치)을
--          함수 내부에서 검증하도록 함수 자체를 수정 — 둘 중 하나를 먼저 끝낸 뒤에 아래를 실행.
--
--    -- (선행 작업 완료 후에만 주석 해제)
--    -- revoke execute on function public.decrypt_case_field(/* 시그니처 */) from authenticated;
--
-- 소유권 검증 방식(대안, 라이브 안 깨짐)의 스케치는 체크리스트 4번 참고.
