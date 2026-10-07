# Tasks: 머신 토큰 즉시 폐기

설계: [CHANGE.md](CHANGE.md) (Status: `Proposed (2026-10-07)`) · 결정 기록: [ADR.md](ADR.md) · 증거: [EVIDENCE.md](EVIDENCE.md).
**모든 항목은 미착수이고, 수용(유지보수자가 Q1–Q3을 결정하고 Status를 `Accepted`로 표시) 전에는 "Inspect" 단위만 진행할 수 있다.** 체크 표시는 실제로 끝난 것만 한다.
구현은 기본 꺼짐으로 단계 병합한다. LDAP 항목·ACL·`image/` 변경이 생기면 `.agents/skills/ldapium-directory-change/SKILL.md`를 먼저 로드한다.
경로 접두: `m/` = `ui/backend/internal/machineauth/`, `h/` = `ui/backend/internal/httpapi/`, `c/` = `ui/backend/internal/config/`.
각 항목의 "검수"는 그 항목의 PR이 통과해야 하는 수용 확인이다. 구현 PR은 Class D로 독립 검토(보안 검토)를 받는다.

## Inspect and establish evidence (수용 전 가능)

- [ ] `T-001` (D8, Q7) Keycloak 실측 스파이크(저장소 밖 스크래치, 고정 이미지 `quay.io/keycloak/keycloak:26.7.4` — 부모 EVIDENCE §2와 같은 방식): (a) `aud`에 있는 resource client로 SA 토큰 introspection `active:true` 경로, (b) client 비활성화 뒤 사전 발급 토큰의 introspection 결과, (c) 폐기 엔드포인트(RFC 7009)로 access token을 폐기한 뒤 introspection·JWKS 검증 결과, (d) client not-before 정책 존재·의미, (e) 인증서 바인딩 토큰 발급 여부(`cnf.x5t#S256`). 비밀(토큰 서명, secret) 미기록.
      검수: 결과를 EVIDENCE.md에 추가하고 D8·D10의 "미검증" 문구를 실측 결과로 교체. 결과로 D8이 바뀌면 CHANGE.md Revision으로 기록.
- [ ] `T-002` (D3, Q2) 디렉터리 실측: `ldapium:e2e` 이미지의 스키마에서 폐기 항목에 쓸 기존 속성·objectClass 후보와 그 `ou` 위치를 확정하고, 기본 머신 ACL(`docs/machine-ldap-account.md` `{0}`–`{2}`)이 후보 위치를 `M`으로 읽게 하는지(그리고 `userPassword` 등 비밀 속성은 여전히 못 읽는지)를 새 컨테이너에서 `ldapsearch -D $MACHINE_DN`으로 확인. `B`를 좁힌 구성도 1건. 후보가 없으면 스키마 확장 필요 여부를 Q2에 기록.
      검수: 명령·출력을 EVIDENCE.md에 추가. 부수 변경 없음(이미지 불변).
- [ ] `T-003` (REQ-001, REQ-008) 기준선: 현재 요청 경로의 `jti` 미사용·요청당 bind·`serve` 순서(`h/machine.go:284-345`)를 재확인하고, 기존 드릴(`scripts/test/test-machine-revocation-drill.py`, 18 검사)의 현 결과를 기록(성공·실패 포함).
      검수: 재현 명령과 출력.
- [ ] `T-004` (Q5, 성능) 갱신 부하 추정: 항목 10000개 subtree 조회의 응답 크기·지연을 새 컨테이너에서 측정(상한 `MAX_ENTRIES`, 1 MiB 근거 확인).
      검수: 측정값을 EVIDENCE.md에. 측정 못 하면 그 사실을 기록.
- [ ] `T-005` (수용) 유지보수자 결정: Q1–Q10 결정을 CHANGE.md "Resolved questions"로 기록, Owner 지정, 보안 재검토(Codex critic 계약: 규칙 재작성 금지, 결함·경합·오류 처리·보안·호환·과복잡·테스트 누락·운영 위험만 나열, 깨끗하면 `PASS`) 통과, Status `Accepted` 표시(유지보수자만).
      검수: BLOCKER 없음.

## Implement (수용 이후, 순서대로; 각 단위는 단독으로 검증되고 기능 꺼짐 상태에서 기존 테스트를 통과한다)

- [ ] `T-010` (REQ-005, D12, REQ-007) 설정: `c/machine.go`에 `MACHINE_REVOCATION_ENABLED`(기본 false; false면 하위 값을 읽지 않음), `_REFRESH`(1–60 s, 기본 5 s), `_MAX_STALE`(`REFRESH`–10 m, 기본 3×REFRESH), `_MAX_ENTRIES`(활성 항목 상한), 위치 설정(Q2 결과). 머신 인증이 꺼져 있으면 무시, 범위 위반·`MAX_STALE < REFRESH`는 기동 실패. 소비자 없음(값만 파싱·검증).
      검수: 단위 — 기본 꺼짐에서 새 env 미독출, 범위 경계, 켠 상태 조합 표.
- [ ] `T-011` (REQ-001, REQ-002, D2, D12) 검증기 claim: `m/claims.go`의 `Principal`에 `IssuedAt`(이미 검증하는 `iat`, `claims.go:121`)와 `JTI`를 추가한다(지금 `Principal`은 둘 다 버린다 — `claims.go:59-64`). `jti`는 정책 플래그 `RequireJTI`가 켜졌을 때만 필수(없음·null·비문자열이면 reason `jti`). 폐기 판정은 하지 않는다.
      검수: 단위 — `RequireJTI` 켬: 누락·null·비문자열 거부, 끔: 기존 표 전 행 결과 불변, 두 필드가 Principal에 실림.
- [ ] `T-012` (REQ-001, REQ-003, REQ-007, D2, D6) 순수 폐기 스냅샷: `m/revocation.go` — `Snapshot{cutoffs, jtis, refreshedAt}`와 `Check(clientID, iat, jti, now) → {ok | revoked | unavailable}`(CHANGE.md 판정 규칙 1–4; jti 항목 건너뜀은 `now > expires+skew+REFRESH+MAX_STALE`일 때만). 시계 주입, 상한.
      검수: 단위 — `iat == T+skew`/`+1` 경계, `expires+skew` 경계에서 jti 항목이 **아직 유효**함(P1 회귀), 건너뜀 경계, `MAX_STALE` 경계(fake clock), 스냅샷 없음, 상한·형식 오류.
- [ ] `T-013` (REQ-006, REQ-010, REQ-012, D3, D7) **항목 쓰기·정리 도구와 LDAP 문서**(소스보다 먼저 — 성장 상한의 예방책이 첫 쓰기와 함께 존재해야 함): `scripts/`에 항목 추가·제거·`prune` 스크립트(추가 시마다 `expires+skew+REFRESH+MAX_STALE`가 지난 jti 항목 삭제; cutoff는 `createTimestamp` 사용, 수정 금지; 토큰·secret은 인자에 쓰지 않음; 활성 항목이 상한 80%를 넘으면 WARN), `docs/machine-ldap-account.md`(위치·ACL 점검, T-002 결과), `docs/machine-auth-operations.md`(순서 ①발급 차단 **확인** → ②기록 → ③같은 토큰 확인 → ④백스톱, D7의 남는 창, 상한 수식, 롤백 시 폐기 해제 주의, 1절 문구를 기능 유무로 분기).
      검수: 새 컨테이너에서 스크립트·문서 명령을 실행해 `ldapsearch`로 결과 확인(`createTimestamp`가 서버 시각임, prune이 활성 항목을 지우지 않음, 80% 경보); 실행하지 않은 명령은 "미실행" 표기. ldapium 코드 변경 없음.
- [ ] `T-014` (REQ-003, REQ-007, REQ-008, D4, D6) 소스·갱신: `h/` 내 구체 소스(LDAP 단일 비행 조회, 머신 bind, 응답 크기·활성 항목 수 상한, 형식 오류=갱신 실패)와 `REFRESH` 주기 갱신 고루틴(종료 시 정지), 스냅샷 준비 상태 노출. 갱신 실패는 직전 스냅샷 유지(`MAX_STALE`까지), ERROR 로그·카운터. 요청 경로 무변경(아직 훅 없음).
      검수: 라이브(LDAP wire는 저장소 원칙상 단위 테스트 안 함) — `T-013` 도구로 쓴 항목이 `REFRESH` 안에 스냅샷에 반영, 제거 반영, 형식 오류 항목 → 갱신 실패 로그·카운터, slapd 중지 시 준비 상태가 `MAX_STALE` 후 not-ready, 복구. 갱신 상태 기계는 주입 소스로 단위.
- [ ] `T-015` (REQ-004, REQ-005, D5) 훅: `h/machine.go` `serve`에서 `Verify` 직후·`budget.acquire` 직전에 `Check`. 폐기=401 `token_invalid`(+`WWW-Authenticate`)·감사 reason `revoked`·`tk.fail()` 계상, 스냅샷 not-ready=503 `unavailable`+`Retry-After`(감사 reason은 `capacity`가 아니라 신규 값 여부를 구현 시 결정하고 닫힌 집합·`docs/audit-event-schema.md`에 반영). 기능 꺼짐은 훅 미설치.
      검수: 단위 — 순서(폐기 거부는 client 예산·scope·bind 이전: bind 카운터 0), **최초 스냅샷 전 첫 요청 503**(이 항목의 책임), 감사 한 줄, IP throttle 계상, 응답 본문이 사유를 말하지 않음, 꺼짐 회귀(`TestMachine_*`).
- [ ] `T-016` (REQ-005, D12) Helm: `charts/ldapium` `ui.machineAuth.revocation.*` 값·렌더(기본 꺼짐 렌더는 이전과 바이트 동일), `charts/ldapium/README.md`, `test-chart-machine-auth.sh` 확장.
      검수: 꺼짐 렌더 diff 0, 켠 렌더 필수 값 검증.
- [ ] `T-017` (REQ-011, AC-001–AC-004, AC-007) 라이브 드릴·CI: 기존 `test-machine-revocation-drill.py`를 확장하거나 새 스크립트로 (a) jti 폐기가 2 replica에서 상한 안에 401·컨테이너 ID 불변, (b) cutoff 경계(서버 `createTimestamp` 기준), (c) slapd 중지 → `MAX_STALE` 후 503, 복구, (d) 형식 오류·상한 초과 항목, (e) 폐기+allowlist 조합, (f) `exp+skew` 경계 근처 jti 항목이 조기 정리되지 않음. CI job `machine bearer auth (real Keycloak)`에 편입(job 이름·path 필터 불변). 전 컨테이너 로그 secret scan.
      검수: 단계별 응답 표와 시각, 최대 지연 ≤ 문서화된 상한 수식, 변이 시험(훅 제거 시 드릴 실패).
- [ ] `T-018` (AC-005) 호환 회귀: 기능 꺼짐·켠 상태(항목 없음) 모두 기존 단위·계약·e2e·드릴(c) 무변경 통과.
      검수: CI 전체 통과.

## Verify and close

- [ ] `T-020` 독립 검토: security-reviewer + Codex critic(위 계약)로 구현 PR 검토, 변이 시험 결과 첨부.
- [ ] `T-021` 문서 동기화: 부모 [CHANGE.md](../machine-principal-auth/CHANGE.md) Non-goals·D7·위협 모델의 "introspection 후속" 문구에 이 패키지 링크, [IMPLEMENTATION-STATUS](../../IMPLEMENTATION-STATUS.md), 릴리스 노트.
- [ ] `T-022` 이슈 처리: #286은 모든 수용 조건(ADR + 라이브 드릴)이 충족되기 전에는 "Related to #286 (not closing yet)"로 연결. 옵션 C·D, A2, 공유 limiter에 남는 범위는 집중된 후속 이슈로 분리(AGENTS.md "Issue tracker convention").
