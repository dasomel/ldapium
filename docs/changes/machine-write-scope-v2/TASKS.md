# Tasks: 머신 쓰기 범위 v2b·v2c

설계: [CHANGE.md](CHANGE.md) (Status: v2b `Accepted` 2026-10-12 — Q2·Q3·Q4·Q7 권고대로; v2c `Proposed`, 승인 아님 — Q1·Q5·Q6 보류; 관련 후속 이슈 #390) · 결정 기록: [ADR.md](ADR.md) · 증거: [EVIDENCE.md](EVIDENCE.md) · 부모: [machine-write-scope TASKS](../machine-write-scope/TASKS.md)(T-026 → 이 패키지 v2b, T-030/T-031 → v2c).
수용 전에는 `Inspect and establish evidence`만 진행할 수 있다. `Implement` 단위는 해당 하위 범위(v2b 또는 v2c)가 수용된 뒤에만 착수하며, 각 단위는 별도 PR·Class D 독립 검토다. 체크 표시는 실제로 끝난 것만 한다.
ACL·LDAP 쓰기 의미·`image/`를 건드리는 작업은 먼저 `.agents/skills/ldapium-directory-change/SKILL.md`를 로드한다. 라이브 LDAP 경로는 모킹하지 않는다(AGENTS.md "Testing philosophy"). 비밀번호 값은 증거·로그·PR 본문에 남기지 않는다(센티널은 일회용 무작위 값, 기록은 "센티널 N건"으로만).
경로 접두: `h/` = `ui/backend/internal/httpapi/`, `l/` = `ui/backend/internal/ldapclient/`, `c/` = `ui/backend/internal/config/`, `f/` = `scripts/test/fixtures/machine-acl/`.

## Inspect and establish evidence (수용 전 가능)

- [x] `T-001` **(2026-10-11, main `049fcc3` 소스 읽기; CHANGE.md P1–P19, EVIDENCE.md §1)** 현재 코드의 사실 확정: 열린 표·카탈로그·거부 목록, `CreateGroup` seed, 잠금 구획 설정·ACL, Password Modify·멱등 비밀번호 모드·사람 비밀번호 한도 키, 닫힌 본문 집합, 비밀번호 정책 기본값, accesslog 기본 ops. 검수: 각 사실의 파일:줄이 EVIDENCE.md §1에 있다.
- [ ] `T-002` (`REQ-005`, `REQ-007`, `REQ-010`, `REQ-012`, `REQ-014`) **라이브 실측 E-01–E-12, E-15–E-23**(실제 slapd, 새 컨테이너, `docker build -t ldapium:e2e -f image/Dockerfile ./image`; macOS/Colima에서는 AGENTS.md의 `docker exec -i`·파생 이미지 규칙). 각 항목의 명령·기대·판정 기준은 EVIDENCE.md §2. 검수: 실제 출력(실패 포함)을 EVIDENCE.md에 보존, 가정이 틀린 결정(D379-3/5/7/8/10/13/14/15)은 CHANGE.md Revision으로 개정하고 영향받는 하위 범위의 수용을 다시 받는다.
- [ ] `T-005` (`REQ-001`–`REQ-017`) **수용 선행**: (v2b) 유지보수자가 CHANGE.md Q2·Q3·Q4 결정과 Status 갱신(**2026-10-12 완료**: Q2·Q3·Q4·Q7 권고대로), security-reviewer 1라운드(BLOCKER 0)(**미완 — 아직 하지 않음**; T-014 개방 전 필요). (v2c) 유지보수자가 Q1·Q5·Q6 결정, **전용 security-reviewer 라운드**와 Codex critic 1회(critic 계약: 재작성 금지, 버그·보안·호환·누락 시험만, 깨끗하면 `PASS`), `E-07`–`E-10`·`E-12`·`E-16`·`E-17`·`E-20`–`E-23` 결과 반영, CHANGE.md "Ship-gating open risks" R-1–R-8 각각이 닫혔거나 유지보수자가 수용으로 기록함(R-4는 닫을 수 없으므로 수용 결정 필수). 검수: CHANGE.md 머리말·Resolved questions에 결정과 검토 결과가 기록됨.

## Implement — v2b (수용 후)

병합 순서: T-010 → T-011 → T-012 → T-013 → T-015 → **T-014(개방)**. T-014 전까지 새 오퍼레이션은 도달 불가다.

- [ ] `T-010` (`REQ-001`, `REQ-003`) **seed 설정과 기동 검증(오퍼레이션 없음)**: `MACHINE_WRITE_GROUP_SEED_DN` 파싱(쓰기 꺼짐이면 읽지 않음), D26 형식, 보호 집합 자동 포함(`c/machine_write_scope.go:235-247`), `M`·`W_*`·관리자와 상이, `directory.groups.create`가 어느 상한에 있으면 필수. 검수: `c/` 단위 표(미설정·형식 오류·동등 변형·보호 집합 포함), 기존 `go test ./internal/config` 통과.
- [ ] `T-011` (`REQ-003`, `REQ-004`, `REQ-005`) **그룹 오퍼레이션 파이프라인(표 미등록)**: 카탈로그 3행, 그룹 생성 DN 형태(`cn`+`GroupCreateBase`, `h/machine_write_pipeline.go:287-296` 분기 추가), 닫힌 본문(`createGroup {cn,description}`, `patchGroup {dn,description}`, `deleteGroup` 쿼리 `dn`), 머신 경로 seed 인자(`l/groups.go` — 사람 경로 `c.dn` 바이트 불변), 허용 목록·특권 그룹 검사를 `patchGroup`/`deleteGroup`에 적용. 검수: AC-002·AC-003·AC-004 단위 부분(시험용 표 주입, `machineDeps.writeOps`), 변이: seed를 `c.dn`으로 되돌림·허용 목록 검사 제거·`cn` 허용 → 실패.
- [ ] `T-012` (`REQ-005`) **`W_data` ACL에 `description`**: `f/write-data.ldif` `{5}`에 `description` 추가, `docs/machine-write-account.md` 동기화, `scripts/test/test-machine-write-acl-live.py`·`test_machine_write_acl_check.py` 확장. 검수: AC-006(`W_data` 부분)·부모 AC-010 조합 재실행, 기존 신원 접근 결과 전후 동일.
- [ ] `T-013` (`REQ-006`, `REQ-007`, `REQ-008`, `REQ-016`) **잠금(표 미등록), 해제는 미개방 유지**: 카탈로그 1행 `lockUser`(`Compartment: "lock"`, `Class: inetOrgPerson`, `IfMatch: true`), 닫힌 본문 `{dn}`, `M` 사전 읽기의 `memberOf` ∩ `MACHINE_WRITE_PRIVILEGED_GROUPS` 거부(`l/machine_write_identity.go`), `W_lock` 꺼짐에서 lock scope 상한 기재 시 기동 실패. `unlockUser`는 카탈로그에도 넣지 않고 `directory.users.unlock`은 미개방 어휘로 남김(D379-7). 검수: AC-005·AC-005b(해제 우회 5종 모두 403·bind 0), 변이: 특권 검사 제거 → 실패, `unlockUser`를 열린 표에 추가 → AC-005b 시험 실패.
- [ ] `T-015` (AC-002–AC-006) **v2b 라이브 드릴**: `scripts/test/test-machine-write-drill.py` 확장(실제 Keycloak 토큰, 새 컨테이너): seed·허용 목록·특권 그룹·`cn` 거부·잠금·해제 우회 거부(AC-005b 5종, 재시작 포함)·특권 그룹 중첩 멤버 잠금 사례(수용한 잔여 위험을 실제 결과로 기록)·구획 경계(`W_lock` 직접 쓰기)·재생·412·428. 검수: 실제 출력·검사 수를 EVIDENCE.md에.
- [ ] `T-014` (`REQ-002`) **v2b 개방**: `machineWriteOps`·`config.MachineWriteOpenScopes`에 4개(`createGroup`, `patchGroup`, `deleteGroup`, `lockUser`) 추가, `machineWriteOpenedBy`에 `D379-3`/`D379-5`/`D379-6`/`D379-7` 인용, 거부 목록에서 제거(`updateGroup`·`unlockUser`는 유지), OpenAPI `security`·`x-machine-scope`, `docs/api.md`·`llms.txt`·`docs/audit-event-schema.md`. 검수: 계약 시험·전수 거부 시험 갱신, AC-001(꺼짐 불변) 재확인, T-015 녹색, Class D 독립 검토 BLOCKER 0.

## Implement — v2c (v2c 수용 후, v2b 병합 후)

병합 순서: T-020 → T-021 → T-029 → T-022 → T-023 → T-028 → T-024 → T-025 → **T-026(개방)** → T-027.

- [ ] `T-020` (`REQ-001`, `REQ-009`) **`W_cred` 설정·기동 검증(오퍼레이션 없음)**: `MACHINE_WRITE_CRED_ENABLED`, `MACHINE_WRITE_CRED_MIN_LENGTH`(기본 12)·`MACHINE_WRITE_CRED_POLICY_DNS`(기본 꺼짐; 꺼지면 `MACHINE_WRITE_CRED_*` 미독), `MACHINE_WRITE_CRED_BIND_DN`/`_PASSWORD`(Secret 관례, 진단에 값 없음), `MACHINE_WRITE_CRED_SUBTREES ⊆ MACHINE_WRITE_SUBTREES`(Q9), 다른 신원과의 `ParseDN` 동등 변형 표, 보호 집합 포함, `writeBindIdentity("cred")`. 검수: `c/` 단위 표, 켜도 오퍼레이션 없음(403).
- [ ] `T-021` (`REQ-010`) **`W_cred` ACL 조각과 라이브 증명**: 신규 `f/write-cred.ldif`(CHANGE.md 스케치: `creatorsName`·표지·`!(userPassword=*)`·특권 filter, 표지 `=z`; `E-07`–`E-09`·`E-16` 결과로 확정)와 `f/write-data.ldif`의 표지 `add` 규칙, `docs/machine-write-account.md` 절, `scripts/test/test-machine-write-acl-live.py` 확장(직접 `ldappasswd`/`ldapmodify`), 순서 계약(부모 D11) 단언, `scripts/test/test-check-machine-write-acl-live.sh` 확장. 검수: AC-007·AC-007b(직접 LDAP 부분) 전부, `E-17` 동시성 재실행, 기존 신원 접근 결과 전후 동일, `M` 읽기 전용 증명 재실행, filter 제거 변이 → 실패.
- [ ] `T-029` (`REQ-018`) **자격 증명 대기 표지(오퍼레이션 없음)**: 머신 `createUser` 닫힌 본문에 `credentialPending`(bool) 추가 — v2c 꺼짐이거나 client 상한에 `password.write`가 없으면 400, 켜져 있으면 Add에 `employeeType: ldapium-credential-pending:<태그>`(태그 = 부모 D9 주체 입력의 SHA-256 앞 16 hex). `patchUser`·사람 DTO 경로는 `employeeType`을 받지 않음을 시험으로 고정. 검수: 태그 계산 표, 표지 없는 생성 바이트 불변, 변이: 태그를 상수로 → 교차 client 시험 실패.
- [ ] `T-022` (`REQ-007`, `REQ-011`, `REQ-012`) **머신 `setPassword` 파이프라인(표 미등록)**: 카탈로그 1행(`Compartment: "cred"`, `IfMatch: false`, 사전 읽기 `inetOrgPerson`+특권 검사+`creatorsName`=`W_data`+표지 태그 == 요청 client 태그), 성공 후 `W_cred`로 표지 값 삭제(실패 시 감사 `cleanup=failed`, 응답은 성공), 닫힌 본문 `{dn,password}`(`oldPassword`·빈 값 거부, `validate.Password`), `If-Match` 존재 시 400, 멱등 비밀번호 모드(`s.idempotent(r.execute, true)`, `h/machine_write_pipeline.go:382`), 사람 `passwordLimiter` 미경유, 오류 메시지 값 미포함. 검수: AC-008·AC-007b(앱 부분: 다른 client 표지 403) 단위 표, 저장 결과 본문 `{}` 단언, 변이: 비밀번호 모드 끔·`oldPassword` 허용·태그 대조 제거 → 실패.
- [ ] `T-023` (`REQ-013`, `REQ-016`) **비밀번호 한도·감사**: 대상 전역 직렬화(키 = `entryUUID`, client 공유, 동시 1건)와 비밀번호 전역 예산(기본 1 rps), `compartment=cred` 감사 줄(비밀번호 필드 없음), `docs/audit-event-schema.md`. 검수: 경계 표, 감사 줄 골든, 패닉·취소 시 해제(`machine_limiter_panic_test.go` 패턴).
- [ ] `T-028` (`REQ-014`, D379-15, D379-16, AC-010b) **실행 시 전제 검사**: 설정 읽기 신원(`MACHINE_WRITE_CRED_ACL_READER_DN`/`_PASSWORD`, 기동 검증·보호 집합)과 그 `cn=config` ACL 규칙(fixture·가이드), subtree별 카나리 DN 설정, CHANGE.md "실행 시 전제 검사" 표 1–8을 기동 시(실패 → 비0 종료)·`setPassword` 직전(실패 → 503)·60초 주기(실패 → 비밀번호 오퍼레이션 503)로 실행, `olcAccess` 원문 대조(앞 규칙·묶음·토큰), 기본·대상별 정책 하한, accesslog 자식 항목 읽기, 결과 코드만 로그(값 없음). 차트: `audit.enabled`와 v2c 동시 활성 렌더 실패, 카나리 생성 가이드(`docs/machine-write-account.md`). 검수: AC-010b 전부(둘째 subtree만 느슨한 구성, base 숨김·자식 read 구성, 검사 후 규칙 삽입 포함; 라이브), `E-21`·`E-22`·`E-23` 결과 반영, 판정 표 단위 시험, 변이: 검사 하나 제거·accesslog 검사를 base 검색으로 되돌림 → 해당 라이브 시나리오 실패.
- [ ] `T-024` (`REQ-012`, `REQ-014`, AC-009, AC-010; 부모 **T-031**) **비밀번호 단계 라이브 증명**: `E-13`(평문 센티널 + 해시 패턴 스캔: 응답·헤더·UI 감사·UI/slapd/Keycloak 컨테이너 로그·`LDAP_AUDIT_ENABLED=true` 구성의 auditlog stdout·`writes` 포함 accesslog의 `reqMod`/`reqOld`를 관리자와 `M` 각각으로), `E-17`(동시 단일 성공) 재실행, `E-10` 재실행(정책 적용), 재생·422·429·ACL 거부 경로 포함. 검수: 평문·해시 0건을 경로별 표로(해시가 나오는 구성은 T-028/차트가 거부하는 구성임을 함께 단언), 실행하지 못한 경로는 "Not verified".
- [ ] `T-025` (`REQ-017`, AC-011) **구획별 긴급 차단 드릴**: `MACHINE_WRITE_CRED_ENABLED=false` 재배포, `W_cred` 회전, 진행 중 요청 상한(`MACHINE_REQUEST_TIMEOUT`) 실측, 다른 구획 영향 없음. `docs/machine-auth-operations.md` "Machine write emergency block" 확장. 검수: 실측값(추정 금지).
- [ ] `T-026` (`REQ-002`) **v2c 개방**: `setPassword`를 `machineWriteOps`·`MachineWriteOpenScopes`에 추가, `machineWriteOpenedBy`에 `D379-9`/`D379-10`, OpenAPI·`docs/api.md`·`llms.txt`, 차트 `ui.machineAuth.write.cred.*`(Secret 참조만, `scripts/test/test-chart-machine-write.sh` 확장). 검수: 계약 시험, AC-001, T-024/T-025 녹색, Class D 독립 검토 + 전용 security-reviewer BLOCKER 0.
- [ ] `T-027` **CI·릴리스 게이트**: v2b·v2c 드릴을 기존 머신 쓰기 e2e에 합류(path 필터 없음), `release.yml` `release_critical`에 정확 이름으로 추가(부모 T-025 방식). 검수: 태그 SHA에서 성공.

## Verify

- [ ] `T-040` `cd ui/backend && go test ./internal/httpapi ./internal/machineauth ./internal/config ./internal/ldapclient -count=1`와 `-race`, `go vet ./internal/...`, 차트 스크립트, `make check`. 변이 시험 목록(CHANGE.md "Verification plan")을 PR 본문에.
- [ ] `T-041` 증거 기록(`research/README.md`, 실패 포함). 실행하지 못한 항목은 EVIDENCE.md "Not verified".

## Synchronize durable truth

- [ ] `T-050` ADR 결정 승격, 부모 CHANGE.md·TASKS.md(T-026/T-030/T-031) 상태 갱신, `docs/api.md`·`docs/machine-write-account.md`·`docs/machine-auth-operations.md`·`docs/audit-event-schema.md`·`llms.txt`·OpenAPI·CHANGELOG 동기화, #379에 진행 기록("Related to #379 (not closing yet)"; v2b·v2c 모두 끝나기 전에는 닫지 않음).

## Completion review

- [ ] `T-060` 독립 검토(작성자 ≠ 검토자): 하위 범위별 위협 모델 항목의 통제가 실제 구현·증거와 대응하는지, 열린 질문 결정 기록과 대조.
