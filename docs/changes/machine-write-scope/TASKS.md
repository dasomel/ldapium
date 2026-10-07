# Tasks: 머신 주체 쓰기 범위 (v2)

설계: [CHANGE.md](CHANGE.md) (Status: `Proposed / awaiting review`) · 선행 패키지: [machine-principal-auth](../machine-principal-auth/TASKS.md), [api-conditional-writes](../api-conditional-writes/CHANGE.md), [replication-identity](../replication-identity/CHANGE.md).
모든 항목은 미착수다. **수용 표시는 유지보수자만 하며, 수용 전에는 `Implement` 이후 단계를 시작하지 않는다**(Class D, #285 수용 조건: "security review before any code").
ACL·`image/entrypoint.sh`·LDAP 쓰기 의미를 건드리는 작업은 먼저 `.agents/skills/ldapium-directory-change/SKILL.md`를 로드한다. 라이브 LDAP 경로는 모킹하지 않는다(AGENTS.md "Testing philosophy").
구현은 단계 병합이며 **각 단위는 독립 출하 가능**하고 기본 꺼짐에서 기존 테스트가 그대로 통과한다. 각 항목의 "검수"는 그 PR이 통과해야 하는 수용 확인이다. 체크 표시는 실제로 끝난 것만 한다.

## Inspect and establish evidence

- [ ] `T-001` (`REQ-003`, `REQ-013`) 소스 오브 트루스 재확인(HEAD): `machineOps`/`machineOpFor`(`machine_scopes.go`), `config.MachineScopes`, `machine.go`의 비-GET 거부 지점, 전수 거부 시험 `TestMachine_EveryProtectedOperationExercised`와 `machine_contract_test.go`가 거부 목록을 어디서 도출하는지(데이터 vs 하드코딩), `openapi.json`의 쓰기 오퍼레이션 `security` 현황. 검수: 결과를 EVIDENCE.md에 기록, D13 테스트 설계가 실제 구조와 맞는지 CHANGE.md에 반영.
- [ ] `T-002` (`REQ-004`) 속성 재고조사: `createUser`·`patchUser`·`patchGroup`·멤버 연산이 **실제로 쓰는 LDAP 속성**을 핸들러·`ldapclient`·DTO에서 도출해 부록 A의 "닫힌 속성 목록"을 확정한다(`objectClass`·`pwd*`·`userPassword`·`memberOf`·운영 속성의 경로 포함, `memberOf`/refint 오버레이가 쓰기 신원 ACL 밖에서 갱신되는지). 검수: 오퍼레이션×속성 표, 목록 밖 속성을 담은 요청이 현재 코드에서 어떻게 처리되는지 단위 시험으로 고정(변경 없이 관측만).
- [ ] `T-003` 다운스트림 검토: `docs/api.md`·`llms.txt`·프런트 `api-docs.ts`(보호 분류가 `security` 빈 배열 기준, v1 T-003 결과)가 쓰기 오퍼레이션의 `machineBearer` 선언에 영향받는지, 사람 UI가 `If-Match`/`Idempotency-Key`를 아직 보내지 않는다는 사실(ADR "Consequences")이 머신 필수 규칙과 충돌하지 않는지, 감사 이벤트 스키마 소비자, 차트 README.
- [ ] `T-004` (`REQ-007`, `REQ-012`, D12) 미검증 항목 실측(실제 slapd): ① 쓰기 신원으로 한 Add/Modify/Delete가 accesslog에 `reqDN`·`reqAuthzID`로 무엇을 남기는지 ② 쓰기 신원 비밀번호 회전/계정 잠금이 **진행 중 요청**과 **다음 요청**에 미치는 영향(요청마다 bind, `machine_exec.go:89`) ③ `notAllowedOnNonLeaf`·컨테이너 삭제 ④ `by dn.exact=W write` 규칙이 `memberOf`/refint 갱신·`entryCSN` assertion에 미치는 영향 ⑤ 비밀 속성 `none`이 `W`의 Password Modify를 막는지(비밀번호 단계 입력) ⑥ **Add 시 `objectClass`**: `W_data`가 사용자·그룹 Add를 하려면 엔트리·각 속성(objectClass 포함)에 어떤 접근 수준이 필요한지, `add` 수준으로 Add는 되고 Modify의 objectClass 변경은 거부되는지(D18) ⑦ 재시작 후 같은 `Idempotency-Key`가 재실행됨(`idempotency/store.go:153-181`)을 실제로 확인하고 `If-Match`·`entryAlreadyExists`가 중복을 막는 정도. 검수: 실제 명령·출력을 EVIDENCE.md에 보존(실패 포함), 가정이 틀린 결정은 CHANGE.md 개정.
- [ ] `T-005` (`REQ-001`–`REQ-014`) 수용 선행: Owner 지정, CHANGE.md "Open questions for the maintainer" 1–10 결정 기록, ADR 초안(D1/D3/D4/D5/D9), **security-reviewer 검토**(위협 모델·ACL·멱등 주체·긴급 차단), 독립 비평 라운드 후 BLOCKER 없음. 수용 표시는 유지보수자만 한다. 검수: CHANGE.md 머리말에 수용 근거 기록.

## Implement

수용 이후에만 착수. 병합 순서: T-010 → T-011 → T-012 → T-014 → T-015 → T-016 → T-020 → T-021 → T-022 → T-023 → **T-013(쓰기 개방)**. **T-010은 쓰기 가능 신원·오퍼레이션을 하나도 열지 않아 v1과 읽기 호환**이다. 쓰기 오퍼레이션을 등록하는 단위는 T-013 하나뿐이고 그 선행 조건은 T-013 본문에 있다.

- [ ] `T-010` (`REQ-001`, `REQ-013`, `REQ-014`) **단위 1 — 계약 스캐폴딩(읽기 호환, 동작 변화 없음).** `config.MachineScopes`에 쓰기 scope 어휘(D7) 추가(client 상한에 적어도 거부), `machineWriteOps` 표를 **비어 있는 채로** 도입하고 `machineOpFor` 동작은 현재와 동일, `MACHINE_WRITE_ENABLED` 파싱(기본 꺼짐, 꺼지면 어떤 `MACHINE_WRITE_*`도 읽지 않음), D13 계약 테스트를 데이터 구동으로 바꾸고(거부 목록 = D2 영구 거부 + 미개방 쓰기, 줄이는 PR은 D-id 인용 필수), 전수 거부 시험이 새 구조에서 같은 37개를 거부함을 단언. 검수: AC-001 — 기존 `go test ./internal/httpapi ./internal/machineauth ./internal/config` 전부 통과, `openapi.json` diff 없음 또는 additive, 변이 시험(거부 목록에서 항목 삭제 → 테스트 실패), 읽기 전용 증명 스크립트 녹색.
- [ ] `T-011` (`REQ-001`, `REQ-002`) **단위 2 — 쓰기 신원 설정·기동 검증(여전히 오퍼레이션 없음).** 구획별 `W_data`/`W_lock`/`W_cred` bind DN·비밀번호 env(비밀번호는 기존 Secret 관례), 기동 검증: `M`·관리자·프로파일 관리자·`LDAP_SERVICE_ACCOUNT_DN`·rootdn(`MACHINE_LDAP_ROOT_DNS`)·서로와 `ldap.ParseDN` 동등이면 실패(v1 D4/D19 변형 12종 재사용), 쓰기 켬+`M` 미설정/멱등 저장소 꺼짐 실패(D9/D10), 플래그 조합 표. 검수: AC-001·AC-002 단위 부분(`config/machine_write_test.go`), 켜면 기동하고 쓰기는 여전히 403(표가 비어 있음).
- [ ] `T-012` (`REQ-003`, `REQ-004`) **단위 3 — 쓰기 가드 구현(표는 비어 있어 도달 불가).** client별 `MACHINE_WRITE_SUBTREES` 상한과 `dnWithinBase` 재사용 가드(대상·부모·멤버 DN, 연결 이전 거부, `machine_guard.go` 패턴), 오퍼레이션별 닫힌 속성 가드(T-002 결과), 구획→bind DN 선택(`machineExecutor`가 오퍼레이션 등급으로 DN·슬롯 선택). 검수: AC-003 (a)(b)(c) 단위 표(대소문자·공백·escape·hex·다중값 RDN·형제 DN 변형), 가드 제거 변이 시험.
- [ ] `T-014` (`REQ-005`, `REQ-006`) **멱등·조건부 필수화와 주체 분기(T-013의 선행 조건, 오퍼레이션이 없어도 시험 가능).** `idempotency.go:139`의 `sess.DN` 인자를 principal 종류별로 분기(머신 = `machine:`+`len(iss)`+`:`+iss+client id, 사람 경로 바이트 불변), 머신 쓰기에서 `Idempotency-Key` 없으면 428(새 코드 `idempotency_key_required`, 표·골든·OpenAPI enum·`docs/api.md`·`llms.txt` 동시 갱신, D218-14), `If-Match` 필수 규칙은 기존 `if_match_required`. 검수: AC-004·AC-005 — client 간·사람↔머신 교차 재생/충돌 없음, 토큰 갱신 후 같은 기록, 사람 멱등 기존 시험 무변경, 공유 DN 주체로 되돌리면 실패하는 변이 시험.
- [ ] `T-015` (`REQ-007`) **쓰기 감사 필드.** `machine_audit.go`의 이벤트에 쓰기 필드(D6) 추가, 한 줄 규칙 유지(조기 반환 포함), 대상 DN 지문/평문 옵션(Q4), `docs/audit-event-schema.md` "머신 접근 이벤트" 갱신. 검수: AC-006 — 조기 반환 표 + 쓰기 전용 행(412·재생·LDAP 거부), 센티널 토큰·비밀번호·본문 값 0건.
- [ ] `T-016` (`REQ-008`) **쓰기 한도.** 읽기와 분리된 client 예산·client당 동시 쓰기 1·전역 쓰기 슬롯(D8d), v1 `machine_limiter.go` 유계 구조 재사용, panic/취소/타임아웃에서 해제(`machine_limiter_panic_test.go` 패턴). 검수: AC-007 경계 표, 읽기 예산 영향 없음, 변이 시험(해제 제거).

## ACL, 문서, 운영

- [ ] `T-020` (`REQ-002`, `REQ-004`, `REQ-011`) **쓰기 ACL 조각과 가이드.** `docs/machine-ldap-account.md`를 확장하거나 `docs/machine-write-account.md`를 신설해 `W_data`/`W_lock`(/`W_cred`) 계정 생성·확정 LDIF(`scripts/test/fixtures/machine-acl/`에 쓰기 조각 추가)·적용/확인/롤백을 둔다. **D11 순서 계약**: 모든 기존 allow 앞, `M` 묶음 뒤, 인덱스는 `olcAccess` 읽기로 계산. 비밀 속성·`pwd*` 규칙은 `W_data`에 `none`. #277 해소 전 `prepare`와 비공존을 경고로 명시. 검수: 가이드의 LDIF·명령이 T-021 스크립트에서 문자 그대로 일치(v1 T-015 방식).
- [ ] `T-021` (`AC-002`, `AC-003d`, `AC-008`, `AC-010`) **라이브 ACL 증명**(`scripts/test/test-machine-write-acl-live.py` 신설, v1 `test-machine-acl-readonly-live.py` 패턴): 새 초기화 컨테이너, 쓰기 신원 허용/거부를 속성별·subtree별로 증명, 앱 가드를 거치지 않는 직접 `ldapmodify`로 상한 밖 거부, `M` 직접 쓰기 전부 거부와 읽기 전용 증명 재실행, (복제 신원 없음 / `dedicated`) × (익명 읽기 설정·미설정) 조합의 `olcAccess` 정확 인덱스 단언·롤백, 기존 신원 접근 결과 전후 동일. `prepare` 조합은 #277 해소 후. 검수: 실제 출력·변이 시험을 EVIDENCE.md에 보존.
- [ ] `T-022` (`REQ-012`, `AC-011`) **긴급 차단 드릴·운영 문서.** `docs/machine-auth-operations.md`에 쓰기 차단 절차(쓰기만 끄는 재배포, 쓰기 신원 회전/잠금)와 한계(발급 토큰·진행 중 요청), 실제 드릴: 쓰기 신원 회전 후 모든 replica의 다음 쓰기 503·읽기 정상·발급 토큰 상태 확인. 검수: 노출 상한을 실측값으로 문서화(추정 금지).
- [ ] `T-023` (`REQ-011`) **운영 점검 스크립트**: 쓰기 ACL이 `M`·복제 신원 규칙과 정의된 순서인지, 기존 allow 앞인지, `W`의 비밀 속성 `none`이 설치돼 있는지를 `olcAccess` 읽기로 확인(실패 시 비0 종료, 거짓 통과 금지), `prepare` 구성에서는 쓰기 비공존 경고. 검수: 올바른/잘못된 순서·누락 규칙 각각에 대한 라이브 판정.
- [ ] `T-013` (`REQ-003`, `REQ-004`, `REQ-010`) **오퍼레이션 개방 단위 — 쓰기 경로를 여는 유일한 단위이며 마지막에 병합한다.** **병합 선행 조건(모두 main에 있어야 함): T-014(멱등 주체·필수 헤더), T-015(쓰기 감사), T-016(쓰기 한도), T-020/T-021(ACL 가이드와 라이브 증명), T-023(점검 스크립트).** 추가로 **켜는 스위치가 스스로 거부한다**: `MACHINE_WRITE_ENABLED=true`는 멱등 저장소 활성·쓰기 감사 필드·쓰기 한도·`W_*` bind 가능을 기동 시 확인하고 하나라도 없으면 기동 실패(플래그 기본 꺼짐만으로는 켜는 운영자를 보호하지 못한다). Q2 결정에 따라 `machineWriteOps`에 `createUser`(비밀번호 없이, D15; scope `directory.users.create`)·`patchUser`(`.update`)·`deleteUser`(`.delete`)를 등록, `If-Match` 필수, 컨테이너/리프 아닌 삭제 거부(D8e), 생성 objectClass 고정 집합(D18), OpenAPI `security`·`x-machine-scope` additive, `docs/api.md`·`llms.txt` 동기화. 검수: AC-003·AC-009, 선행 항목 하나를 빼고 켜면 기동 실패하는 시험, 전수 거부 시험이 개방된 오퍼레이션만 허용으로 바꿈, 계약 테스트 통과.
- [ ] `T-024` (`AC-012`) 차트: `ui.machineAuth.write.*`(스키마·`required`, 구획별 Secret 참조만), `ui.replicaCount`≠1 또는 멱등 비활성이면 쓰기 활성 렌더 실패, 꺼짐 렌더가 origin/main과 바이트 동일, `terminationGracePeriodSeconds` 요건. 검수: `scripts/test/test-chart-machine-auth.sh` 확장, `verify-chart-schema.sh` 프로파일.
- [ ] `T-025` (`AC-001`–`AC-012`) **CI·릴리스 게이트**: 실제 Keycloak+slapd 쓰기 e2e(양·음성 토큰, scope/상한/subtree/속성 거부, 428/412/재생, 감사, 한도, 센티널 로그 스캔) 워크플로 — [machine-keycloak-e2e.yml](../../../.github/workflows/machine-keycloak-e2e.yml) 패턴, 정확 이름 `release.yml`의 `release_critical`에 추가(path 필터 없음), 태그 SHA에서 성공 확인.

## Later stages (각각 별도 승인·별도 플래그·별도 증거)

- [ ] `T-026` (v2b) 그룹 쓰기·멤버십(`directory.groups.create/update/delete`, `directory.groups.members.add/remove`, 멤버 DN도 subtree 상한)과 잠금(`directory.users.lock`, `W_lock`). 각각 T-012/T-014/T-016 위에서 오퍼레이션 등록 + T-021 증거 확장.
- [ ] `T-030` (v2c, **Q1 승인 필요**) 비밀번호 구획: `W_cred` ACL, 비밀번호 포함 `createUser`, `setPassword`(서버 생성 금지 D16, `If-Match` 불가라 멱등 키+대상 한정+한도), `T-004`⑤ 결과 반영. 별도 security-reviewer 라운드.
- [ ] `T-031` (v2c) 비밀번호 단계 라이브 증명: 비밀 값이 응답·감사·멱등 기록·모든 컨테이너 로그에 0건, 직접 ACL 시도 거부, 긴급 차단 드릴.

## Verify

- [ ] `T-040` 단위/정적: `cd ui/backend && go test ./internal/httpapi ./internal/machineauth ./internal/config ./internal/ldapclient -count=1`와 `-race`, `go vet ./internal/...`, 차트 스크립트. 모킹 프레임워크 도입 금지. 변이 시험 목록(비-GET 거부·subtree 가드·멱등 주체·`If-Match` 강제·ACL `by * break`)을 PR 본문에 둔다.
- [ ] `T-041` 증거 기록(`research/README.md` 규약, 실패 포함)과 발견된 회귀 위험의 계약/단위 시험 승격. 실행하지 못한 항목은 "Not verified"에 남긴다.

## Synchronize durable truth

- [ ] `T-050` `ADR.md`(D1/D3/D4/D5/D9 승격), `docs/api.md`·`docs/machine-ldap-account.md`·`docs/machine-auth-operations.md`·`docs/audit-event-schema.md`·`llms.txt`·OpenAPI·CHANGELOG 동기화, #285에 진행 기록(부분 PR은 "Related to #285 (not closing yet)", 전체 범위를 덮기 전에는 닫지 않음 — AGENTS.md "Issue tracker convention"), 남은 범위는 후속 이슈로 분리.

## Completion review

- [ ] `T-060` 독립 검토(작성자 ≠ 검토자): 각 단위 PR을 Class D로 `code-reviewer`/Codex 비평, 마지막에 위협 모델 항목별 통제의 실제 구현·증거 대조, 열린 질문 결정 기록 대조.
