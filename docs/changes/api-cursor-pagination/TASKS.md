# Tasks: `GET /api/users`·`/api/groups` 서버측 커서 페이지네이션

설계: [CHANGE.md](CHANGE.md) (Status: `Accepted 2026-10-06 — maintainer instruction to process #215 …; implementation requires T-001 and the image change in its own commit`, 이슈 #215).
구현은 `T-001` 완료와 이미지·차트 변경(`T-015`)의 **별도 커밋**을 전제로 한다. 각 구현 단위는 무파라미터 경로 불변(`REQ-001`) 상태로 병합한다.
LDAP 배선·검색·이미지 변경이므로 구현 전에 `.agents/skills/ldapium-directory-change/SKILL.md`를 먼저 로드한다.

## Inspect and establish evidence

- [x] `T-001` (`REQ-001`, `REQ-010`) 소스 오브 트루스 재확인: `user_handlers.go:12-18`, `group_handlers.go:12-18`, `dto.go:5-26`, `ldapclient/search.go:10-61`, `ldapclient/dial.go:124-157`, `ldapclient/errors.go:15-55`, `openapi.json`(`listUsers`·`listGroups`·`UserList`·`GroupList`·`x-ai-hints`), `docs/api.md:95-96`, `llms.txt:36-37,45`. `ldapclient.Client` 인터페이스 구현체·가짜(`auth_handlers_test.go`, `session/store_test.go`) 목록. #218 봉투 병합 여부와 `apiErr` 헬퍼 이름 확인. **구현 착수 전 필수.**
- [x] `T-002` (`REQ-004`, `REQ-005`, `REQ-008`, `REQ-013`, `REQ-014`) **라이브 스파이크 — 설계 확정이 아니라 사실 확인**(실제 `ldapium:e2e` + 12000건): (1) 비관리자 paged search 총합에 hard limit이 적용되는가(`ldapsearch -E pr=500/noprompt`, 기본 10000과 `LDAP_SIZE_LIMIT=500`), rootDN은 면제인가; (2) `olcLimits: {0}users size.prtotal=<값|unlimited>` 구문이 유효한지, 설정 시 soft/hard가 `olcSizeLimit` 기본을 유지하는지, `anonymous`는 영향이 없는지; (3) `uid`·`cn` ORDERING 규칙 부재(`(uid>=x)`)와 `entryUUID` 순서·OR 필터 지연; (4) 한 연결에서 paged search 진행 중 다른 오퍼레이션이 허용되는가, paged search 두 개의 동시 진행 허용 여부; (5) paged 스캔 중 미변경 엔트리가 누락되지 않는가; (6) `SearchAsync` 취소(청크 타임아웃) 후 같은 연결이 정상인지(go-ldap `conn.go:610`의 늦은 패킷 처리 포함), 서버 `TimeLimit` 효과; (7) SSO 서비스 계정이 rootDN인지. 결과를 CHANGE.md "검증하지 못한 사실"에 반영하고 가정이 틀리면 D215-13/14를 갱신·재검토한다.
- [ ] `T-003` (`REQ-009`, `REQ-011`) 다운스트림·연계 검토: #218 코드 표에 "Error codes introduced" 8개 흡수(PR 한 줄 요건), #214 머신 신원의 커서 결속값(`cursorBinding`, 임시 `Session` 문제), API 소비자·SDK·`docs/api.md` 사용 예, 프런트의 `truncated`·`UserList`/`GroupList` 의존 지점.
- [x] `T-004` (`AC-001`) 변경 전 기준선: 5001건 이상 디렉터리에서 무파라미터 `GET /api/users`·`/api/groups` 응답(키 집합·길이·첫/마지막 DN·`truncated`)을 기록하고 기존 `go test ./...`(ui/backend)·UI e2e 결과를 캡처.
- [x] `T-005` (`REQ-001`–`REQ-015`) 수용 선행: 유지보수자 지시로 수용(2026-10-06), Q1·Q2는 CHANGE.md Review record에 결정으로 기록. 수용 표시는 유지보수자 몫이며 이미 완료.

## Implement

병합 단위 순서. `T-015`는 자체 커밋으로 가장 먼저.

- [x] `T-015` (`REQ-014`, `REQ-004`) **이미지·차트 opt-in 설정(Class C, 별도 커밋)**: `image/entrypoint.sh`에 `LDAP_PAGED_TOTAL_LIMIT`(숫자|`unlimited`, 미설정=현재 동작) 파싱·검증(`LDAP_SIZE_LIMIT`와 같은 패턴 `:169-173`)과 `01-cn-config.ldif`(`olcSizeLimit` `:74` 다음) 렌더(`olcLimits: {0}users size.prtotal=<값>`, 미설정이면 줄 없음; 치환은 `:1005` 인근 방식); `image/README.md` env 표(`:89` 인근)·bootstrap-only 절(`:234-243`)·기존 볼륨 `ldapmodify` 절차와 보안 비용(열거 위험) 문서화; 차트 `ldap.limits.pagedTotal`(기본 비움)을 `values.yaml`·`templates/statefulset.yaml`(`LDAP_SSSVLV_MAIN_ENABLED` 항목 `:135-136` 선례)·`README.md`·`README-ko.md`에 추가(값이 있을 때만 env 렌더). 테스트: 엔트리포인트 렌더(미설정/값/`unlimited`/`abc`, `scripts/test/test-bootstrap-seed.sh` 선례), `helm template` 기본·설정 렌더와 `scripts/verify-chart-schema.sh` 프로필 추가, `ldapium:e2e` 재빌드 후 `cn=config`의 `olcLimits` 확인(`AC-012`).
- [x] `T-010` (`REQ-002`, `REQ-003`, `REQ-006`, `REQ-007`, `REQ-009`, `REQ-011`, `REQ-015`) 순수 헬퍼(LDAP 비의존): 커서 인코드/디코드/HMAC와 `cursorBinding(sess)` = `Session.ID` 해시(D215-1, 주입 가능한 비밀·세션·리소스·`q`), 정렬 키 함수·튜플 비교(D215-4), `limit`/`sort`/`q` 검증(D215-2), `q` 필터 구성(D215-7), 최소 `limit+1` 선택 힙(D215-6), **`assemblePage(selected, fetched)`**(D215-6 규칙 1–5: 방출·삭제·`t2≠t1` 제외·순서·커서 전진). 신규 의존성 금지.
- [x] `T-016` (`REQ-008`, `REQ-013`) **컨텍스트 인지 청크 검색 래퍼** `ldapclient/search_chunk.go`(D215-13): `searchChunk(ctx, req)` = `conn.SearchAsync(chunkCtx, …)`로 paged 요청 1개를 읽고 `chunkCtx = WithTimeout(ctx, chunkTimeout=5s)`, `req.TimeLimit=ceil(chunkTimeout)`, 종료 후 `ctx.Err()` 확인(취소가 오류로 보고되지 않음), 페이징 쿠키는 `Response.Controls()`에서 추출; `c.mu`는 청크마다 획득·해제; 세션당 `scanMu`(두 번째 동시 스캔은 컨텍스트까지 대기); `sizeLimitExceeded`→새 `domain.ErrSizeLimitExceeded`(`ldapclient/errors.go`의 `mapErr`에 case 추가). 검색 함수와 시계를 주입 가능하게 만들어 단위 테스트(타임아웃·취소·`scanMu` 대기·상한·청크 사이 뮤텍스 해제)를 쓴다. 기존 `searchAllPaged`·`ListUsers/ListGroups`는 수정하지 않는다.
- [x] `T-011` (`REQ-002`, `REQ-004`, `REQ-005`, `REQ-008`, `REQ-013`, `REQ-015`) `ldapclient` 페이지 조회: users/groups phase 1 키 스캔(청크, `maxScanEntries`=100000, D215-8) + phase 2 `entryUUID` 청크 조회(≤100)와 `assemblePage` 호출(D215-6). 테스트 이음새 `betweenPhases func()`(비프로덕션, 기본 nil). `Client` 인터페이스에 메서드를 추가하고 가짜 구현체 갱신.
- [x] `T-012` (`REQ-001`, `REQ-002`, `REQ-008`, `REQ-009`, `REQ-013`) `httpapi`: 커서 모드 분기(`limit`·`cursor`·`q`·`sort` 존재 시), `listRequestTimeout`=30s 컨텍스트 생성·전달, 응답 DTO(`hasMore`, `nextCursor`, `truncated:false`; D215-3), 오류 매핑(400 `invalid_*`, 422 `size_limit_exceeded`/`scan_limit_exceeded`, 503 `scan_timeout`/`unavailable`+`Retry-After`; #218 봉투 `error`=`message`). 무파라미터 분기는 바이트 동일. GET은 `If-Match`·`Idempotency-Key`를 요구하지 않는다.
- [x] `T-013` (`REQ-010`) OpenAPI: `listUsers`·`listGroups`의 `parameters`(`limit` 1–200, `cursor`, `q`, `sort`), `UserList`/`GroupList`에 선택 `hasMore`·`nextCursor`(`required` 불변), 400·422·503 응답과 오류 코드, 설명의 "커서 없음"을 동시 변경 보장표(D215-5)·두 단계 규칙·크기 제한 안내로 교체; `x-ai-hints`·`llms.txt`·`docs/api.md` 문구 정렬.
- [ ] `T-014` (`REQ-002`, `REQ-004`, `REQ-005`, `REQ-012`) 적재 도구: `scripts/bench-generate-ldif.py`(현재 `ou=people` 사용자만)에 그룹과 엣지 엔트리(대소문자 혼합·`uid` 없음·`uid` 중복·비ASCII) 생성을 추가하거나 동반 생성기를 둔다. 결정적 출력 유지, 적재는 `scripts/bench-load.sh` 재사용.

## Verify

- [x] `T-020` (`AC-004`, `AC-005`, `AC-006`, `AC-007`, `AC-008`, `AC-011`, `AC-012`, `AC-013`) 단위/정적: `go test ./...`(ui/backend) — 커서 변조·결속(재로그인 새 `Session.ID` 포함) 표, 키 순서, 힙 선택, 검증 표, 필터 구성·이스케이프 퍼즈, `userPassword` 픽스처, **`assemblePage` 두 단계 사이 변경 표((a)–(f))**, 청크 래퍼 시간 주입 테스트(`T-016`), `sizeLimitExceeded`→422 매핑, 핸들러 400/422/503, 계약·드리프트·오류 코드 골든(`api_contract_test.go:39,84`, `api_docs_test.go:102`), `go vet`·린트.
- [x] `T-021` (`AC-001`, `AC-002`, `AC-003`, `AC-004`, `AC-006`, `AC-007`, `AC-011`, `AC-013`) 라이브: `scripts/test/test-api-cursor-pagination-local.py`(신규) — 12000 users/groups 전체 순회(관리자 로그인, 그리고 `LDAP_PAGED_TOTAL_LIMIT=unlimited` 이미지의 일반 사용자; 집합 동등·중복 0·엄격 증가), 기본 설정 일반 사용자의 422 `size_limit_exceeded`(레거시 5000 불변, `q`로 좁히면 성공), 페이지 사이 변경 (a)–(f), **재로그인 후 이전 커서 거부**, 무파라미터 호환, 과권한 bind `userPassword` 비노출, 지연 주입 하의 같은 세션 병렬 요청 대기 시간과 취소된 청크 뒤 연결 정상 여부, `betweenPhases` 이음새 라이브 테스트(두 단계 사이 삭제·modrdn·속성 수정·ACL 변경). 실패 시도도 기록.
- [x] `T-022` (`AC-009`) 성능 측정: 10k·50k, `limit=50`/`200`, 페이지 p50/p95/p99와 전체 순회 시간, 레거시 목록 지연 비교, 환경(호스트·Docker/Colima·이미지 태그) 기록. D215-9 예산과 대조해 통과 또는 탈출구(세션 스냅샷) 채택을 CHANGE.md에 기록.
- [x] `T-023` 실패·성공·환경·명령을 `research/` 관례로 증거화, 발견된 회귀 위험을 지속 검사로 전환, 라이브 스크립트를 CI에 연결할지(ui-e2e 계열 vs `workflow_dispatch`/야간)와 실행 시간 결정.

## Synchronize durable truth

- [x] `T-030` (`REQ-010`) `docs/api.md`·`llms.txt`·`openapi.json` 최종 정렬, 순회 의미(보장/비보장, 두 단계 규칙)와 비용 한계(O(N)/페이지)·크기 제한 안내를 사용자 문서에 기재.
- [x] `T-031` ADR 불필요 판정 재확인(D215-1·D215-5가 `docs/api.md` 정본, 이미지 설정은 `image/README.md` 정본). T-002/T-022 결과로 설계가 바뀌면 CHANGE.md 갱신·재검토.
- [ ] `T-032` 릴리스 노트(API·이미지·차트 각 1줄), 롤백·호환 메모, 이슈 #215에 완료 범위 코멘트와 후속 이슈 분리(UI 커서 모드 — `AC-010`, "Related to #215 (not closing yet)").
- [ ] `T-033` #214(결속값)·#218(오류 코드 표) 포트폴리오 영향 검토와 상태 갱신.

## Completion review

- [ ] Every requirement maps to an acceptance scenario and verification result (Traceability matrix).
- [ ] Material scope changes were reflected in the Change Package and re-reviewed.
- [ ] Expected evidence is attached or linked.
- [ ] Known incomplete work has an owner and tracking issue (UI 커서 모드 후속 이슈 포함).
- [ ] The PR states the checks actually run and any important unverified path.
