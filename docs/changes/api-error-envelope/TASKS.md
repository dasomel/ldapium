# Tasks: HTTP API 오류 봉투 통일, `/metrics`, CORS 결정

설계: [CHANGE.md](CHANGE.md) (Status: `Accepted 2026-10-06 — maintainer instruction to process #218 (open questions resolved as recorded below)`). 모든 항목은 미착수이며 Owner 지정 후 시작한다.
구현은 Phase 1(봉투) → Phase 1b(쓰기 Origin 게이트) → Phase 2(`/metrics`) → Phase 3(CORS) 순으로 단계 병합하고, 각 단계는 기능 꺼짐 상태에서 기존 테스트가 통과해야 한다.
경로 접두: `BE` = `ui/backend/internal/httpapi/`, `FE` = `ui/frontend/`. LDAP 설정·`image/entrypoint.sh` 변경은 이 패키지에 없다
(생기면 `.agents/skills/ldapium-directory-change/SKILL.md`를 먼저 로드한다).

## Inspect and establish evidence

- [ ] `T-001` (`REQ-001`, `REQ-014`) 소스 오브 트루스 재확인: 오류 생산자 표(CHANGE.md Problem 1)가 착수 시점 `main`과 일치하는지 `grep -rn "echo.NewHTTPError\|respondErr(" BE`로 재집계(현재 104곳), 신규 생산자 반영. 오류 본문을 디코드·단언하는 모든 테스트를 열거해 갱신 대상 목록을 확정한다: `grep -rn "map\[string\]string\|body\[\"error\"\]\|json.loads" BE/*_test.go scripts/test FE/e2e` (알려진 것: `api_docs_test.go:60-61,404-405`).
      증거: 집계 명령·출력, 표 갱신 diff.
- [ ] `T-002` (`AC-001`, `AC-002`) 사전 기준선: 현재 오류 본문 형태를 전 라우트 401/404/405로 캡처하고, `go test ./...`(ui/backend)·`npm run lint`·`npm run build`·기존 e2e 결과를 기록.
      증거: 캡처한 본문 목록, 명령·종료 코드.
- [ ] `T-003` (`AC-001`) 미검증 항목 확정(CHANGE.md 마지막 절 (a)(b)(d)): ① Recover 패닉·라우터 404에서 `X-Request-Id` 설정 여부 ② Echo `OPTIONS`가 `RouteNotFound` 캐치올과 공존할 때의 응답 ③ `session.Store.Create(dn, nil)` + `session.Sign`으로 인증 테스트 서버(임시 `AppProfilesPath`, 백업 비활성/활성)를 만들 수 있는지.
      불가하면 403/415/428/412/422 검증을 핸들러 단위 테스트로 대체하는 계획을 CHANGE.md에 반영(재검토).
      증거: 임시 테스트 출력(커밋하지 않음) 또는 결론 메모.
- [ ] `T-004` (`REQ-014`) 다운스트림 검토: #214–#217 이슈·패키지(`machine-principal-auth` 포함)가 요구하는 새 오류 조건을 모아 D218-3 코드 표에 예약 코드(`unavailable` 등) 충돌이 없는지 확인, 소비자 문서(`docs/api.md`, `llms.txt`) 사용 예 점검.
- [ ] `T-005` (`REQ-001`–`REQ-014`) 수용 선행: Owner 지정, Q1·Q2 결정 기록, ADR 초안(D218-1~14), 보안 검토(`/metrics` 노출·CORS) 요청. **수용 표시는 유지보수자만 한다.**

## Implement

### Phase 1 — 오류 봉투 (additive, Class B 수준 검증으로 선행 병합 가능, Q1)

- [ ] `T-010` (`REQ-001`, `REQ-003`, `REQ-005`, `REQ-006`) `BE/errors.go`(또는 `errors_envelope.go`): 순수 헬퍼 `writeAPIError`/상태→기본 `code` 매핑/`retryable`·`Retry-After` 규칙/5xx 정적 문구 표(D218-3·5·8). 코드 골든 목록. 모킹 없는 표 주도 단위 테스트.
      파일: `BE/errors.go`, `BE/errors_test.go`. 증거: `go test ./internal/httpapi -run 'Envelope|Respond'`.
- [ ] `T-011` (`REQ-001`, `REQ-004`, `REQ-006`, `AC-001`) `apiErrorHandler`(`BE/api_docs.go:77`)가 `/api`의 모든 `*echo.HTTPError`·sentinel·일반 error를 봉투로 변환하고, `respondErr`(`BE/errors.go:28`)가 같은 빌더를 쓰게 한다. 5xx는 `HTTPError.Message` 무시·로그에 `requestId` 포함. 비-`/api` 경로는 현행 폴백 유지. `message` == `error`.
      파일: `BE/api_docs.go`, `BE/errors.go`. **같은 PR에서 기존 테스트를 갱신한다(무수정 통과 주장 금지):** `api_docs_test.go:60-61`(`TestUnknownAPIPathsReturnJSONError`)과 `api_docs_test.go:404-405`의 `map[string]string` 디코드는 `retryable`(bool) 때문에 실패하므로 봉투 구조체(`error`·`message`·`code`·`requestId`·`retryable`)로 디코드하도록 바꾸고, `errors_test.go:30-37,65`와 `scripts/test/test-api-edge-codes-local.py:151,154`가 계속 통과하는지 확인한다. 증거: 갱신 전후 diff, `go test ./internal/httpapi` 통과 출력.
- [ ] `T-012` (`REQ-003`) 도메인 구분이 필요한 약 20곳을 `apiErr(status, code, msg)`로 교체(`admin_required`, `origin_mismatch`, `feature_disabled`, `backup_busy`, `revision_conflict`, `if_match_required`, `session_expired`, `keycloak_disabled`, `upstream_failed`, `login_rate_limited` 등 D218-3 표). 문구·상태 불변. 나머지 `echo.NewHTTPError`는 수정하지 않는다.
      파일: `middleware.go`, `auth_handlers.go`, `app_profile_handlers.go`, `backup_handlers.go`, `keycloak_handlers.go`, `sso.go`, `app_method_handlers.go`, `app_export_handlers.go`. 증거: 문구·상태 diff 없음(테스트), AC-003 표.
- [ ] `T-013` (`REQ-007`, `AC-006`) `openapi.json`: `components.schemas.Error` 하나(+`components.responses`: BadRequest/Unauthorized/Forbidden/NotFound/MethodNotAllowed/Conflict/PreconditionFailed/UnsupportedMediaType/Unprocessable/PreconditionRequired/TooManyRequests(+`Retry-After` 헤더)/Internal/BadGateway/ServiceUnavailable)를 두고 `ErrorBody`·`EchoErrorBody`·`ApiError`(현재 `openapi.json:4295-4330`)와 경로의 참조(현재 158/38/27회)를 교체. 예외 `getLdapHealth` 503·리다이렉트는 테스트 허용 목록.
      드리프트 테스트(`BE/api_contract_test.go`)에 “모든 비-2xx/3xx 응답이 `Error`를 참조, 구 컴포넌트 부재” 추가.
      증거: `go test ./internal/httpapi -run OpenAPI`, 변경 전후 참조 집계.
- [ ] `T-014` (`AC-001`, `AC-004`, `AC-005`, `AC-017`) 계약 테스트: 전 라우트(`s.echo.Routes()`)에 401·404·405, T-003 결과에 따라 403/415/428/412/422/429/5xx(주입·패닉)를 구동해 5개 키·`requestId`==`X-Request-Id`·코드 표 소속·`Retry-After` 규칙·5xx 센티널 비누출을 단언하고, DN이 든 LDAP 진단 문자열(`uid=alice,ou=people,dc=example,dc=org`)을 `ldapclient` 래핑 오류 형태로 주입해 응답에 DN이 없음을 단언(D218-15). `errors_test.go:15`의 센티널 방식 확장.
      파일: `BE/api_error_contract_test.go`(신규). 증거: `go test ./internal/httpapi`.
- [ ] `T-015` (`REQ-002`, `AC-002`) FE: `FE/src/lib/app-profiles.ts:23,67`, `FE/src/lib/backups.ts:10`을 `error ?? message`(`api.ts:48`와 동일 순서)로 정리하고 `FE/src/lib/types.ts:190` `ApiErrorBody`에 `code?`·`requestId?`·`retryable?` 추가(표시 동작 불변). 서버 문구 표시 e2e 신설: `page.route`로 `error`+`message`+`code` 응답 주입 후 사용자·그룹·프로필·백업·로그인(429) 화면 문구 단언.
      파일: `FE/src/lib/*.ts`, `FE/e2e/error-envelope.spec.ts`(신규). 증거: `npm run lint`, `npm run build`, `npm run e2e` 출력.
- [ ] `T-016` (`REQ-013`, `REQ-014`) 문서: `docs/api.md` “오류 형식”(`:59-68`)·“상태 코드”(`:100-110`)·“아직 지원하지 않는 것”(`:118-121`)을 새 봉투·코드 표·`retryable`·`Retry-After`·`message` deprecated alias로 갱신, `BE/openapi/llms.txt` 동기화.
      증거: 문서 diff, `go test`(llms.txt 서빙 테스트 `api_docs_test.go:102`).

- [ ] `T-017` (`REQ-016`, `AC-017`) 4xx 메시지 정책(D218-15): `respondErr`/봉투 빌더에서 sentinel + 래핑 진단 → 고정 문구 대체·로그 원문 기록. `echo.NewHTTPError(4xx, err.Error())` 호출(`tree_handlers.go`·`group_handlers.go`·`user_handlers.go`·`app_*`·`backup_handlers.go:133`)을 열거해 `validate`/`appprofile` 검증 오류 여부를 확인하고, LDAP 진단이 섞일 수 있는 지점은 고정 문구로 교체. `ChangePasswordPage.tsx:70-73`이 보는 문구가 어떤 경로로 도달하는지 라이브 확인하고 UI를 `code` 기반 분기로 옮길지 결정(미검증 (e)). `validate` 문구 값 비에코 표 테스트.
      파일: `BE/errors.go`, `ui/backend/internal/ldapclient/errors.go`(문구 변경 없이 호출부에서 처리, 변경 시 AGENTS.md 와이어 경로 규칙 준수), `BE/errors_test.go`, FE 비밀번호 변경 화면. 증거: `go test`, 라이브 비밀번호 변경 실패 출력, UX 비용 기록.

### Phase 1b — 쓰기 Origin 게이트 (CORS보다 먼저 병합, Q2 해소)

- [ ] `T-033` (`REQ-015`) 사전 확인: 프록시 뒤에서 `c.Scheme()`·`Host`가 브라우저 `Origin`과 어떻게 비교되는지(`requireProfileWrite` 비교 `app_profile_handlers.go:112-120`, `X-Forwarded-Proto` 처리 `sso.go:248`, `UI_TRUSTED_PROXIES`), 차트 Ingress(`ui-ingress.yaml`) 구성에서 정상 UI 쓰기가 통과하는지 로컬 Docker/Ingress 또는 단위로 확인. 결과를 CHANGE.md D218-16에 반영(미검증 (d)).
- [ ] `T-034` (`REQ-015`, `AC-016`) 전역 미들웨어: `/api` 상태 변경 메서드에 `Origin` 헤더가 있으면 본인 origin 또는 허용 목록(Phase 3 이전에는 빈 목록)과 비교, 불일치·`null`은 403 `origin_mismatch` 봉투. 헤더 없음은 통과. `GET`/`HEAD`/`OPTIONS` 제외. 기존 `requireProfileWrite`는 유지(더 엄격).
      파일: `BE/origin_gate.go`(신규), `BE/server.go`(미들웨어 등록, `s.echo.Use` 목록 `:87-99`), `BE/origin_gate_test.go`. 증거: 쓰기 라우트 열거 표 주도 테스트(AC-016 (a)–(e)).
- [ ] `T-035` (`REQ-015`, `AC-016`, `AC-002`) FE e2e: 동일 출처 사용자·그룹·로그인 쓰기가 계속 성공함을 확인하는 회귀(`ui/frontend/e2e`), 릴리스 노트에 Origin 보내는 비브라우저 클라이언트·프록시 영향 기록, `docs/api.md`에 규칙 추가.

### Phase 2 — `/metrics` (기본 꺼짐)

- [ ] `T-020` (`REQ-010`, `AC-010`) 의존성 추가 PR(Class C 증거): `prometheus/client_golang` 도입, `go mod graph`로 전이 모듈 확정, `./scripts/licenses.sh`로 `THIRD-PARTY-LICENSES.md` 재생성 후 `--check`, govulncheck(`security-scan.yml` 동등 명령), `scripts/bundle-go-modules.sh`·`go mod verify`. 라이선스가 허용 목록 밖이면 D218-11 탈출구(직접 구현)로 전환하고 CHANGE.md 재검토.
      증거: 각 명령과 종료 코드, 모듈·라이선스 목록.
- [ ] `T-021` (`REQ-009`) `internal/metrics`(신규): 전용 `Registry`, D218-9 지표 정의, 좁은 인터페이스(`ObserveHTTP`/`ObserveLDAP`/`LoginFailure`/`APIError`), 라벨 값 정규화(미등록 route→`unmatched`, method→`other`). 단위 테스트.
- [ ] `T-022` (`REQ-009`) HTTP 미들웨어: `route`=`c.Path()`, 상태 class, 지연, in-flight, `api_errors_total{code}`(T-011 빌더에서 증가). 미들웨어는 `/metrics` 비활성이어도 no-op 구현으로 존재(오버헤드 최소).
      파일: `BE/server.go`(미들웨어 등록, 현재 `:85-96`), `BE/errors.go`.
- [ ] `T-023` (`REQ-009`) 관찰자 훅: `ui/backend/internal/ldapclient/dial.go`(`Bind`:35, `Ping`:72)와 client 공통 검색·쓰기 경로에 `op`/`result` 관측, 로그인 실패 `reason`(`auth_handlers.go`), `sessions_active`(`session.Store.Len`, `store.go:117`). 라벨에 DN·uid·IP·오류 문자열 금지. LDAP 와이어 경로는 단위 테스트하지 않고 T-026 라이브로 검증.
- [ ] `T-024` (`REQ-008`, `AC-007`) 설정·리스너: `internal/config`에 `METRICS_ADDR`(기본 빈 값, 형식 검증), `cmd/server/main.go`(`:69-76` 옆)에 `/metrics` 전용 `http.Server`(`ReadHeaderTimeout`)와 `Shutdown`(`:88`) 연동. Echo 라우터에는 등록하지 않는다. 단위/통합 테스트: 미설정 시 리스너 없음, 설정 시 포트에서만 응답, 8080 `/metrics` 404 봉투.
- [ ] `T-025` (`REQ-008`, `REQ-013`, `AC-018`) 차트(D218-10): `ui.metrics.enabled`(기본 false) → UI 컨테이너 포트 9331(`ui-deployment.yaml`), **공개 UI Service(`ui-service.yaml`)에는 추가하지 않고** 별도 `…-ui-metrics` Service, UI 파드 NetworkPolicy 신설(`ldapium.ui.selectorLabels`, `_helpers.tpl:70`; 기존 8080 허용을 `ui.networkPolicy.httpFrom` 기본 전체 허용으로 유지, 메트릭 포트는 `ui.metrics.networkPolicy.from`만 허용, 비어 있으면 `fail`), `ui.metrics.serviceMonitor.enabled`·`ui.metrics.podMonitor.enabled` 기본 false, 값·README. **`helm template` 단언 테스트**: 기본값에 신규 리소스 없음, 활성 시 공개 Service에 메트릭 포트 없음, 정책이 메트릭 포트를 설정 피어로만 허용, 빈 `from` 렌더 실패, 모니터 리소스 기본 부재, 기존 slapd 정책·ServiceMonitor 렌더 불변. UI 인그레스(8080) 유지 확인(미검증 (f)).
      파일: `charts/ldapium/templates/ui-deployment.yaml`, 신규 템플릿(메트릭 Service·NetworkPolicy·모니터), `values.yaml`, `charts/ldapium/README.md`, 차트 테스트 스크립트. 증거: `helm template`(기본값/활성/빈 `from`) 출력과 단언 결과, 기존 차트 린트.
- [ ] `T-027` (`REQ-008`, `AC-007`) 공개 포트 `/metrics` 명시 라우트: `GET /metrics`·`/metrics/`(HEAD 포함)가 `application/json` 404 봉투(`code: not_found`)를 반환하고 SPA 폴백(`server.go:214-228`)보다 먼저 매칭되도록 `routes()`(`BE/server.go`)에 등록. 단위 테스트: 두 구성 모두 `index.html`이 아님.
- [ ] `T-026` (`AC-007`–`AC-009`) 검증 구현: 스크랩 테스트(형식·지표 존재), 카디널리티 테스트(임의 경로·메서드 N회 후 시계열 상한), 무비밀 테스트(센티널 비밀·DN·uid·IP 부재), 라이브: `scripts/test/test-api-edge-codes-local.py`에 `/metrics` 스크랩·LDAP bind/search 지표 증가 확인 단계 추가(로컬 Docker, 이미지 태그 기록).

### Phase 3 — CORS (기본 꺼짐)

- [ ] `T-030` (`REQ-011`) 설정 검증: `internal/config`에 `CORS_ALLOWED_ORIGINS` 파싱(쉼표, 정확한 `scheme://host[:port]`만; `*`·`null`·경로/쿼리/사용자 정보·빈 요소는 기동 실패). 단위 테스트.
- [ ] `T-031` (`REQ-011`, `REQ-012`) CORS 미들웨어(자체 구현 또는 Echo `middleware.CORSWithConfig`): 활성 시 **모든** 응답(일치·불일치·Origin 없음·`OPTIONS`)에 `Vary: Origin`, 일치 Origin에만 `Allow-Origin`(반영값)·`Allow-Credentials`, 프리플라이트는 핸들러(`api_docs.go:151-153`의 #230 `OPTIONS` 204) 앞에서 가로채 응답, 프리플라이트(`OPTIONS`+`Access-Control-Request-Method`)는 `GET, HEAD, OPTIONS`·`Content-Type, Accept`·`Max-Age 600`, 노출 `X-Request-Id, Retry-After, ETag`. 쓰기 메서드·불일치·`null` Origin은 헤더 없음. 미설정 시 미들웨어 비등록. 쿠키 속성(`middleware.go:64`)은 건드리지 않는다. 단위 테스트(AC-011~013 케이스 표, `Vary` 전 응답 단언). 허용 목록은 T-034 게이트의 허용 목록과 같은 설정값을 공유한다.
      파일: `BE/cors.go`(신규), `BE/server.go`, `BE/cors_test.go`.
- [ ] `T-032` (`REQ-013`) 차트 `ui.cors.allowedOrigins`(기본 빈 목록 → env 미설정)와 `docs/api.md`·`llms.txt`의 CORS 절(“같은 사이트 읽기 전용, `SameSite=Lax`상 다른 사이트는 쿠키 미전송, 머신 클라이언트는 CORS 불필요”). Q2 결과를 반영.

## Verify

- [ ] `T-040` (`AC-001`, `AC-003`–`AC-006`, `AC-011`–`AC-013`, `AC-016`, `AC-017`) 단위/정적 검사 실행: `cd ui/backend && go vet ./... && go test ./...`, `cd ui/frontend && npm run lint && npm run build`, OpenAPI 드리프트.
- [ ] `T-041` (`AC-002`, `AC-007`–`AC-009`, `AC-018`) 통합/런타임/사용자 여정: `cd ui/frontend && npm run e2e`(기존 백업·프로필 e2e 포함), `scripts/test/test-api-edge-codes-local.py`(로컬 Docker, `ldapium:e2e`/`ldapium-ui:e2e` 재빌드 후; `docker exec -i` 주의 — AGENTS.md).
- [ ] `T-042` 실패·성공·환경·명령을 증거로 기록(PR 본문, 필요 시 `research/README.md` 규약). 실패한 시도도 보존.
- [ ] `T-043` 발견된 회귀 위험을 지속 검사로 전환: 전 라우트 오류 계약 테스트, 코드 골든 목록, OpenAPI 오류 참조 검사, 카디널리티·무비밀 테스트가 CI(`go test`)에서 항상 실행되는지 확인.

## Synchronize durable truth

- [ ] `T-050` (`REQ-013`) 규범 문서 갱신: `docs/api.md`, `llms.txt`, `charts/ldapium/README.md`, 운영 가이드(스크랩 대상·NetworkPolicy 주의).
- [ ] `T-051` ADR 작성: D218-1~14 승격(외부 오류 계약, 신규 리스너·의존성, CORS 정책).
- [ ] `T-052` (`REQ-013`) 릴리스·마이그레이션·롤백·호환성 노트: 새 오류 키, 새 env/Helm 값, `message` deprecated alias(제거 시점 미정), 되돌리기 절차.
- [ ] `T-053` (`REQ-014`, `AC-015`) 다운스트림 반영: #214–#217 패키지가 D218-14를 참조하도록 링크, `docs/IMPLEMENTATION-STATUS.md` 상태 갱신, #218은 분할 후속 이슈로 정리(이슈 트래커 관례: 부분 PR은 “Related to #218 (not closing yet)”).

## Traceability matrix

| REQ | AC | Tasks | Evidence |
|---|---|---|---|
| `REQ-001` | `AC-001` | T-010, T-011, T-014 | 전 라우트 계약 테스트 출력, 갱신된 기존 테스트(`api_docs_test.go:60-61,404-405`) |
| `REQ-002` | `AC-002` | T-011, T-015 | FE e2e·lint·build, 문구 diff 없음 |
| `REQ-003` | `AC-003`, `AC-015` | T-010, T-012 | 코드 골든 목록·표 주도 테스트 |
| `REQ-004` | `AC-001` | T-011, T-014 | `requestId`==`X-Request-Id` 단언 |
| `REQ-005` | `AC-004` | T-010, T-012, T-014 | 규칙 표 테스트, 429 `Retry-After` |
| `REQ-006` | `AC-005`, `AC-009` | T-010, T-011, T-014 | 센티널 비누출 테스트 |
| `REQ-007` | `AC-006` | T-013 | OpenAPI 드리프트 테스트 |
| `REQ-008` | `AC-007`, `AC-018` | T-024, T-025, T-026, T-027 | 두 구성 기동 테스트, 공개 포트 404 봉투, `helm template` 단언 |
| `REQ-009` | `AC-008`, `AC-009` | T-021, T-022, T-023, T-026 | 카디널리티·무비밀·라이브 스크랩 |
| `REQ-010` | `AC-010` | T-020 | licenses/govulncheck/번들 로그 |
| `REQ-011` | `AC-011`, `AC-012` | T-030, T-031 | CORS 케이스 표 테스트(`Vary` 전 응답) |
| `REQ-012` | `AC-012`, `AC-013` | T-031, T-032 | 쓰기 프리플라이트 거부·`origin_mismatch` 테스트 |
| `REQ-015` | `AC-016`, `AC-013` | T-033, T-034, T-035 | 쓰기 라우트 열거 표 테스트, 동일 출처 e2e, 프록시 확인 |
| `REQ-016` | `AC-017`, `AC-005` | T-014, T-017 | DN 주입 테스트, 라이브 비밀번호 변경 실패 출력 |
| `REQ-013` | `AC-014` | T-016, T-025, T-032, T-050, T-052 | 문서·차트 기본값 렌더 |
| `REQ-014` | `AC-014`, `AC-015` | T-001, T-004, T-016, T-053 | D218-14 링크, 후속 PR 체크 |

## Completion review

- [ ] Every requirement maps to an acceptance scenario and verification result.
- [ ] Material scope changes were reflected in the Change Package and re-reviewed.
- [ ] Expected evidence is attached or linked.
- [ ] Known incomplete work has an owner and tracking issue.
- [ ] The PR states the checks actually run and any important unverified path.
