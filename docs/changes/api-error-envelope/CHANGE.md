# Change: HTTP API 오류 봉투 통일, UI 백엔드 `/metrics`, CORS 정책 결정

- Change class: `D` — 외부 API 계약 변경(오류 봉투), 신규 리스너(`/metrics`)·신규 Go 의존성, 인증 경계 인접 정책(CORS). 봉투 단계(Phase 1)는 계약만 바꾸는 additive 변경이라 Class B 수준 검증으로 먼저 병합한다(Q1 해소). 쓰기 Origin 게이트(D218-16)는 CORS보다 먼저 병합한다(Q2 해소).
- Owner: 미지정 — 구현 착수 전 지정
- Related issue: [#218](https://github.com/dasomel/ldapium/issues/218) (후속 참조: #214 머신 인증, #215 커서 페이징, #216 조건부 쓰기, #217 백업 job ID)
- Status: `Accepted 2026-10-06 — maintainer instruction to process #218 (open questions resolved as recorded below)`
- Accepted by / date: 유지보수자 지시(#218 처리) / 2026-10-06 — Q1·Q2는 아래 “Open questions and risks”에 해소 결과로 기록. 구현 단계별 병합 전 Owner 지정 필요
- 작성일: 2026-10-06

> 설계 문서다. 코드·OpenAPI·Helm은 변경하지 않았고 아래 동작은 구현·런타임 검증되지 않았다.
> 현황 서술은 2026-10-06 `main`(60dae0d, #230 병합 포함) 소스에서 확인했다. 독립 비평(Codex) 지적 6건을 반영해 개정했다(Review record 참고). 확인하지 못한 항목은 “미검증”으로 표시하고 마지막 절에 모았다.
> 경로 표기: 접두 없는 `*.go`는 `ui/backend/internal/httpapi/`, `ui/frontend/…`는 전체 경로.

## Problem

외부 호출자는 오류 본문을 한 가지로 파싱할 수 없다. 같은 상태 코드가 두 형태로 나온다.

**1. 오류 생산자**

| 생산자 | 위치 | 본문 | 상태 코드 |
|---|---|---|---|
| `respondErr` (도메인 오류) | `errors.go:28-47` | `{"error"}`, 500만 `requestId` 추가(`errors.go:46`), 원문은 서버 로그만(`errors.go:44-45`) | 404 409 401 403 400 500 |
| 라우터 404/405 | `api_docs.go:77-91`(핸들러), `api_docs.go:140-155`(`handleAPINotFound`), 등록 `server.go:83,164-165` | `{"error"}`, 405는 `Allow` 헤더 | 404 405 |
| 세션 게이트 | `middleware.go:32,38,44` | Echo 기본 `{"message"}` | 401 (not logged in / session invalid / session expired) |
| 로그인 | `auth_handlers.go:24,37,45,49` | `{"message"}` | 404(SSO 모드) 429(+`Retry-After`, `auth_handlers.go:35`) 400 |
| SSO | `sso.go:83,88,92,109,124,129` | `{"message"}` | 404 400 500 |
| 프로필 게이트·쓰기 | `app_profile_handlers.go:36,46,55,69,73,79-104`, `app_method_handlers.go:26-49`, `app_export_handlers.go:14-47` | `{"message"}` | 404 403 400 428 412 422 500 |
| 동일 출처·콘텐츠 유형 | `requireProfileWrite` `app_profile_handlers.go:112-120` (호출: `app_export_handlers.go:27,62`, `app_profile_handlers.go:62`, `app_method_handlers.go:20`, `backup_handlers.go:51,84,103`, `keycloak_handlers.go:55,92`) | `{"message"}` | 403 415 |
| 백업 | `backup_handlers.go:37,47,57-133` | `{"message"}` | 404 403 428 400 412 409 422 |
| Keycloak | `keycloak_handlers.go:21-40,66-107` | `{"message"}` | 404 503 403 502 400 428 412 500, 업스트림 상태 통과(403/404/409/412/422, `keycloak_handlers.go:34-36`) |
| 입력 검증 | `user_handlers.go`, `group_handlers.go`, `tree_handlers.go` (`StatusBadRequest`, 다수가 `err.Error()`) | `{"message"}` | 400 |
| SPA 폴백 | `server.go:225` | `{"message"}` | 500 (`/api` 밖) |
| 패닉 | `middleware.Recover()` `server.go:87` → Echo 기본 핸들러(일반 `error`는 `{"message":"Internal Server Error"}`, echo v4.15.4 `echo.go:448-455`) | `{"message"}`, `requestId` 없음 | 500 (Recover 경로 런타임 미검증) |
| LDAP 헬스 | `auth_handlers.go:135-142` | `{"reachable":bool}` — 오류 봉투 아님 | 200/503 |

`echo.NewHTTPError` 호출은 비테스트 코드에 104곳이다(2026-10-06 grep).

**기존 테스트 영향(봉투가 깨뜨리는 것):** 오류 본문을 `map[string]string`으로 디코드하는 테스트가 있다 — `api_docs_test.go:60-61`(`TestUnknownAPIPathsReturnJSONError`, `api_docs_test.go:36`)와 `api_docs_test.go:404-405`. `retryable`(bool)이 추가되면 `json.Unmarshal`이 실패한다. 그 밖의 오류 본문 단언은 문자열 포함 검사다: `errors_test.go:30-37`(센티널 비누출·`requestId` 포함), `errors_test.go:65`(본문이 도메인 오류 문구를 포함), `scripts/test/test-api-edge-codes-local.py:151,154`(`json.loads(...).get('error')`가 문자열), `ui/frontend/e2e/api-docs.spec.ts`의 `page.route` 모의 응답 `{error:…}`(서버 변경과 무관). 따라서 “기존 테스트가 무수정으로 통과한다”는 주장은 성립하지 않으며, 봉투 변경(T-011)과 같은 PR에서 위 두 곳을 `map[string]any`/봉투 구조체 디코드로 갱신한다(T-011).

- `Retry-After`는 로그인 429에만 있다(`auth_handlers.go:35`, 계산 `login_limiter.go:92-98`). 503에는 없다.
- 기계가 읽을 안정적 오류 코드가 없어 호출자는 영문 문장을 문자열 매칭해야 한다(UI도 `ui/frontend/src/pages/ChangePasswordPage.tsx:70-73`에서 `code 53`·`verify old password`를 매칭).
- 관측: Echo JSON 액세스 로그(`server.go:95-97`)와 인증 이벤트(`audit_log.go:35`, `request_id`)는 있으나 Prometheus 코드가 없다(`ui/backend/go.mod`·`internal/`·`cmd/` grep 결과 없음). 준비도는 `/api/auth/config`로 대체 중이다(`ui/backend/cmd/server/main.go:93-97`).
- CORS 코드는 없다(`internal/`·`cmd/` grep 결과 없음). 브라우저 외 호출자 정책이 미정이다.
- `/metrics`와 SPA: 공개 포트의 `e.GET("/*", …)`(`server.go:214`)는 `/api` 밖의 알 수 없는 경로를 `index.html` 200으로 응답한다(`server.go:219-228`). 따라서 `/metrics`는 지금 공개 포트에서 HTML 200이다(404가 아님).

**2. 프런트엔드 소비 방식 (봉투 변경이 깨뜨리면 안 되는 지점)**

| 호출 지점 | 읽는 키 |
|---|---|
| `ui/frontend/src/lib/api.ts:46-48` (대부분의 화면) | `error` → `message` → `statusText` |
| `ui/frontend/src/lib/types.ts:190-193` | `ApiErrorBody {error?, message?}` |
| `ui/frontend/src/lib/app-profiles.ts:23`, `:67` | **`message`만** |
| `ui/frontend/src/lib/backups.ts:10` | `message` → `error` |
| `ui/frontend/src/pages/ChangePasswordPage.tsx:70-73`, 각 폼 다이얼로그 | `ApiError.message` 문자열 그대로(영문 서버 문구 매칭 포함) |
| `ui/frontend/src/context/AuthContext.tsx:47` | `ApiError` 여부만 |

결론: `message`를 지우면 응용 프로파일·백업 화면이 즉시 깨진다. **두 키를 모두 유지해야 한다.** 서버 문구(영문)는 UI가 그대로 표시하므로 문구 변경도 금지다. Go·Python 테스트는 `message` 키를 읽지 않는다(`internal/httpapi/*_test.go`, `scripts/test/*.py` grep 결과 없음). `scripts/test/test-api-edge-codes-local.py:154`는 405 본문의 `error` 문자열을 검사한다. 서버 메시지 표시를 직접 단언하는 프런트 e2e는 현재 없다(`ui/frontend/e2e/` 확인).

**3. OpenAPI**: `openapi.json:4295-4330`에 `ErrorBody`, `EchoErrorBody`, `ApiError`(oneOf) 세 컴포넌트가 있고, 경로에서 `EchoErrorBody` 158회·`ErrorBody` 38회·`ApiError` 27회 참조된다(2026-10-06 스크립트 집계). 드리프트 가드 `api_contract_test.go:39`(라우트 일치)·`:84`(오퍼레이션 완결성)는 오류 응답 형태를 검사하지 않는다. `docs/api.md:59-70`이 “두 형태 공존”을 그대로 문서화한다.

**4. CORS 상호작용**: 세션 쿠키는 `SameSite=Lax`(`middleware.go:64`, 근거 주석 `:69-72`). 동일 출처 검사(`Origin`==요청 Host·스킴)는 **프로필·메서드·백업·Keycloak 쓰기에만** 있고(`requireProfileWrite`, 위 호출 목록) 사용자·그룹·엔트리 쓰기에는 없다(`SameSite=Lax`에 의존). `Origin`이 있는 교차 출처 “단순 요청”(폼 POST 등)은 프리플라이트 없이 전송되므로 프리플라이트 차단만으로는 쓰기를 막지 못한다 → D218-16.
**#230(PR, 병합됨, `60dae0d`)은 사실로 취급한다:** `HEAD`는 GET 라우트가 있으면 GET으로 재작성되어 본문 없이 응답하고(`headPreMiddleware`, `server.go:172-190`, 로그용 원 메서드는 `restoreMethodMiddleware`가 복원), `OPTIONS`는 등록된 `/api` 경로에서 204 + `Allow`를 반환하며 `Access-Control-*`는 없다(`handleAPINotFound`, `api_docs.go:140-155` 중 `:151-153`; `Allow`는 `HEAD`·`OPTIONS`를 포함). 테스트: `api_docs_test.go:188-197`(Allow 집합), `:246`(`TestHEADBehaviour`). 함의: ① `OPTIONS` 204와 `HEAD` 오류 응답은 본문이 없어 봉투 대상이 아니다(헤더 `X-Request-Id`는 유지, D218-6) ② `OPTIONS`가 `RouteNotFound` 핸들러를 지나므로 CORS 미들웨어는 그 앞에서 프리플라이트에 직접 응답해야 한다(D218-12).

## Intent

모든 `/api` 오류가 하나의 봉투를 갖게 하고(기존 `error`·`message` 유지, `code`·`requestId`·`retryable` 추가), 후속 이슈(#214–#217)가 그 봉투와 코드 표에 새 코드를 **추가만** 하도록 규약을 고정한다. 프로세스 지표는 기본 꺼짐의 별도 리스너로 노출한다. CORS는 기본 비활성이며, 필요한 배포만 정확한 origin allowlist로 읽기 전용 교차 출처 호출을 허용한다.

## Scope

- In scope: 오류 봉투와 코드 표, 4xx 메시지 정책(D218-15), 상태 변경 요청 Origin 게이트(D218-16), 공개 포트 `/metrics` 404 라우트, `apiErrorHandler`·`respondErr`·`echo.NewHTTPError` 생산자 통합, OpenAPI 단일 `Error` 컴포넌트·공통 응답, `/metrics` 리스너·지표 계약·Helm 연동, CORS 옵트인 미들웨어, 계약·카디널리티·무비밀 테스트, `docs/api.md`·`llms.txt`.
- Affected: `ui/backend/internal/httpapi`(오류 핸들러·미들웨어·OpenAPI), `internal/config`, `cmd/server/main.go`, `internal/ldapclient`·`internal/session`(관측 훅), `ui/backend/go.mod`, `THIRD-PARTY-LICENSES.md`, `charts/ldapium`(`ui.metrics.*`, UI NetworkPolicy, `ui.cors.*`), `docs/api.md`, `ui/frontend/src/lib`(`error ?? message` 정리).
- 대상: 외부 시스템·AI 에이전트, 후속 이슈 작성자, 운영자. 브라우저 UI 사용자 영향 없음(목표).

## Non-goals

- 4xx `error` 문구 변경(검증 문구 `err.Error()` 통과 포함), 상태 코드 변경(예: Keycloak 비활성 503 유지), `/api/v1` 버전 상승.
- `/api/health/ldap` 본문 변경(프로브 계약, 봉투 대상 아님 — D218-6).
- 인증/머신 principal(#214), 커서(#215), 조건부 쓰기(#216), 백업 job ID(#217) 자체 구현. 이 패키지는 그들이 참조할 규약만 정한다.
- LDAP 서버(slapd) 지표: 기존 `openldap_exporter` 사이드카가 담당하며 중복 구현하지 않는다(D218-9).
- `SameSite` 쿠키 정책 변경, 인증 모델 변경, Origin 게이트 우회용 비활성 플래그.
- 분산 추적, 로그 포맷 변경, 사용자·DN 단위 지표.

## Requirements

- `REQ-001` — 모든 `/api` 오류 응답(4xx/5xx, 라우터 404/405, 패닉, 게이트, `respondErr`)은 단일 JSON 봉투 `{error, message, code, requestId, retryable}`로 나온다. 예외는 D218-6 항목뿐이다.
- `REQ-002` — 하위호환: `error`(문자열, 주 필드)와 `message`(동일 값 사본)를 모두 유지한다. 기존 문구·상태 코드는 바뀌지 않으며 현행 UI는 무수정으로 서버 메시지를 계속 표시한다.
- `REQ-003` — `code`는 안정적 snake_case 문자열이며 초기 목록(D218-3)은 append-only다. 이름 변경·삭제는 계약 변경이다.
- `REQ-004` — `requestId`는 모든 오류 본문에 있고 `X-Request-Id` 응답 헤더·서버 로그 줄과 같은 값이다.
- `REQ-005` — `retryable`은 고정 규칙(D218-5)으로 정해지고, 429와 일시적 503에는 `Retry-After`(정수 초)가 항상 있다.
- `REQ-006` — 5xx 본문의 `error`/`message`는 코드별 고정 문구만 담고 내부 오류 텍스트(호스트·포트·LDAP 진단·업스트림 본문)를 절대 담지 않는다.
- `REQ-007` — OpenAPI에는 오류 스키마 `Error` 하나와 공통 응답 컴포넌트만 있고, 드리프트 테스트가 모든 문서화된 오류 응답이 이를 참조함을 강제한다.
- `REQ-008` — `/metrics`는 `METRICS_ADDR` 설정 시에만 별도 리스너에서 제공하며 기본 꺼짐이다. 공개 UI 포트(8080)에는 노출되지 않으며, 공개 포트의 `/metrics`는 명시 라우트가 봉투 404로 응답한다(SPA HTML 아님). 차트는 메트릭 포트를 공개 UI Service로 노출하지 않고 허용 피어를 설정으로 제한하며 ServiceMonitor는 기본 꺼짐이다.
- `REQ-009` — 지표는 UI 백엔드 프로세스 범위이며 라벨 카디널리티에 상한이 있고, 사용자·DN·IP·요청 경로 원문·비밀을 라벨/값으로 담지 않는다.
- `REQ-010` — 지표 의존성은 기존 공급망 게이트(`scripts/licenses.sh --check`, govulncheck, 오프라인 모듈 번들, `go.sum`)를 통과한다.
- `REQ-011` — CORS 헤더는 기본으로 어떤 응답에도 붙지 않는다. `CORS_ALLOWED_ORIGINS`(정확한 origin 목록) 설정 시에만 일치하는 Origin에 한해 `Access-Control-*`가 붙고, `Vary: Origin`은 활성 시 모든 응답(일치·불일치·Origin 없음·`OPTIONS`)에 붙는다. `*`·`null`·와일드카드는 기동 거부다.
- `REQ-012` — CORS 허용이 쿠키 정책(`SameSite=Lax`)·동일 출처 쓰기 검사를 약화하지 않는다. 교차 출처 쓰기 메서드는 허용 목록에 없다.
- `REQ-013` — 롤아웃은 additive이며 `/metrics`·CORS 플래그는 기본 꺼짐이고, `docs/api.md`·OpenAPI·`llms.txt`가 동기화된다.
- `REQ-015` — `Origin` 헤더가 있는 상태 변경 요청(POST/PUT/PATCH/DELETE)은 그 Origin이 요청 자신의 origin과 같거나 허용 목록에 있을 때만 처리하고 아니면 403 `origin_mismatch`다(프로필·백업뿐 아니라 사용자·그룹·엔트리 쓰기 전부). `Origin`이 없는 요청(curl, 서비스, #214 머신 principal)은 영향이 없다.
- `REQ-016` — 오류 `message`/`error` 정책: 알려진 도메인 오류는 고정 문구, LDAP 진단 텍스트에서 파생된 문구는 코드의 고정 문구로 대체(원문은 `requestId`와 함께 서버 로그에만), 사용자 입력 검증 문구는 필드 이름만 담고 값은 담지 않는다. 어떤 오류 본문에도 DN·비밀이 없다.
- `REQ-014` — 후속 이슈(#214–#217)가 참조할 규약(코드 추가 절차, 상태→코드 기본 매핑, `retryable` 규칙, 헤더)이 이 문서에 명시되어 있다.

## Acceptance scenarios

### `AC-001` — 모든 라우트의 오류 경로가 봉투를 쓴다

- Covers: `REQ-001`, `REQ-004`
- Given 등록된 모든 `/api` 라우트(`s.echo.Routes()`, `api_contract_test.go:47` 방식으로 열거)와 세션·프로필 저장소를 갖춘 테스트 서버
- When 라우트마다 401(쿠키 없음), 404(알 수 없는 경로), 405(틀린 메서드), 403/415/428/412/422(게이트·검증), 429, 5xx(주입된 비매핑 오류·패닉)를 유발
- Then (기존 `map[string]string` 디코드 테스트 `api_docs_test.go:60-61,404-405`는 같은 PR에서 갱신되어 통과한다) 모든 응답이 `application/json`이며 `error`·`message`(같은 값)·`code`(코드 표 안)·`requestId`(비어 있지 않음, `X-Request-Id` 헤더와 동일)·`retryable`(bool)을 가진다.

### `AC-002` — UI가 서버 메시지를 계속 표시한다

- Covers: `REQ-002`
- Given 봉투 변경이 적용된 백엔드와 현행 프런트
- When 사용자·그룹 검증 실패, 프로필 412/428, 백업 409, 로그인 429, 세션 만료 401을 발생
- Then 각 화면이 서버 `error` 문구를 이전과 동일하게 표시하고, `message`만 읽는 응용 프로파일·백업 화면도 동일하게 동작한다. 새 키 `code`·`retryable`·`requestId`는 UI 파서를 깨뜨리지 않는다.

### `AC-003` — 코드 표가 고정·완결이다

- Covers: `REQ-003`
- Given 코드 표(D218-3)와 순수 매핑 헬퍼
- When 표의 모든 (생산자, 상태) 조합을 헬퍼에 입력
- Then 출력 `code`가 표와 일치하고, 표에 없는 상태 코드는 `internal`(5xx)·`invalid_request`(4xx) 폴백으로만 매핑되며, 방출 가능한 코드 집합이 골든 목록과 정확히 같다(추가는 테스트 갱신을 요구).

### `AC-004` — `retryable`과 `Retry-After`

- Covers: `REQ-005`
- Given 429(로그인 제한)·503(일시적)·502·412·428·500 응답
- When 헬퍼와 로그인 핸들러를 구동
- Then `retryable`이 D218-5 표와 같고, 429·일시적 503에 `Retry-After`가 정수 초로 있으며, 그 외 상태에는 없다.

### `AC-005` — 5xx는 내부 텍스트를 노출하지 않는다

- Covers: `REQ-006`
- Given 호스트·포트·`ldap result code`·업스트림 본문이 들어 있는 오류를 `respondErr`·Keycloak 오류·패닉으로 주입
- When 응답 본문을 검사
- Then 본문에 주입 문자열이 없고, `error`는 코드별 고정 문구이며, 서버 로그에는 같은 `requestId`로 원문이 남는다.

### `AC-006` — OpenAPI 단일 `Error`

- Covers: `REQ-007`
- Given 갱신된 `openapi.json`
- When 드리프트 테스트가 모든 오퍼레이션의 비-2xx/3xx 응답을 순회
- Then 각 응답이 `components.responses.*` 또는 `#/components/schemas/Error`를 참조하고, `ErrorBody`·`EchoErrorBody`·`ApiError`는 존재하지 않으며, 예외(`getLdapHealth` 503, 리다이렉트)는 테스트 안의 명시적 허용 목록에만 있다.

### `AC-007` — `/metrics`는 기본 꺼짐이며 공개 포트에서는 봉투 404다

- Covers: `REQ-008`
- Given `METRICS_ADDR` 미설정과 설정(예: `127.0.0.1:9331`) 두 구성
- When 공개 포트(8080)와 메트릭 포트에 `GET /metrics`(및 `/metrics/`·`HEAD`)
- Then 두 구성 모두 공개 포트는 `application/json` 404 봉투(`code: not_found`, `requestId` 포함)이고 `index.html`이 아니다. 미설정 시 메트릭 포트 리스너가 없고, 설정 시 메트릭 포트에서만 200 Prometheus 텍스트 노출이다.

### `AC-008` — 라벨 카디널리티 상한

- Covers: `REQ-009`
- Given 알 수 없는 경로 수천 개·임의 메서드·임의 쿼리로 부하
- When `/metrics`를 스크랩
- Then 시계열 수가 사전 정의 상한 이하이고 `route` 라벨은 등록된 패턴(`c.Path()`)이거나 `unmatched`뿐이다.

### `AC-009` — 지표·오류에 비밀이 없다

- Covers: `REQ-009`, `REQ-006`
- Given 로그인·비밀번호 변경·실패 시나리오와 센티널 비밀 문자열
- When `/metrics` 전체 출력과 모든 오류 본문을 검사
- Then 센티널 비밀·DN·uid·클라이언트 IP가 어디에도 없다.

### `AC-010` — 의존성 게이트

- Covers: `REQ-010`
- Given `prometheus/client_golang`(및 전이 모듈)이 추가된 브랜치
- When `scripts/licenses.sh --check`, govulncheck, `scripts/bundle-go-modules.sh`, `go mod verify`를 실행
- Then 모두 통과하고 `THIRD-PARTY-LICENSES.md`가 재생성되어 있다.

### `AC-011` — CORS 기본 없음

- Covers: `REQ-011`
- Given `CORS_ALLOWED_ORIGINS` 미설정
- When `Origin: https://app.example` 헤더로 `GET`/`OPTIONS`
- Then 응답에 `Access-Control-*`·`Vary: Origin`이 없고 `OPTIONS`는 #230 동작(204+`Allow`, `api_docs.go:151-153`)과 동일하다.

### `AC-012` — CORS 허용 목록·프리플라이트

- Covers: `REQ-011`, `REQ-012`
- Given `CORS_ALLOWED_ORIGINS=https://app.example`
- When 일치/불일치/`null` Origin으로 `GET`과 프리플라이트(`OPTIONS` + `Access-Control-Request-Method`)
- Then 일치 Origin에만 `Access-Control-Allow-Origin: https://app.example`·`Allow-Credentials: true`가 붙고, `Vary: Origin`은 일치·불일치·`Origin` 없는 요청·`OPTIONS` 응답 모두에 붙는다(공유 캐시 오염 방지). 프리플라이트는 `GET, HEAD, OPTIONS`만 허용하며 쓰기 메서드 프리플라이트는 허용 헤더 없이 거부된다. 기동 시 `*`·`null`·경로 포함 값은 오류로 종료한다.

### `AC-013` — CORS가 쓰기 보호를 약화하지 않는다

- Covers: `REQ-012`, `REQ-015`
- Given 허용 목록에 있는 교차 출처 Origin과 없는 Origin
- When 허용 목록의 Origin에서 프로필·백업 쓰기와 사용자 생성 시도(프리플라이트 포함 및 미포함 “단순 요청” 폼 POST)
- Then 프로필·백업 쓰기는 허용 목록과 무관하게 `requireProfileWrite`(Origin==Host)로 계속 403 `origin_mismatch`이고, 사용자 생성의 프리플라이트는 허용 메서드에 없어 거부된다. 허용 목록에 없는 Origin의 폼 POST는 D218-16 게이트가 403으로 막는다. 쿠키 `SameSite=Lax`는 변경되지 않는다.

### `AC-016` — 상태 변경 요청의 Origin 게이트

- Covers: `REQ-015`
- Given 사용자·그룹·엔트리·프로필·백업 쓰기 라우트 전부(`s.echo.Routes()`에서 POST/PUT/PATCH/DELETE 열거)
- When (a) `Origin`이 요청 origin과 동일 (b) 허용 목록에 없는 다른 origin (c) `Origin: null` (d) `Origin` 헤더 없음 (e) `CORS_ALLOWED_ORIGINS`에 있는 origin(사용자·그룹·엔트리 쓰기만; 프로필·백업은 계속 403), 으로 요청
- Then (a)·(d)·(e)는 현행과 같이 처리(상태·본문 불변), (b)·(c)는 403 `origin_mismatch` 봉투이며 핸들러·LDAP에 도달하지 않는다. 로그인(`POST /api/login`)·로그아웃은 목록에 포함해 같은 규칙을 적용하되 UI의 동일 출처 호출은 통과함을 e2e로 확인한다. 리버스 프록시 뒤에서 `Host`/스킴이 어긋나는 구성은 `UI_TRUSTED_PROXIES`와 함께 문서화한다(미검증, T-033).

### `AC-017` — 4xx 메시지 정책과 DN 비노출

- Covers: `REQ-016`, `REQ-006`
- Given `ldapclient/errors.go`의 래핑 지점(`:32,42,48,54`, `mapMemberErr` `:71,73`)이 만드는 오류에 DN·속성명이 든 LDAP 진단 문자열(`uid=alice,ou=people,dc=example,dc=org`, `userPassword` 등)을 주입
- When `respondErr`와 봉투 핸들러로 변환
- Then 응답 본문에 주입한 DN·진단이 없고 `error`/`message`는 해당 코드의 고정 문구이며, 서버 로그에 같은 `requestId`로 원문이 남는다. 사용자 입력 검증 문구(`validate` 패키지)는 값을 포함하지 않음을 표로 단언한다.

### `AC-018` — 차트의 메트릭 포트 보호

- Covers: `REQ-008`
- Given `helm template` 기본값과 `ui.enabled=true, ui.metrics.enabled=true` 구성
- When 렌더 결과를 단언(템플릿 테스트 또는 `helm template` + 스크립트 검사)
- Then 기본값에는 메트릭 관련 리소스·포트가 없고, 활성 시 메트릭 포트는 공개 UI Service(`…-ui`)에 포함되지 않으며 별도 Service만 갖고, 메트릭 포트에 대한 Ingress 규칙은 설정된 피어 selector로만 허용(비어 있으면 `fail`), ServiceMonitor/PodMonitor는 기본 꺼짐이다.

### `AC-014` — 롤아웃·문서

- Covers: `REQ-013`, `REQ-014`
- Given 변경이 병합된 상태
- When 기본값(`ui.metrics.enabled=false`, `CORS_ALLOWED_ORIGINS` 비어 있음)으로 배포하고 문서를 점검
- Then 배포 동작은 오류 본문 필드 추가 외에 변하지 않고, `docs/api.md`·`openapi.json`·`llms.txt`가 새 봉투·코드 표·플래그를 설명하며 “아직 지원하지 않는 것”(`docs/api.md:119-121`)에서 `/metrics`·CORS 항목이 정확히 갱신되어 있다.

### `AC-015` — 후속 이슈 참조 규약

- Covers: `REQ-014`
- Given #214–#217 변경 패키지
- When 각 패키지가 새 오류 조건(예: `cursor_invalid`, `token_invalid`)을 정의
- Then D218-14에 따라 코드 이름·상태·`retryable`을 코드 표에 추가하고 골든 목록·OpenAPI 예시를 함께 갱신한다.

## Architecture and decisions

- Relevant ADR/design links: [machine-principal-auth](../machine-principal-auth/CHANGE.md)(bearer 경로, CORS 미확장), [api-integration PLAN](../api-integration/PLAN.md), [docs/api.md](../../api.md), [AGENTS.md](../../../AGENTS.md)(`userPassword` 비노출, LDAP 와이어 코드 단위 테스트 없음 원칙).
- ADR threshold result: `required` — 외부 계약(오류 봉투·코드 표)과 신규 리스너·의존성은 되돌리기 어렵다. 수용 시 ADR 한 건으로 D218-1~14를 승격한다.

### 결정 기록 (ID는 이 패키지 한정이라 `D218-` 접두)

**D218-1 — 봉투 형태.** 모든 `/api` 오류는 다음 한 형태다.

```json
{
  "error": "profile changed; reload before saving",
  "message": "profile changed; reload before saving",
  "code": "revision_conflict",
  "requestId": "5nQe3kXyZpLwTqA0vB9cJmRdUsHf2GoE",
  "retryable": false
}
```

- 이유: `error`는 기존 `respondErr` 계약이자 `api.ts:48` 우선 키이고, `message`는 Echo 기본·`app-profiles.ts:23,67`·`backups.ts:10`이 읽으며 이슈 본문의 목표 필드다. 같은 값으로 둘 다 두면 소비자 전원이 무수정이다.
- 이슈 본문의 `request_id`(snake) 대신 `requestId`(camel)를 유지한다: 기존 500 본문과 OpenAPI(`openapi.json:4302`)가 이미 `requestId`라 바꾸면 비호환이다. 서버 로그·감사 줄의 `request_id`(`audit_log.go:35`)는 로그 스키마이므로 그대로 둔다.
- 비용: 중복 필드로 바이트가 소폭 늘고 `message`를 보존할 의무가 생긴다. 탈출구: D218-4. 추가 필드(`details`, `field` 등)는 만들지 않는다(필요 시 optional 키로 추가 가능).

**D218-2 — 단일 생산 지점.** 변환은 이미 모든 `/api` 오류가 지나가는 `apiErrorHandler`(`api_docs.go:77`, 등록 `server.go:83`)에 모은다. 핸들러가 반환한 `*echo.HTTPError`·sentinel·일반 `error`를 모두 봉투로 변환한다. `respondErr`(`errors.go:28`)는 같은 빌더(`writeAPIError`)를 호출하게 한다. 기존 `echo.NewHTTPError(status, "…")` 104곳은 1단계에서 **수정하지 않는다**: 상태 코드에서 기본 `code`를 정하고, 도메인 구분이 필요한 약 20곳만 `apiErr(status, code, msg)` 헬퍼(내부적으로 `*echo.HTTPError`)로 교체한다.
- 이유: diff 최소, 누락 불가(핸들러가 어떤 경로로 반환해도 마지막에 통과). 비용: 상태 기반 기본 코드는 덜 구체적이다. 탈출구: 구체 코드가 필요한 지점만 점진 교체.
- 비-`/api` 경로(SPA)는 현행 폴백 유지(`api_docs.go:79`).

**D218-3 — 초기 `code` 목록(닫힌 집합, append-only).**

| code | 상태 | 생산자 → 매핑 |
|---|---|---|
| `invalid_request` | 400 | 본문 파싱 실패·필수 값 누락·검증 문구(`user_handlers.go`/`group_handlers.go`/`tree_handlers.go`, `auth_handlers.go:45,49`, `app_*`/`backup_*` 400, `sso.go:88,124,129`), `respondErr` `ErrInvalidInput`(`errors.go:40`) |
| `invalid_credentials` | 401 | `respondErr` `ErrInvalidCredentials`(`errors.go:36`) |
| `unauthenticated` | 401 | `middleware.go:32`(쿠키 없음)·`:38`(`session invalid`) |
| `session_expired` | 401 | `middleware.go:44` |
| `forbidden` | 403 | `respondErr` `ErrPermissionDenied`(`errors.go:38`), `keycloak_handlers.go:27,36` |
| `admin_required` | 403 | `app_profile_handlers.go:46`, `backup_handlers.go:47` |
| `origin_mismatch` | 403 | `requireProfileWrite` 동일 출처 실패(`app_profile_handlers.go:115`) |
| `not_found` | 404 | `respondErr` `ErrNotFound`(`errors.go:30`), 라우터 404(`api_docs.go:85`), 프로필·방법 없음 404 |
| `feature_disabled` | 404 | `auth_handlers.go:24`, `sso.go:83,109`, `app_profile_handlers.go:36`, `backup_handlers.go:37` |
| `method_not_allowed` | 405 | `api_docs.go:87`(+`Allow`) |
| `conflict` | 409 | `respondErr` `ErrConflict`(`errors.go:34`) |
| `already_exists` | 409 | `respondErr` `ErrAlreadyExists`(`errors.go:32`) |
| `backup_busy` | 409 | `backup_handlers.go:74,94,130` |
| `revision_conflict` | 412 | `app_profile_handlers.go:101`, `app_method_handlers.go:46`, `backup_handlers.go:71,127`, `keycloak_handlers.go:101`, 업스트림 412 |
| `unsupported_media_type` | 415 | `app_profile_handlers.go:118` |
| `validation_failed` | 422 | `app_profile_handlers.go:92,96`, `app_method_handlers.go:42`, `app_export_handlers.go:22,47`, `backup_handlers.go:77,96,133` |
| `if_match_required` | 428 | `app_profile_handlers.go:69`, `app_method_handlers.go:26`, `backup_handlers.go:57,109`, `keycloak_handlers.go:74,98` |
| `login_rate_limited` | 429 | `auth_handlers.go:37` |
| `internal` | 500 | `respondErr` 기본(`errors.go:46`), 패닉, `app_profile_handlers.go:104`, `app_method_handlers.go:49`, `keycloak_handlers.go:107`, `sso.go:92` |
| `upstream_failed` | 502 | `keycloak_handlers.go:40` |
| `keycloak_disabled` | 503 | `keycloak_handlers.go:24` |
| `unavailable` | 503 | 예약: 일시적 의존성 장애(후속 #214 JWKS 등이 사용) |
| `cursor_invalid` | 400 | **#215**: 변조·잘림·버전·리소스/`q`/주체 불일치 커서(원인 구분 없는 일반 문구, `retryable:false`) |
| `cursor_expired` | 400 | **#215(예약)**: 현재 #215 D215-10은 “커서에 만료 없음”이라 미사용. 이름만 확보 |
| `size_limit_exceeded` | 422 | **#215**: 스캔·크기 상한 초과(D215-8), `retryable:false` |
| `job_not_found` | 404 | **#217**: 백업 job ID 없음 |
| `job_not_cancellable` | 409 | **#217**: 이미 종료 상태 job 취소(D217-5), `retryable:false` |
| `persistence_unavailable` | 503 | **#217**: job·상태 기록 저장소 일시 불가, `retryable:true` + `Retry-After` |
| `idempotency_key_conflict` | 409 | **#216 자리표시**: 같은 키의 처리 중 요청이 존재, `retryable:true` |
| `idempotency_key_reused` | 422 | **#216 자리표시**: 같은 키에 다른 요청 본문, `retryable:false` |
| `idempotency_*` (그 외) | #216 | **#216 예약 패밀리**: 정확한 이름·상태는 #216이 이 표에 추가 |
| `idempotency_outcome_unknown` | 409 | **#216**: 쓰기 결과를 판정할 수 없음(연결 유실·패닉)이거나 영속 기록의 지문 키를 알 수 없음. `retryable:false`, 리소스를 읽어 확인 후 재시도 |
| `idempotency_capacity` | 503 | **#216**: 멱등 기록 상한 도달, 새 키 거부. `retryable:true` + `Retry-After`(일시적 503 규칙) |
| `idempotency_unsupported` | 422 | **#216**: 멱등 기능이 꺼진 배포에서 키가 붙음. `retryable:false` |
| `partial_failure` | 500 | **#216**: 사용자 생성 부분 성공(보상 불가). `retryable:false`, 선택 키 `state`·`dn`(D216-5, D218-15의 DN 비노출에 대한 명시적 예외 한 건) |
| `token_invalid` | 401 | **#214 예약**: bearer 서명·`iss`/`aud` 검증 실패 |
| `token_expired` | 401 | **#214 예약**: 만료·`nbf` 이전 토큰 |
| `scope_denied` | 403 | **#214 예약**: 토큰 scope가 오퍼레이션 allowlist 밖 |

- 이름 충돌 처리: #217의 `backup_busy`를 그대로 쓰도록 이 패키지의 `backup_running`을 `backup_busy`로 바꿨다(409, `retryable:true`). **정합(해소됨):** #215는 이 표의 이름을 그대로 쓴다. 커서 오류는 `cursor_invalid`(400), `limit`·`sort`·`q` 위반은 기존 `validation_failed`(422, 필드명만 메시지에), 크기 초과는 `size_limit_exceeded`(422)이며 #215는 새 코드를 만들지 않는다. `invalid_request`는 표에 없는 4xx의 폴백으로만 남는다.
- #214가 쓰던 `bad_token`/`insufficient_scope` 가칭은 폐기하고 위 `token_invalid`/`token_expired`/`scope_denied`를 예약한다.
- 기본 폴백: 표에 없는 4xx → `invalid_request`, 5xx → `internal`. 새 생산자가 코드 없이 추가돼도 봉투는 깨지지 않는다.
- 이유(닫힌 집합): 호출자가 `switch(code)`로 분기할 수 있다. 탈출구: 새 코드는 표에 한 줄 추가(D218-14), 이름 변경은 계약 변경.

**D218-4 — `message` 보존 정책.** `message`는 `error`의 동일 사본으로 `/api/v1` 동안 유지한다(근거: `app-profiles.ts:23,67`, `backups.ts:10`). 단계: ① 서버가 두 키 모두 방출 ② UI 세 지점을 `error ?? message`로 이전(T-015) ③ 문서에 `message`를 deprecated alias로 표기 ④ 제거는 UI 이전 후 최소 한 릴리스가 지난 뒤 새 변경 패키지로만 가능. 이 패키지는 제거를 약속하지 않는다.

**D218-5 — `retryable` 규칙(동일 요청을 그대로 다시 보내면 성공할 수 있는가).**

| 조건 | `retryable` | `Retry-After` |
|---|---|---|
| 429 `login_rate_limited` | true | 필수(현행 `auth_handlers.go:35` 유지) |
| 503 `unavailable`, `persistence_unavailable` | true | 필수(정수 초, 기본 5) |
| 502 `upstream_failed` | GET/HEAD만 true, 쓰기는 false(“반복 금지” `docs/api.md:117`) | 없음 |
| 409 `backup_busy`, `idempotency_key_conflict` | true (실행 종료·처리 완료 후) | 없음 |
| 412 `revision_conflict`, 428 `if_match_required` | false — 재조회 후 새 요청 필요(재시도 아님) | 없음 |
| 503 `keycloak_disabled`(설정 사유) | false | 없음 |
| 500 `internal` | false (부분 적용 가능성, 맹목 재시도 금지) | 없음 |
| 그 외 4xx | false | 없음 |

- 이유: `retryable=true`는 “같은 요청”만 뜻한다. 412/428은 재조회가 필요해 false로 둬 자동 재시도 루프를 막는다. 비용: 502 규칙이 메서드에 의존한다. 탈출구: 502를 false로 고정(additive).
- `Retry-After`는 `retryable && status ∈ {429, 503}`일 때만, RFC 9110 §10.2.3 정수 초.

**D218-6 — 봉투 예외.** 2xx/3xx(`/api/sso/*`의 302/303 리다이렉트 포함)와 `GET /api/health/ldap`의 `{"reachable":bool}`(200/503, `auth_handlers.go:135-142`: 프로브 계약) 외 모든 `/api` 비-2xx는 봉투다. 본문이 없는 응답도 예외다: #230의 `OPTIONS` 204(`api_docs.go:151-153`)와 `HEAD` 응답(GET 재작성 후 net/http가 본문 제거, `server.go:172-190`)은 봉투 본문이 없고 `X-Request-Id` 헤더는 그대로 나간다. 예외는 OpenAPI 드리프트 테스트의 명시적 허용 목록에 이름으로 기록하며 새 예외는 이 문서 개정을 요구한다.

**D218-7 — `requestId`.** 항상 `X-Request-Id` 응답 헤더 값(`middleware.RequestID()`, `server.go:92`)에서 읽는다(`requestIDOf`, `audit_log.go:120-122`). 인바운드 `X-Request-Id` 수용 동작(Echo 기본)은 유지한다. 새 ID 체계를 만들지 않는다. 라우터 404·패닉 경로에서 헤더가 설정되는지는 AC-001이 검증한다(미검증).

**D218-8 — 5xx 본문은 고정 문구.** 상태 ≥500이면 `error`/`message`는 코드별 정적 표(`internal`→`internal error`, `upstream_failed`·`keycloak_disabled`→현행 문구, `unavailable`→`service temporarily unavailable`)에서만 가져오고 `HTTPError.Message`·`err.Error()`는 5xx에서 무시한다. 원문은 `errors.go:45`와 같은 형식으로 로그에만 남긴다. 이유: 핸들러가 실수로 `err.Error()`를 5xx에 넣어도 구조적으로 누출이 불가능하다. 비용: 5xx 문구 변경은 표 수정이 필요하다. 4xx는 현행 문구를 그대로 통과(검증 안내가 UI 가치).

**D218-9 — `/metrics` 범위.** UI 백엔드 프로세스 지표만 낸다. LDAP 서버 지표는 기존 사이드카가 이미 낸다(`charts/ldapium/templates/statefulset.yaml:266-319` `openldap_exporter`, 포트 9330, `metrics-service.yaml:13-17`, `servicemonitor.yaml:17-18`) — 중복하지 않는다. 지표(접두 `ldapium_ui_`):

| 지표 | 유형 | 라벨(상한) |
|---|---|---|
| `http_requests_total` | counter | `route`(등록 패턴 + `unmatched`), `method`(5개 + `other`), `code_class`(`2xx`…`5xx`) |
| `http_request_duration_seconds` | histogram | `route`, `method` |
| `http_requests_in_flight` | gauge | 없음 |
| `api_errors_total` | counter | `code`(D218-3 닫힌 집합) |
| `login_failures_total` | counter | `reason`(`invalid_credentials`/`rate_limited`/`malformed`/`upstream`) |
| `ldap_operations_total` | counter | `op`(`bind`/`search`/`ping`/`write`), `result`(`ok`/`invalid_credentials`/`error`) |
| `ldap_operation_duration_seconds` | histogram | `op` |
| `sessions_active` | gauge | 없음(`session.Store.Len`, `ui/backend/internal/session/store.go:117`) |

- 금지 라벨: 사용자·uid·DN·IP·쿼리 문자열·요청 경로 원문·오류 문자열. `route`는 Echo `c.Path()` 패턴만(미등록은 캐치올 패턴 또는 `unmatched`).
- 이유: 운영자에게 없는 신호(요청률·지연·로그인 실패·LDAP 호출 오류·세션 수)만 추가한다. 비용: `ldapclient`에는 주입 가능한 인터페이스가 없다(AGENTS.md Testing philosophy) → 관찰자 훅을 `dialer.Bind`/`Ping`(`ui/backend/internal/ldapclient/dial.go:35,72`)과 `client` 공통 경로에 최소로 삽입하고 와이어 경로는 라이브로 검증한다.

**D218-10 — `/metrics` 노출.** 새 env `METRICS_ADDR`(기본 빈 값 = 리스너 없음). 설정 시 `cmd/server/main.go`(`:69-76`의 단일 리스너 옆)에서 `/metrics`만 서빙하는 두 번째 `http.Server`를 띄우고 같은 종료 흐름에서 `Shutdown`한다(`:88`). 인증은 없다(Prometheus 관례); 보호는 네트워크 경계다.
- **공개 포트의 `/metrics`는 명시 라우트로 404 봉투를 반환한다**(`GET /metrics`·`/metrics/`, HEAD 포함). 이유: 지금은 SPA 폴백(`server.go:214-228`)이 알 수 없는 경로를 `index.html` 200으로 응답해, 스캐너·운영자가 “메트릭이 켜져 있다/없다”를 HTML로 오인하거나 지문 채취(fingerprinting)에 쓸 수 있고 헬스체크가 200을 성공으로 오판할 수 있다. 비용: 라우트 1개와 OpenAPI 비문서화 예외(`/api` 밖). 탈출구: 라우트 제거 시 SPA 폴백으로 복귀. (SPA 폴백을 유지하고 AC를 지우는 대안은 기각.)
- 차트(`charts/ldapium`, 모두 `ui.enabled=true`이면서 `ui.metrics.enabled=true`일 때만; 기본 false): ① 메트릭 컨테이너 포트(제안 9331 — 9330은 slapd exporter 사용)는 **공개 UI Service(`ui-service.yaml`, 포트 `http`만 노출)에 추가하지 않고** 별도 `…-ui-metrics` Service로만 노출한다. ② UI 파드용 NetworkPolicy를 `ui.metrics.networkPolicy.*`로 신설한다: 현재 차트 정책은 slapd 파드만 선택하므로(`networkpolicy.yaml:14-16`, `ldapium.selectorLabels`) UI 파드(`ldapium.ui.selectorLabels`, `_helpers.tpl:70`)에는 정책이 없다. 신규 정책은 UI 파드를 선택하면 기본 거부로 바뀌므로 **기존 UI 인그레스 포트(8080, `http`)의 허용을 명시적으로 유지**하고(`ui.networkPolicy.httpFrom` 설정, 기본은 전체 허용 `- {}`로 현행 동작 유지) 메트릭 포트는 `ui.metrics.networkPolicy.from`(원시 NetworkPolicy peer 목록)에만 허용한다. 이 목록이 비어 있으면 `fail`(빈 `from`은 “전체 허용”이라는 `networkpolicy.yaml:3-4`의 선례를 따름). 값 예: `- namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: monitoring}}`. 기본값은 두지 않는다(명시 설정 필수). ③ `ui.metrics.serviceMonitor.enabled`·`ui.metrics.podMonitor.enabled` 모두 기본 false이며 켜면 UI 메트릭 Service/포트만 대상으로 한다(slapd exporter의 `servicemonitor.yaml`과 라벨 충돌이 없도록 `ldapium.ui.labels` 사용).
- 검증(AC-018): `helm template`(기본값/활성/빈 `from`) 단언 — 기본값에 신규 리소스 없음, 공개 UI Service에 메트릭 포트 없음, NetworkPolicy가 메트릭 포트를 설정된 피어로만 허용, 빈 `from`은 렌더 실패.
- 이유: 공개 포트에 올리거나 모든 파드에 열면 인증 없는 운영 정보가 노출된다. 탈출구: env 비우기로 즉시 해제, `ui.metrics.enabled=false`.

**D218-11 — 의존성: `prometheus/client_golang` 채택.**

| 기준 | 직접 구현(텍스트 노출) | `prometheus/client_golang` |
|---|---|---|
| 코드량·위험 | 약 150줄 이상, 히스토그램·이스케이프·정렬 직접 책임, 표준 도구와 미세한 비호환 위험 | 검증된 구현, 히스토그램·Go/프로세스 컬렉터 제공 |
| 의존성 | 0 | 전이 모듈 다수(정확한 목록·수는 미검증, T-020에서 `go mod graph`로 확정) |
| 라이선스 | — | Apache-2.0/BSD 계열 예상 → `scripts/licenses.sh`의 `GO_ALLOWED`(`MIT,Apache-2.0,BSD-3-Clause,BSD-2-Clause,ISC`) 통과 예상(미검증) |
| 공급망·오프라인 | — | `go.sum` 증가, `scripts/bundle-go-modules.sh`(모듈 캐시 번들)·govulncheck(`.github/workflows/security-scan.yml:72-99`) 대상 |

결정: `client_golang`을 쓰되 전역 기본 레지스트리 대신 전용 `Registry`를 만들고 `internal/metrics` 패키지(좁은 인터페이스: `ObserveHTTP`, `ObserveLDAP`, `LoginFailure`, `APIError`)에 가둔다. 이유: 직접 구현의 정확성 부담이 의존성 비용보다 크고, 인터페이스 격리로 교체 가능하다. 탈출구: AC-010 게이트가 실패하거나 전이 의존성이 부담이면 같은 인터페이스 뒤를 직접 구현으로 교체. 의존성 추가는 Class C 증거(licences·govulncheck·번들)를 PR에 첨부한다.

- **구현 결과(슬라이스 C, 2026-10-06):** 의존성은 `client_golang` v1.24.1(+ 직접 필요한 전이 모듈 7개: beorn7/perks, cespare/xxhash/v2, munnerz/goautoneg, prometheus/client_model·common·procfs, google.golang.org/protobuf; `go.mod`·`go.sum`), 라이선스는 전부 `GO_ALLOWED` 안(MIT/Apache-2.0/BSD-3)이고 `licenses.sh --check`·`go mod verify`·`bundle-go-modules.sh`·govulncheck 통과. **발견·결정 D218-C1:** `go-licenses`는 호스트 OS의 빌드 태그로 패키지를 열거해 `prometheus/procfs`(linux 전용)가 macOS 실행에서만 빠졌다 — CI(linux)의 `--check`와 어긋나므로 `scripts/licenses.sh`가 항상 `GOOS=linux`로 열거하도록 고쳤다(툴은 호스트용으로 설치). **D218-C2:** `internal/metrics`는 `Recorder` 인터페이스(+`Nop`)와 전용 `Registry`이며 모든 라벨 값을 닫힌 집합으로 정규화한다(라우트=등록 패턴 또는 `unmatched`, 메서드 5개+`other`, 코드=`codeTable`+`other`). `/metrics` 비활성이면 `Nop`라 수집·리스너가 없다. HTTP 미들웨어는 가장 바깥(Recover 앞)에서 `c.Path()`·응답 상태를 기록한다. LDAP 관측은 `ldapclient.Observer` 한 개(op/result/duration)이며 `client.conn`을 `Search/Add/Modify/Del/ModifyDN/PasswordModify`만 감싼 `obsConn`으로 바꿔 삽입했고 `bind`는 dial+uid 조회+bind 전체, `ping`은 헬스 프로브다(로그인 실패 `reason`·`sessions_active`는 각각 `handleLogin`·`session.Store.Len`). **D218-C3:** `METRICS_ADDR`는 `host:port`(포트 1–65535, 호스트에 공백·URL 문법 불가)만 받고 `LISTEN_ADDR`와 같은 포트·겹치는 호스트(와일드카드 포함)면 기동 거부다. 리스너(`cmd/server/metrics.go`)는 `GET /metrics` 정확 경로만 제공하고 나머지는 404, 다른 메서드는 405다. 공개 포트는 `GET /metrics`·`/metrics/`를 명시 라우트로 404 봉투(`not_found`)로 응답한다(HEAD 포함, `/api` 밖이므로 OpenAPI에는 없음). **D218-C5:** 차트의 포트 충돌 검사는 `ui.service.port`가 아니라 실제 컨테이너 리스너 8080과 비교한다(Service 포트 80→8080은 정상 구성이며 `ui.metrics.port=8080`은 백엔드가 기동을 거부하므로 렌더 단계에서 실패). **D218-C6:** `licenses.sh`는 PATH에 없는 도구를 예측 가능한 `/tmp` 경로가 아니라 호출마다 `mktemp -d`(0700)에 설치·실행하고 지운다.
**D218-C4(차트):** UI 컨테이너/Service 포트 이름을 `metrics`가 아닌 `ui-metrics`로 했다 — slapd `servicemonitor.yaml`의 셀렉터(`ldapium.labels`)가 UI Service 라벨의 부분집합이라 같은 이름이면 slapd 모니터가 UI 메트릭 포트를 긁을 수 있다. 메트릭 Service는 `component: ui-metrics` 라벨, ServiceMonitor/PodMonitor는 그 라벨·UI 파드만 선택한다. 문서의 `ui.networkPolicy.httpFrom` 기본 `- {}`는 `from` 항목을 아예 생략하는 빈 목록(`[]`)으로 구현했다(의미 동일 = 전체 허용, 빈 피어 요소에 의존하지 않음). 증거: `internal/metrics`·`httpapi/metrics_test.go`·`config/metrics_addr_test.go`·`cmd/server/metrics_test.go`, `scripts/test/test-chart-ui-metrics.sh`(42 단언, CI helm 잡·`make check`), 라이브 `test-api-edge-codes-local.py`(실제 LDAP bind/search/write 카운터, 공개 포트 404 봉투, 비밀·IP·경로 비누출). 미검증: Prometheus Operator CRD 하의 ServiceMonitor/PodMonitor 실제 스크랩(렌더만 확인), 클러스터 NetworkPolicy 집행(CNI 의존).

**D218-12 — CORS.** 기본: CORS 헤더 없음(현행). 옵트인 env `CORS_ALLOWED_ORIGINS`(쉼표 구분, 정확한 `scheme://host[:port]`만).
- 기동 시 검증: `*`, `null`, 경로·쿼리·사용자 정보 포함, 빈 요소는 실패.
- 활성 시 `Vary: Origin`을 **모든** 응답에 붙인다 — 일치·불일치·`Origin` 없는 요청·`OPTIONS` 응답 전부. 이유: 같은 URL의 응답이 Origin에 따라 달라지므로 공유 캐시가 한 Origin용 응답을 다른 Origin에 재사용하면 안 된다(`api_docs.go:63`의 `Cache-Control: public` 정적 응답 포함). 비활성 시에는 아무 헤더도 붙이지 않는다.
- 일치하는 `Origin`에만 `Access-Control-Allow-Origin: <그 값>`·`Access-Control-Allow-Credentials: true`; 불일치는 `Access-Control-*`를 붙이지 않는다(차단은 브라우저).
- 허용 메서드는 `GET, HEAD, OPTIONS` 고정, 허용 요청 헤더 `Content-Type`·`Accept`, 노출 헤더 `X-Request-Id`·`Retry-After`·`ETag`, `Max-Age` 600. 프리플라이트(`OPTIONS` + `Access-Control-Request-Method`)는 CORS 미들웨어가 핸들러 앞에서 직접 위 헤더와 204로 응답한다(#230의 `OPTIONS`가 `RouteNotFound` 핸들러 `api_docs.go:151-153`를 지나므로 미들웨어가 먼저 가로채야 한다). 그 외 `OPTIONS`는 #230 동작(204+`Allow`)을 유지한다.
- 프리플라이트 차단은 쓰기를 막지 않는다: `Content-Type: application/x-www-form-urlencoded` 등 “단순 요청”은 프리플라이트 없이 전송된다. `Origin`은 인증이 아니다. 쓰기 보호는 D218-16의 서버측 Origin 게이트가 담당하며 CORS는 읽기 전용 허용에 한정된다.
- 쿠키 상호작용: 세션 쿠키는 `SameSite=Lax`(`middleware.go:64`)라 **다른 사이트(registrable domain이 다른 origin)의 fetch/XHR에는 쿠키가 실리지 않는다.** 따라서 CORS 허용은 같은 사이트의 다른 origin(예: `console.example.com` → `ldapium.example.com`)의 읽기 호출에만 의미가 있다. `SameSite=None`으로 완화하지 않는다(SSO 콜백·CSRF, 주석 `middleware.go:69-72`).
- 머신 principal(#214)은 브라우저가 아니고 `Origin` 헤더를 보내지 않으므로 CORS가 필요 없으며 D218-16에도 영향이 없다. #214는 CORS를 확장하지 않는다(`machine-principal-auth` T-012).
- **구현 결과(슬라이스 D, 2026-10-06):** `CORS_ALLOWED_ORIGINS`는 `config.parseCORSOrigins`가 검증한다(`*`·`null`·경로/쿼리/프래그먼트/사용자 정보·빈 요소·비 http(s)는 기동 거부, 소문자 정규화·중복 제거). 목록이 비어 있으면 미들웨어가 등록되지 않고 `Server.writeOrigins`도 비어 있다. 목록이 있으면 `cors.go`의 미들웨어(RequestID·로거·`Secure` 뒤, Origin 게이트 앞)가 등록되고 같은 목록이 쓰기 게이트의 허용 목록이 된다. **D218-D1:** 헤더 부여는 문서(T-031)대로 `GET`/`HEAD` 실제 응답과 프리플라이트에만 한정한다 — 목록의 Origin이 보낸 쓰기(게이트는 통과)의 응답에는 `Access-Control-*`를 붙이지 않아 페이지가 응답을 읽을 수 없다. **D218-D2:** 허용되지 않는 프리플라이트(쓰기 메서드·불일치·`null`·`Access-Control-Request-Method` 없는 `OPTIONS`)는 `Access-Control-*` 없이 `next`로 넘겨 #230 동작(204+`Allow` 또는 404 봉투)을 그대로 유지한다. 허용된 프리플라이트는 핸들러 앞에서 204로 직접 응답하며 경로가 `/api`가 아니거나 존재하지 않아도 같다. **D218-D3:** 허용된 프리플라이트 응답에는 `Vary: Origin` 외에 `Access-Control-Request-Method`·`Access-Control-Request-Headers`도 `Vary`에 더한다(응답이 그 요청 헤더에 따라 달라지므로; 문서의 `Vary: Origin` 요구는 충족). `Vary`는 기존 값을 보존하며 중복 추가하지 않는다. 차트는 `ui.cors.allowedOrigins`(기본 빈 목록 → env 없음, 쉼표로 결합). 증거: `config/cors_origins_test.go`, `httpapi/cors_test.go`(AC-011~013: 기본 꺼짐, 전 응답 `Vary`, 일치/불일치/`null`/대소문자/스킴/포트/접두 변형, 쓰기 무헤더, 프리플라이트 표, 프로필·백업 쓰기 `origin_mismatch` 유지, 쿠키 `SameSite=Lax`), 변이 증명(규칙별로 코드를 망가뜨리면 테스트 실패: `Vary` 제거, 임의 Origin 허용, 쓰기 헤더 부여, 쓰기 프리플라이트 허용, 자격 증명 헤더 제거, 프리플라이트 가로채기 제거, `*` 반사, 미들웨어 항상 켬/끔, 게이트 목록 공유 해제, 기동 검증 5종 — `null` 거부는 스킴 검사와 중복이라 단독 제거로는 살아남음), `scripts/test/test-chart-ui-cors.sh`, 라이브 `test-api-edge-codes-local.py`.
- 이유: 정당한 필요(같은 사이트 브라우저 대시보드의 읽기)만 열고 와일드카드+자격 증명 조합을 구조적으로 불가능하게 한다. 비용: 교차 출처 쓰기 UI는 지원하지 않는다. 탈출구: 쓰기 허용이 필요하면 별도 변경 패키지로 D218-16 허용 규칙을 확장.

**D218-13 — 호환성·롤아웃.** additive만: 제거된 키 없음, `/api/v1` 유지(`GET /api/v1/meta`의 `apiVersion` 불변). `/metrics`·CORS는 기본 꺼짐. `docs/api.md`의 “오류 형식”(`:59-68`)·“상태 코드”(`:100-110`)·“아직 지원하지 않는 것”(`:118-121`)과 `llms.txt`, OpenAPI를 갱신한다. 병합 순서: Phase 1 봉투(+OpenAPI+문서+4xx 메시지 정책) → Phase 1b 쓰기 Origin 게이트(D218-16) → Phase 2 `/metrics` → Phase 3 CORS. 각 단계는 독립 병합·되돌리기 가능.

**D218-14 — 후속 이슈 규약(#214–#217).**
1. 새 오류 조건은 D218-3 표에 `code` 한 줄(이름·상태·생산자·`retryable`)을 추가하고 골든 목록 테스트·OpenAPI 설명을 같은 PR에서 갱신한다.
2. 새 생산자는 `apiErr(status, code, msg)`를 쓴다. 상태 기본 매핑으로 충분하면 `echo.NewHTTPError`도 허용되나 도메인 구분이 있으면 코드를 명시한다.
3. 새 응답 헤더(`Retry-After`, `ETag`, `Link` 등)는 CORS 노출 목록(D218-12)과 OpenAPI 응답 헤더에 반영한다.
4. 5xx 문구는 정적 표에 추가한다(D218-8). 상태 코드 의미는 `docs/api.md:101-111`과 일치시킨다.
5. 후속 코드는 D218-3 표에 이미 흡수했다: #215 `cursor_invalid`·`cursor_expired`(예약)·`size_limit_exceeded`, #216 `idempotency_key_conflict`·`idempotency_key_reused`(자리표시, `idempotency_*` 패밀리는 #216이 확정), #217 `job_not_found`·`job_not_cancellable`·`backup_busy`·`persistence_unavailable`, #214 `token_invalid`·`token_expired`·`scope_denied`(예약; 일시적 JWKS 장애는 `unavailable`+`Retry-After`). 모든 예시·테스트는 `error`와 `message`를 함께 보여야 한다(D218-1). 예: 429 응답 `{"error":"too many failed login attempts","message":"too many failed login attempts","code":"login_rate_limited","requestId":"…","retryable":true}` + `Retry-After: 42`.

**D218-15 — 4xx 메시지 정책(DN·비밀 비노출).** `respondErr`가 사용자에게 통과시키던 `err.Error()`는 두 종류다. (1) 도메인 sentinel 자체(`domain/errors.go`: `entry not found`, `invalid credentials`, …) — 고정 문구라 그대로 둔다. (2) LDAP 진단이 붙은 래핑 오류 — `ldapclient/errors.go:32`(`ErrInvalidCredentials: <le.Err>`), `:42`·`:54`(`ErrInvalidInput: <le.Err>`), `:48`(`ErrConflict: <le.Err>`), `mapMemberErr`의 `:71`·`:73` — 진단에는 DN·속성명·정책 문구가 들어갈 수 있다.
- 규칙: ① `errors.Is`로 매칭된 sentinel이 있고 `err.Error()`가 sentinel 문구와 다르면(= 래핑된 진단이 있음) `error`/`message`는 **해당 코드의 고정 문구**(sentinel 문구)로 대체하고 원문은 `log.Printf("… [%s] …", requestId, err)`로 서버 로그에만 남긴다(`errors.go:45`와 같은 형식). ② 사용자 입력 검증 문구(`validate/validate.go`의 `uid must be…`, `cn must not…` 등)는 필드 이름만 담고 사용자 값을 에코하지 않는다 — 신규 검증 문구도 값을 넣지 않는다(리뷰 체크리스트, 코드 표 테스트). ③ `echo.NewHTTPError(4xx, err.Error())` 호출(`tree_handlers.go`·`group_handlers.go`·`user_handlers.go`·`app_*`·`backup_handlers.go:133`)은 `err`가 `validate`/`appprofile` 검증 오류일 때만 허용하고, 그 오류에 LDAP 진단이 섞일 수 있는 지점은 T-017에서 열거해 고정 문구로 교체한다.
- **알려진 UX 비용(미검증 일부):** UI는 일부 서버 진단을 그대로 표시한다(`ChangePasswordPage.tsx:70-73`이 `code 53`·`verify old password` 문구를 매칭하고, 주석은 ppolicy 품질·이력 위반 문구를 “as-is”로 보여 준다고 명시). ①이 적용되면 그 구체 사유는 사용자 화면에서 사라지고 고정 문구만 보인다. 해당 문구가 현재 어떤 경로(sentinel 래핑 vs 500 경로)로 도달하는지는 미검증(T-017에서 라이브로 확인). 완화: 비밀번호 변경 실패는 `code`(예: 기존 `invalid_credentials`/`invalid_request`)로 UI 분기를 옮기고, 운영자는 `requestId`로 로그를 조회한다. 탈출구(구현하지 않음): DN이 없음을 보장하는 진단 패턴 allowlist를 코드별로 추가하는 별도 변경.
- **구현 결과(슬라이스 A, `l1-ldap`/`l1-ui` 이미지로 라이브 확인 2026-10-06; 위 “탈출구”를 유지보수자 지시로 구현함 — 재검토 필요):** 미검증 (e)의 답: 비밀번호 변경 실패 중 ppolicy·ppm 제약 위반(LDAP 19)은 `ErrInvalidInput` 래핑으로 400에 `invalid input: <진단>`으로 도달한다(`Password fails quality checking policy`, `Password is not being changed from existing value`, ppm 강도 검사 등). 잘못된 현재 비밀번호는 LDAP 53(`unwilling to verify old password`)이라 `mapErr` 기본 경로 → **500 `internal error`**로, 기존에도 `ChangePasswordPage.tsx`의 `code 53` 분기는 서버 응답에 도달하지 못한다(변경 없음). **기존 누출 발견:** ppm의 모든 메시지는 `Password for dn="<사용자 DN>" …` 형태라 지금까지 사용자 DN이 400 본문에 실려 나갔다. 구현: `error_diagnostics.go`의 고정 allowlist(ppolicy 고정 문구, 값 없는 ldapclient 검증 문구)와 ppm 꼬리 패턴(DN 접두를 제거하고 `Password <꼬리>`로 전달, 숫자·클래스명만 가변, `forbidden characters in <set>`은 개수만)을 통과한 진단만 전달하고 나머지는 센티널 고정 문구로 대체·원문은 로그. 표 주도 테스트로 고정. 비용: 일부 정확한 사유 상실, `ErrInvalidInput`류 4xx의 정보량 감소.

**D218-16 — 상태 변경 요청의 Origin 게이트.** POST/PUT/PATCH/DELETE 요청에 `Origin` 헤더가 **있으면** 서버는 그 값이 (a) 요청 자신의 origin(스킴·Host 일치, `requireProfileWrite`(`app_profile_handlers.go:112-120`)와 같은 비교)과 같거나 (b) `CORS_ALLOWED_ORIGINS` 허용 목록(설정된 경우)에 있을 때만 통과시키고, 아니면 핸들러 실행 전에 403 `origin_mismatch` 봉투로 거부한다. `Origin` 헤더가 **없는** 요청(curl, 서비스, #214 머신 principal 등 비브라우저)은 영향이 없다. `Origin: null`은 거부한다. 프로필·메서드·백업·Keycloak 쓰기의 기존 `requireProfileWrite`(Origin 필수·동일 출처만, 허용 목록 무관)는 더 엄격하므로 그대로 둔다 — 새 게이트는 그 앞의 전역 미들웨어(`/api` 쓰기 메서드)이며 `GET`/`HEAD`/`OPTIONS`에는 적용하지 않는다.
- 범위: 사용자·그룹·엔트리 이동·로그인·로그아웃을 포함한 모든 `/api` 쓰기. `POST /api/login`은 Origin 없는 스크립트 호출(`docs/api.md` 로그인 예)이 계속 동작해야 하므로 `Origin` 없음 규칙이 필수다.
- 호환성 영향(기록): ① 브라우저 UI의 동일 출처 호출은 `Origin`==요청 origin이라 통과 — 단 리버스 프록시·Ingress가 `Host`/스킴을 재작성하면(예: TLS 종단 후 `http` 전달, `X-Forwarded-*`) 요청이 보는 origin이 브라우저 Origin과 달라 정상 UI 쓰기가 403이 될 수 있다 → `c.Scheme()`/`Host` 산출이 `UI_TRUSTED_PROXIES`(`ip_extractor.go`)와 `X-Forwarded-Proto/Host`를 어떻게 다루는지 T-033에서 확인하고 필요 시 신뢰 프록시 설정으로만 허용한다(현재 프로필·백업 쓰기가 같은 비교를 이미 쓰고 있어 같은 위험을 이미 지고 있음 — 미검증). ② 다른 사이트/비허용 origin의 브라우저 폼 POST는 거부된다(의도). ③ Origin을 보내는 비브라우저 클라이언트(일부 HTTP 라이브러리)는 영향을 받을 수 있어 릴리스 노트에 명시.
- 테스트: 쓰기 라우트 열거 표 주도 테스트(AC-016 (a)–(e)), UI e2e 동일 출처 쓰기 회귀(`ui/frontend/e2e`), 프록시 헤더 구성 단위 테스트.
- **구현 결과(슬라이스 B, 2026-10-06; T-033 미검증 (d)의 답):** 게이트는 `origin_gate.go`의 전역 미들웨어(`Recover`·`RequestID`·로거·`Secure` 뒤, 라우팅 핸들러·세션 게이트 앞)로 `/api` 아래 POST/PUT/PATCH/DELETE에만 적용한다. `Origin` 헤더가 존재하면(빈 값 포함) `sameOrigin`(스킴 대소문자 무시, 호스트는 소문자·후행 점 제거·해당 스킴의 기본 포트(80/443) 제거·IPv6 대괄호 정규화 후 양쪽 비교 — 프록시가 Host를 대문자로 쓰거나 `:443`을 붙여도 통과하고 suffix/userinfo/`null` 속임수는 계속 거부, 경로·쿼리·프래그먼트·사용자 정보 없음, `null`·빈 값 거부)이거나 `Server.writeOrigins`(CORS 허용 목록이 들어올 슬라이스 D 전까지 빈 목록)에 정확히 있을 때만 통과하고 아니면 403 `origin_mismatch`다. 문구는 `requireProfileWrite`의 `same-origin request required`와 구별되도록 고정 `request origin not allowed`를 쓴다(코드는 같음, 새 코드 없음). `requireProfileWrite`는 같은 `sameOrigin`을 호출하도록 정리했고(빈 Host의 Origin만 더 엄격해짐) 동작은 그대로다. **프록시 확인(T-033):** 서버의 자기 origin은 `c.Scheme()`(TLS 또는 `X-Forwarded-Proto`/`X-Forwarded-Protocol`/`X-Forwarded-Ssl`/`X-Url-Scheme`, 신뢰 프록시와 무관하게 헤더를 그대로 신뢰)와 `req.Host`(`X-Forwarded-Host`는 쓰지 않음)다. 따라서 Ingress가 브라우저의 `Host`를 보존하고 TLS 종단 시 `X-Forwarded-Proto: https`를 붙이면 통과하고(nginx-ingress 기본 동작), `Host`를 재작성하는 프록시는 정상 UI 쓰기도 403이 된다. 헤더 위조는 이득이 없다: 게이트는 브라우저가 위조할 수 없는 `Origin`을 요청 자신의 origin과 비교하는 것이고 교차 출처 단순 요청은 `X-Forwarded-*`를 붙일 수 없다. `UI_TRUSTED_PROXIES`는 클라이언트 IP(`RealIP`)에만 영향을 주며 이 비교에는 관여하지 않는다. Vite 개발 프록시는 `changeOrigin: false`라 Host/Origin이 함께 보존된다(`vite.config.ts`). 증거: `origin_gate_test.go`(순수 헬퍼·프로브 서버로 핸들러 비도달 관측·전 쓰기 라우트 (a)–(e) 열거), 라이브 `test-api-edge-codes-local.py`(foreign/`null`/무헤더/동일 출처, 로그인·로그아웃 포함), 라이브 Playwright `origin-gate.spec.ts`(브라우저 로그인·쓰기가 실제 `Origin`과 함께 통과). 비-`/api` 경로는 게이트 대상이 아니다.
- 이유: `Origin`은 인증이 아니지만 `SameSite=Lax` 쿠키가 같은 사이트의 다른 origin에는 실리므로, 허용되지 않은 same-site origin의 폼 POST가 사용자·그룹 쓰기에 도달하는 경로를 서버가 직접 닫는다. 비용: 프록시 구성 의존, 일부 클라이언트 영향. 탈출구: 게이트를 `UI_ORIGIN_GATE=off`로 끄는 플래그는 두지 않는다(보안 기본값 유지) — 문제 시 Phase 롤백(PR revert).

- Alternatives and important trade-offs:
  - 이슈의 `code/message/request_id/retryable`만 방출(기존 키 제거): 기각 — `app-profiles.ts`·`backups.ts`가 깨지고 외부 소비자가 이미 `error`를 읽는다(`docs/api.md:61`).
  - 핸들러마다 `respondErr`로 일괄 치환: 기각 — 104곳 diff, 누락 위험. 단일 핸들러(D218-2)가 더 작고 안전.
  - 문자열 기반 코드 추론: 기각 — 영문 문구가 바뀌면 조용히 틀린다. 상태 기본 코드 + 명시 코드.
  - `/metrics`를 8080 경로로 제공: 기각 — 인증 없는 운영 정보가 공개 포트에 노출(D218-10).
  - CORS `*`: 기각 — 자격 증명과 양립 불가.

## Change impact

| Area | Impact / evidence needed |
|---|---|
| Source / API / command | `errors.go`·`api_docs.go`·`middleware.go` 및 `apiErr` 교체 지점(약 20곳), `internal/metrics`(신규), CORS 미들웨어(신규), `cmd/server/main.go` 보조 리스너. 오류 본문 필드 추가는 외부 API 변경 → 계약·UI 증거 필요 |
| Dependencies / lockfiles | `ui/backend/go.mod`·`go.sum`에 `prometheus/client_golang` + 전이 모듈 추가(Phase 2). 프런트 의존성 변경 없음 |
| Runtime / toolchain | 선택적 두 번째 리스너·고루틴. 메모리·CPU 영향은 라벨 상한으로 제한 — 증거: 카디널리티 테스트 |
| CI / CD | 기존 테스트 갱신(`api_docs_test.go:60-61,404-405`, 봉투 변경과 같은 PR), Go 테스트 추가, `helm template` 단언 추가, 기존 `licenses.sh --check`·govulncheck 게이트 통과 필요. 신규 워크플로 없음. 라이브 검증은 `scripts/test/test-api-edge-codes-local.py` 확장(기존 e2e 레인 재사용) |
| Release / packaging | 릴리스 노트: 오류 본문 추가 필드·새 env·차트 값. 이미지 구조 변경 없음 |
| Generated output | `THIRD-PARTY-LICENSES.md` 재생성(Phase 2). `openapi.json`·`llms.txt`는 손작성이라 직접 수정 |
| Security / supply chain | 인증 없는 `/metrics` 노출 경계·차트 NetworkPolicy(D218-10), 지표·오류의 DN·비밀 비포함(D218-15, AC-005/009/017), CORS 자격 증명·`Vary` 규칙(D218-12), 쓰기 Origin 게이트(D218-16), 신규 의존성 감사(D218-11). 호환성 영향: 프록시 뒤 Host/스킴 재작성, Origin을 보내는 비브라우저 클라이언트, 사용자 화면의 LDAP 진단 문구 상실(D218-15) |
| Offline / air-gap | 모듈 캐시 번들(`scripts/bundle-go-modules.sh`)에 새 모듈이 포함되는지 확인. 런타임 외부 호출 없음 |
| Documentation / operations | `docs/api.md`, `llms.txt`, `charts/ldapium/README.md`, 운영 가이드(스크랩·NetworkPolicy 주의) |
| Portfolio / downstream repositories | #214–#217 변경 패키지가 D218-14를 참조. 소비자·에이전트 안내(`llms.txt`) 갱신 |

## Verification plan

| Acceptance ID | Verification method | Environment | Expected evidence |
|---|---|---|---|
| `AC-001` | 기존 `map[string]string` 디코드 테스트(`api_docs_test.go:60-61,404-405`) 갱신 + 계약 테스트: 빈 설정 `Server`(`api_docs_test.go:21`의 `New(cfg,nil,nil,spa)` 방식)로 401·404·405를 전 라우트에 구동. 403/415/428/412/422는 세션 저장소(`session.Store` + 서명 쿠키)와 임시 프로필 저장소를 갖춘 테스트 서버로 구동(타당성 미검증, T-003). 패닉·5xx는 테스트 전용 라우트에서 주입 | `go test ./...` (ui/backend) | 모든 라우트×오류 클래스에서 5개 키 존재, `X-Request-Id`와 `requestId` 일치 |
| `AC-002` | Playwright e2e: `page.route`로 각 오류 형태(`error`+`message`+`code`)를 주입해 사용자·그룹·프로필·백업·로그인 화면이 서버 문구를 표시함을 단언. 기존 백업·프로필 e2e 회귀 | `npm run e2e` (ui/frontend) | 화면별 문구 표시 단언 |
| `AC-003` | 순수 매핑 헬퍼 표 주도 단위 테스트 + 코드 골든 목록(`ldap.NewEntry` 방식처럼 모킹 프레임워크 없음) | `go test` | 표·골든 일치 |
| `AC-004` | 단위: 헬퍼 규칙 표, 로그인 핸들러 429 `Retry-After`(`login_limiter_test.go` 확장) | `go test` | 규칙 표 일치, 정수 초 |
| `AC-005` | 단위: 센티널 문자열을 `respondErr`·`keycloakErr`·Recover에 주입해 비누출·로그 상관 확인(`errors_test.go:15` 확장) | `go test` | 본문에 센티널 없음 |
| `AC-006` | 정적 드리프트 테스트 확장(`api_contract_test.go`): 비-2xx/3xx 응답 `$ref` 검사, 구 컴포넌트 부재 | `go test` | 위반 0건 |
| `AC-007` | 통합: 두 구성으로 서버 기동, 공개 포트 `/metrics`가 봉투 404(HTML 아님)인지와 메트릭 포트 응답 확인. 라이브: `test-api-edge-codes-local.py`에 `/metrics` 스크랩 단계 추가 | go test(httptest) + 로컬 Docker 스택 | 포트·상태·형식 확인 로그 |
| `AC-008` | 부하 테스트: 임의 경로·메서드 N회 후 시계열 수 상한 단언 | `go test` | 상한 이하 |
| `AC-009` | 센티널 비밀·DN으로 시나리오 수행 후 `/metrics`·오류 본문 grep | go test + 라이브 | 센티널 0건 |
| `AC-010` | `./scripts/licenses.sh --check`, govulncheck, `scripts/bundle-go-modules.sh`, `go mod verify` | 로컬/CI | 통과 로그, 재생성된 `THIRD-PARTY-LICENSES.md` |
| `AC-011` | 단위: 미설정 서버에서 Origin 포함 `GET`/`OPTIONS` | `go test` | `Access-Control-*` 없음 |
| `AC-012` | 단위: 일치·불일치·`null`·프리플라이트·기동 거부 케이스 표 | `go test` | 헤더 단언 |
| `AC-013` | 단위: 허용 Origin의 프로필 쓰기 403 `origin_mismatch`, 쓰기 프리플라이트 거부, 비허용 Origin 폼 POST 거부 | `go test` | 단언 |
| `AC-016` | 쓰기 라우트 열거 표 주도 테스트(a)–(e) + 동일 출처 UI 쓰기 e2e + 프록시 헤더 구성 단위 테스트 | `go test`, `npm run e2e` | 상태·본문 불변(a,d,e)·403 봉투(b,c) |
| `AC-017` | 단위: DN이 든 LDAP 진단 문자열을 `ldapclient` 래핑 오류 형태(`ErrInvalidInput: …` 등)로 `respondErr`에 주입, `validate` 문구 값 비에코 표 단언. 라이브: 비밀번호 변경 실패 화면 문구 확인(UX 비용 기록) | `go test` + 로컬 Docker 스택 | 응답에 DN 없음, 로그에 원문 |
| `AC-018` | `helm template` 기본/활성/빈 `from` 렌더 단언(스크립트 또는 chart test) | 로컬 | 단언 로그 |
| `AC-014` | 문서 점검, 기본값 `helm template`에 신규 리소스 없음, OpenAPI/`llms.txt`/`docs/api.md` 일관성 | 로컬 | diff·렌더 출력 |
| `AC-015` | 리뷰 체크리스트(후속 패키지 PR이 표를 갱신했는지) | PR 리뷰 | 링크 |

단위/정적 증거와 라이브(LDAP 포함 `test-api-edge-codes-local.py`, Docker 스택) 증거는 분리해 기록한다. LDAP 와이어 경로는 단위 테스트하지 않고 라이브로 검증한다(AGENTS.md).

## Rollout, rollback and recovery

- Rollout sequence: Phase 1(봉투·OpenAPI·`docs/api.md`·UI `error ?? message`·4xx 메시지 정책) → Phase 1b(쓰기 Origin 게이트, 항상 켜짐) → Phase 2(`/metrics`, 기본 꺼짐) → Phase 3(CORS, 기본 꺼짐). 각 단계는 기능 꺼짐 상태에서 기존 테스트가 통과해야 병합한다. `main` CI 녹색 후에만 릴리스.
- Rollback trigger and procedure: 정상 UI 쓰기가 403이 되는 프록시 구성 등 Origin 게이트 회귀가 확인되면 Phase 1b PR을 되돌린다. 클라이언트 파싱 회귀가 확인되면 해당 단계 PR을 되돌린다(additive 변경이라 데이터 복구 불필요). `/metrics`는 `METRICS_ADDR` 비우기, CORS는 `CORS_ALLOWED_ORIGINS` 비우기로 즉시 해제.
- Data/configuration recovery: 영속 데이터·스키마 변경 없음. 신규 env/Helm 값의 기본값은 현행 동작과 동일.
- Compatibility or migration obligations: Origin 게이트(D218-16)는 Origin을 보내는 클라이언트와 프록시 뒤 구성에 영향 가능 — 릴리스 노트에 명시하고 Phase 3보다 먼저 병합. 4xx LDAP 진단 문구 제거(D218-15) 고지. `error`·`message` 유지(D218-4), 문구·상태 코드 불변, `/api/v1` 불변, 코드 표 append-only. `message` 제거는 별도 패키지·최소 한 릴리스 후.

## Evidence and durable synchronization

- Evidence location/format: PR 본문에 실제 실행한 명령·출력, 라이브 스택 결과(이미지 태그, 명령). 실패도 `research/README.md` 규약에 따라 기록(기회적, 차단 게이트 아님).
- Tests or checks that become durable regression controls: 오류 계약 테스트(전 라우트), 코드 골든 목록, OpenAPI 오류 참조 드리프트 검사, 카디널리티·무비밀 테스트, 메트릭 스크랩 테스트, `test-api-edge-codes-local.py` 확장.
- Documentation to update: `docs/api.md`, `ui/backend/internal/httpapi/openapi/llms.txt`·`openapi.json`, `charts/ldapium/README.md`, 이 패키지 상태.
- ADR/evidence/portfolio records to update: ADR 1건(D218-1~14 승격), `docs/IMPLEMENTATION-STATUS.md`, #214–#217 패키지의 상호 참조.

## Open questions and risks

유지보수자 결정이 필요한 열린 질문은 없다. 2026-10-06 지시로 아래와 같이 해소됐다.

- `Q1` — 해소: 오류 봉투(Phase 1)를 `/metrics`·CORS보다 먼저 병합한다(#215/#216/#217의 선행 조건).
- `Q2` — 해소: Origin 게이트(D218-16)를 먼저 병합한 뒤 CORS 허용 목록을 도입한다(Phase 순서: 봉투 → Origin 게이트 → `/metrics` → CORS).

미검증 항목(구현 전 T에서 확인): (a) Recover 패닉 경로와 라우터 404 경로에서 `X-Request-Id`가 설정되는지(AC-001), (b) `client_golang` 전이 모듈 목록·라이선스, (c) `session.Store.Create(dn, nil)`로 인증 테스트 서버를 구성할 수 있는지, (d) 프록시 뒤에서 Echo `c.Scheme()`/Host가 브라우저 Origin과 어떻게 비교되는지(D218-16, T-033), (e) `ChangePasswordPage.tsx:70-73`이 매칭하는 진단 문구가 현재 어떤 경로로 도달하는지와 D218-15 적용 후 화면(T-017), (f) UI NetworkPolicy 신설이 기존 UI 인그레스(8080)를 막지 않는지(D218-10 `httpFrom` 기본 전체 허용, T-025). #230의 `OPTIONS`/`HEAD`는 병합된 사실로 취급했으며 코드·테스트 위치는 Problem 4에 있다.

## Review record

- Accepted scope/requirements: REQ-001–REQ-016, D218-1~16 (유지보수자 지시, 2026-10-06)
- Material changes after acceptance and re-review: 2026-10-06 독립 비평(Codex, main `60dae0d`) 6건 반영 — ① 기존 테스트 갱신을 T-011에 포함 ② 공개 포트 `/metrics` 명시 404(D218-10, AC-007) ③ `Vary: Origin` 전면 적용 + 쓰기 Origin 게이트(D218-12·16, REQ-015, AC-013·016) ④ 4xx 메시지 정책(D218-15, REQ-016, AC-017) ⑤ 차트 NetworkPolicy·별도 Service·`from` 필수(D218-10, AC-018) ⑥ 후속 패키지 코드명 흡수(D218-3: `backup_running`→`backup_busy`, #214 가칭 폐기). #230 병합에 따라 줄 번호 갱신
- Open questions or blockers: 없음(Q1·Q2 해소). Owner 지정, ADR 초안(T-005)
