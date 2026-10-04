# Change: 외부 HTTP API용 머신 주체(서비스) 인증 — 읽기 전용 범위

- Change class: `D` — 인증·인가 경계 추가, 신규 자격 증명 수용 경로
- Owner: 미지정 — 수용 전 지정
- Related issue: 미등록 — 출처 [api-integration PLAN P0](../api-integration/PLAN.md)
- Status: `Proposed / awaiting review`
- Accepted by / date: 미수용 — 이 문서는 제안이며 Class D 수용 전 구현 착수 금지
- 작성일: 2026-10-04

> 이 문서는 설계 제안이다. 코드·ACL·Helm·OpenAPI는 변경하지 않았고, 아래 동작은
> 어느 것도 구현·런타임 검증되지 않았다. Keycloak 동작에 대한 서술은 T-004에서
> 실제 인스턴스로 확인하기 전까지 “검증 필요”로 취급한다.

## Problem

외부 시스템·AI 에이전트는 현재 사람의 로그인 쿠키를 재생하는 방법밖에 없다.
근거: [REVIEW P0](../api-integration/REVIEW.md), [middleware.go](../../../ui/backend/internal/httpapi/middleware.go) `requireSession`.

- LDAP 모드: 에이전트가 `POST /api/login`에 LDAP 비밀번호(대개 관리자급)를 넘겨야 한다.
- SSO 모드: 브라우저 Authorization Code 흐름만 가능하다. `client_credentials`/bearer 수용 경로가
  없어 무인 호출이 불가능하고, 우회하려면 사람 세션 쿠키를 훔쳐 써야 한다([sso.go](../../../ui/backend/internal/httpapi/sso.go)).
- 세션은 프로세스 메모리의 LDAP bind이며(`session.Session.Bound`), 서비스별 권한 분리·회수·감사 주체가 없다.
- 라우트별 scope가 없어 인증된 세션은 문서화된 40개 보호 오퍼레이션 전부(쓰기·비밀번호·백업 포함)에 도달한다.
  (`openapi.json` 기준 전체 48개 중 공개 8개, 세션 보호 40개. 요청서의 “39”와 1개 차이 — Q9.)

## Intent

Keycloak이 발급한 서비스 클라이언트의 access token(Bearer)으로 **읽기 전용 부분집합**만 호출할 수 있게 한다.
토큰 scope는 서버측 오퍼레이션 allowlist로 해석하고, 실행은 전용 최소권한 LDAP bind 신원으로 한다.
브라우저 쿠키 흐름은 계약·검증·CSRF 규칙을 그대로 유지하며, 기능은 기본 꺼짐이다.

## Scope

- In scope: 인바운드 bearer 검증, scope→오퍼레이션 allowlist(읽기 전용), 전용 LDAP bind 신원,
  인증 경로 분리, 감사·rate limit, OpenAPI `securitySchemes`/계약 테스트, 설정·Helm 값, 운영 문서, e2e.
- Affected: `ui/backend/internal/httpapi`(미들웨어·라우팅·OpenAPI), `internal/config`,
  `charts/ldapium`(`ui.machineAuth.*`), `docs/api.md`, `docs/auth-provider-policy.md`, CI e2e 1개.
- 대상: 외부 시스템/AI 에이전트, 운영자, 보안 검토자. 브라우저 사용자 영향 없음(목표).

## Non-goals

- 쓰기 오퍼레이션, 비밀번호 오퍼레이션, 백업, 애플리케이션 프로파일(x-admin), `entry/move` 허용.
- 조직·subtree별 세분 권한(별도 패키지 [oidc-organization-authorization](../oidc-organization-authorization/CHANGE.md)).
  v1의 최종 범위 통제는 LDAP ACL이다(D4).
- API 키/mTLS 구현(옵션 2·3은 평가만; D1), 토큰 introspection·즉시 폐기, 분산 rate limit.
- cursor paging·idempotency·오류 스키마 정비(PLAN의 P1 항목), Keycloak 클라이언트 프로비저닝 자동화.
- 기존 `/api/login`, SSO 로그인, 쿠키 속성, 세션 모델 변경.

## Requirements

- `REQ-001` — Bearer JWT를 서명(JWKS)·`iss`·`aud`·`exp`·`nbf`·토큰 종류·발급 클라이언트(`azp`)로 검증한다. 하나라도 실패하면 401.
- `REQ-002` — 토큰 scope를 서버측 오퍼레이션 allowlist로만 해석한다. allowlist에 없는 오퍼레이션은 기본 거부(403)이며, v1은 GET 읽기만 허용한다.
- `REQ-003` — 쓰기·비밀번호·백업·프로파일 관리·`entry/move`는 어떤 scope 조합으로도 호출 불가임을 명시 denylist와 계약 테스트로 고정한다.
- `REQ-004` — 머신 요청은 전용 최소권한 LDAP bind 신원으로 실행한다. rootdn/관리자 비밀번호·`SESSION_SECRET`을 머신 경로에 쓰지 않고, 관리자 DN 목록과 겹치면 기동 실패한다.
- `REQ-005` — `userPassword`는 머신 응답에도 절대 나가지 않는다(`entryRedactedAttrs` denylist 불변, bind 신원이 root여도 동일).
- `REQ-006` — 쿠키 경로와 bearer 경로는 서로의 자격 증명을 받지 않는다. 혼용 요청은 거부하고, 쿠키 CSRF/same-origin 규칙은 약화되지 않는다.
- `REQ-007` — LDAP 모드와 SSO 모드 모두에서 동작하되 기존 로그인 경로의 동작은 바뀌지 않는다.
- `REQ-008` — JWKS 조회 불가·설정 불일치·LDAP bind 실패 시 fail closed(허용 폴백 없음).
- `REQ-009` — 모든 머신 요청(허용·거부)을 actor=서비스 client id, request id, 오퍼레이션, 결과로 구조화 로그에 남기고 토큰·비밀은 남기지 않는다.
- `REQ-010` — client별 rate limit·동시 실행 상한·실패 인증 throttling을 제공한다.
- `REQ-011` — 토큰 최대 수명과 시계 오차 허용치를 서버가 강제한다.
- `REQ-012` — OpenAPI에 `securitySchemes`와 오퍼레이션별 scope를 반영하고, 드리프트 테스트가 allowlist/denylist 불일치를 잡는다.
- `REQ-013` — 기본 꺼짐. 꺼진 상태에서 기존 경로·응답·OpenAPI의 기존 오퍼레이션 의미가 동일하다. 설정은 env와 Helm 값으로 제공한다.
- `REQ-014` — ldapium은 토큰·client secret을 저장하지 않고, 머신 bind 비밀번호는 기존 Secret 주입 관례로만 받으며 API·로그에 노출하지 않는다.

## Acceptance scenarios

### `AC-001` — 유효한 서비스 토큰으로 허용 오퍼레이션 호출

- Covers: `REQ-001`, `REQ-002`, `REQ-004`, `REQ-009`
- Given 머신 인증 활성, `directory.users.read`가 허용된 서비스 클라이언트의 유효 토큰
- When `GET /api/users`를 `Authorization: Bearer`로 호출
- Then 200, 실행 bind DN은 머신 전용 DN, 로그에 actor=client id·request id가 남는다.

### `AC-002` — 검증 실패 토큰 거부

- Covers: `REQ-001`, `REQ-011`
- Given 잘못된 `aud` / 만료 / 서명 변조 / 알 수 없는 `iss` / ID token / 허용되지 않은 `azp` / `alg=none` / 수명 초과 토큰
- When 허용 오퍼레이션 호출
- Then 각각 401, 응답 본문에 거부 사유 세부 없음(일반 메시지), LDAP bind 시도 없음.

### `AC-003` — scope 부족·미등록 오퍼레이션

- Covers: `REQ-002`
- Given `directory.groups.read`만 가진 토큰
- When `GET /api/users` 또는 allowlist에 없는 임의 `/api` 경로 호출
- Then 403(scope 부족) / 404(미지 경로는 기존 JSON 404 유지), 어떤 경우에도 LDAP 조회 없음.

### `AC-004` — denylist 오퍼레이션은 모든 scope에서 거부

- Covers: `REQ-003`
- Given 설정에 허용된 모든 scope를 가진 토큰
- When 쓰기·비밀번호·백업·프로파일·`entry/move`·`POST/PUT/DELETE` 31개 오퍼레이션 호출
- Then 전부 403이고 핸들러가 실행되지 않는다. OpenAPI에 해당 오퍼레이션의 `machineBearer`가 없다.

### `AC-005` — `userPassword` 비노출

- Covers: `REQ-005`
- Given 의도적으로 과권한(`userPassword` 읽기 가능) bind 신원을 쓰는 테스트 환경
- When `GET /api/entry`, `/api/users`, `/api/tree`를 userPassword 보유 엔트리에 호출
- Then 응답 어디에도 `userPassword`(대소문자·`;binary` 옵션 포함)가 없다.

### `AC-006` — 쿠키/bearer 혼용 거부

- Covers: `REQ-006`
- Given 유효한 세션 쿠키와 유효한 bearer를 동시에 보냄 / 쿠키 경로에 bearer만 / bearer 경로에 쿠키만
- When 보호 오퍼레이션 호출
- Then 동시 전송은 400, bearer만 있는 요청은 세션 미들웨어를 타지 않고, 쿠키만 있는 요청은 기존 동작(머신 경로로 해석 안 됨). 머신 요청은 `Set-Cookie`를 발행하지 않는다.

### `AC-007` — 모드 독립

- Covers: `REQ-007`
- Given `SSO_ENABLED=false`(LDAP 모드)와 `true`(SSO 모드) 각각 + 머신 인증 활성
- When 머신 토큰으로 허용 오퍼레이션 호출 및 기존 로그인 회귀 시나리오 실행
- Then 두 모드 모두 AC-001 통과, `/api/login`·SSO 콜백 동작 불변.

### `AC-008` — JWKS/발급자 장애 시 fail closed

- Covers: `REQ-008`
- Given Keycloak 중지 또는 JWKS 응답 불가
- When 캐시에 없는 `kid`의 토큰 / 캐시된 `kid`의 토큰 호출
- Then 미캐시 `kid`는 503(+`Retry-After`)로 거부, 캐시된 키로 검증 가능한 토큰은 TTL 내 정상 처리, 어떤 경우도 검증 생략 허용 없음.

### `AC-009` — 설정 오류·bind 실패 fail closed

- Covers: `REQ-004`, `REQ-008`
- Given 머신 bind DN이 `BACKUP_ADMIN_DNS`/프로파일 관리자 DN과 중복 / aud 미설정 / bind 비밀번호 불일치
- When 서버 기동 또는 요청
- Then 중복·필수값 누락은 기동 실패, bind 실패는 503이며 root 폴백 없음.

### `AC-010` — 감사 추적

- Covers: `REQ-009`, `REQ-014`
- Given 허용·거부·인증 실패 요청 각 1건
- When 로그 확인
- Then 각 줄에 `event`, `provider`, `actor`(client id), `request_id`, `operation`, `result`, `reason` 코드가 있고 토큰·비밀번호·원문 `Authorization`은 없다. 실패는 fingerprint만.

### `AC-011` — rate limit·동시성

- Covers: `REQ-010`
- Given client별 한도 N rps, 동시 M
- When 한도 초과 호출 / 서로 다른 client 동시 호출
- Then 초과분 429 + `Retry-After`, 다른 client는 영향 없음, 반복 인증 실패 IP는 throttling.

### `AC-012` — 토큰 수명·시계 오차

- Covers: `REQ-011`
- Given `exp-iat`가 상한 초과 / `nbf`가 허용 오차 이내·초과 / 만료 직후(오차 이내·초과)
- When 호출
- Then 상한 초과·오차 초과는 401, 오차 이내는 허용. 시계는 주입 가능한 `now`로 테스트.

### `AC-013` — OpenAPI·드리프트 테스트

- Covers: `REQ-003`, `REQ-012`
- Given 갱신된 `openapi.json`
- When `go test ./internal/httpapi/...`
- Then `machineBearer` 보유 오퍼레이션 집합 == 코드 allowlist, denylist 오퍼레이션은 `machineBearer` 부재, 기존 `TestOpenAPIMatchesRegisteredRoutes`·`HasNoUserPasswordProperty` 통과.

### `AC-014` — 기본 꺼짐·호환

- Covers: `REQ-013`
- Given `MACHINE_AUTH_ENABLED` 미설정(또는 Helm `ui.machineAuth.enabled=false`)
- When bearer 포함 요청, 기존 e2e(ui-e2e·e2e) 실행
- Then bearer는 무시(쿠키 없음 → 기존 401 `not logged in`), 기존 e2e 무변경 통과, 머신 관련 라우트·검증기·JWKS 조회 없음.

## Architecture and decisions

- Relevant ADR/design links: [auth-provider-policy](../../auth-provider-policy.md)(“프로세스당 단일 provider” — 머신 수용 경로는 UI 로그인 provider가 아닌 별도 인바운드 인증으로 명시 예외화 필요, T-031),
  [api.md](../../api.md), [openapi.json](../../../ui/backend/internal/httpapi/openapi/openapi.json),
  [keycloak-federation-e2e.yml](../../../.github/workflows/keycloak-federation-e2e.yml).
- ADR threshold result: `required` — 신규 자격 증명 수용 경로, 신뢰 경계 확대, 정책 문서 예외. 수용 전 ADR 초안 필요(T-005).

### 대안 비교

| 항목 | 옵션 1: Keycloak OIDC access token (Bearer, client_credentials) | 옵션 2: 해시 저장 정적 scoped API 키 | 옵션 3: mTLS 클라이언트 인증서 |
|---|---|---|---|
| 신규 비밀 저장 | 없음(ldapium은 공개키만 검증) | 키 해시 저장소 필요(저장·백업·복제 문제; 세션과 달리 영속) | 신뢰 CA 번들 |
| 폐기·회전 | 짧은 TTL + Keycloak 클라이언트 비활성화/secret 회전. 즉시 폐기는 불가(D7) | 즉시 폐기·회전 용이 | CRL/OCSP 또는 CA 교체, 운영 부담 큼 |
| 기존 코드 재사용 | `go-oidc` 검증기, issuer discovery, 감사 패턴 재사용 | 없음(저장·발급 UI/CLI 신규) | TLS 종단이 ingress면 헤더 신뢰(XFCC) 문제, 앱 직접 종단 시 TLS 구성 신규 |
| 인프라 전제 | Keycloak 필요(SSO 배포는 이미 보유; LDAP 모드는 별도 필요) | 없음(Keycloak 없는 소규모 배포에 유리) | PKI 필요 |
| 감사 주체 | `azp`/`client_id` 일관, IdP 감사와 상호 참조 | key id | 인증서 subject/serial |
| 주요 위험 | 토큰 탈취 후 TTL 동안 유효, aud/azp 오설정(confused deputy) | 저장소 유출·장기 유효 비밀, 발급 UX 자체 구현 | ingress 헤더 위조, 인증서 수명 관리 |
| 권고 | **우선 평가·채택 후보** | Keycloak 없는 배포용 후속 옵션 | 보류(필요성 확인 후) |

### 결정 기록

| ID | 결정 | 이유 | 비용 | 탈출구 |
|---|---|---|---|---|
| D1 | 옵션 1을 v1로 권고. 옵션 2는 Keycloak 없는 배포용 후속, 옵션 3은 보류 | PLAN P0가 “Keycloak issuer/audience 정책 재사용”을 지정, 신규 비밀 저장소 없음, 기존 검증 코드 재사용 | LDAP 모드 배포는 별도 IdP 필요 | 인증기를 `machineAuthenticator` 인터페이스(단일 메서드: 요청→principal)로 두고 옵션 2 추가는 구현체 추가만으로 가능(구현 시 과설계 금지: 첫 구현체는 구체 타입) |
| D2 | 기존 경로(`/api/users` 등)에 인증기 선택 방식으로 얹는다: `Authorization: Bearer` 존재 → 머신 인증기만, 없음 → 기존 쿠키 `requireSession`. 둘 다 존재 → 400. 경로 복제 없음 | 클라이언트·OpenAPI·SDK 변경 최소, 오퍼레이션 단일 정의 | 한 경로가 두 인증을 받아 테스트 매트릭스 증가, 선택 로직 버그가 곧 경계 약화 | 오퍼레이션 복제 `/api/v1/machine/...` 접두사(경로 분리가 더 강한 격리)로 전환 가능. 순수 함수 `selectAuth`로 격리해 단위 테스트(Q3) |
| D3 | scope는 서버 코드의 정적 `operation→scope` allowlist로만 해석(OpenAPI `x-machine-scope`와 1:1). client별 허용 scope 상한을 서버 설정에 두고, 유효 권한 = 토큰 scope ∩ 서버 상한. 미등록 오퍼레이션 기본 거부 | IdP 설정 실수(과다 scope 부여)가 곧바로 권한 확대가 되지 않게 함. “라우트 추가 시 자동 허용” 방지 | client 추가 시 ldapium 설정도 갱신 필요 | 상한을 `*`(토큰 scope 그대로)로 두는 모드는 두지 않음 — 필요 시 별도 결정으로 도입 |
| D4 | 실행 신원은 배포당 하나의 전용 읽기 전용 LDAP 계정(`MACHINE_LDAP_BIND_DN`). 요청마다 bind 후 종료. rootdn·`LDAP_SERVICE_ACCOUNT_DN`(SSO 서비스 계정)·관리자 DN 재사용 금지, 중복 시 기동 실패. 최종 범위·`userPassword` 접근은 LDAP ACL이 백스톱 | 최소권한, 세션 저장소·`SESSION_SECRET` 무관, 연결 상태 없음(재연결 로직 부재 문제 회피) | 요청당 bind 지연, client별 신원 분리 불가(v1) | 연결 풀 도입, client→DN 매핑 설정 확장, subtree allowlist(Q5) |
| D5 | 검증 정책: `iss` 정확 일치, `aud`에 `MACHINE_OIDC_AUDIENCE` 포함, `azp`(또는 `client_id`)가 허용 목록에 있고 **SSO 브라우저 client id가 아님**, 서명 알고리즘 허용 목록(RS256/ES256 등, `none`·HS* 거부), ID token/refresh 거부(토큰 종류 claim 확인), `sub`는 서비스 계정, `preferred_username`으로 사람 매핑 안 함 | audience confusion·ID token 오용·브라우저 토큰의 머신 경로 재사용(confused deputy) 차단 | Keycloak에 audience mapper·전용 client 설정 필요(운영 문서화) | 허용 알고리즘·claim 이름을 설정화(IdP 호환 필요 시) |
| D6 | v1은 GET 읽기 전용. 비-GET은 scope와 무관하게 거부 | 가장 작은 위험 표면, 쓰기는 idempotency·조건부 수정 계약(PLAN P1) 선행 필요 | 쓰기 자동화 불가 | 쓰기는 별도 Change Package(Class D) |
| D7 | 즉시 폐기 없음. 토큰 최대 수명 `MACHINE_TOKEN_MAX_TTL`(기본 10m, `exp-iat` 초과 시 거부), 시계 오차 `MACHINE_CLOCK_SKEW`(기본 30s, 상한 60s). 회수는 Keycloak client 비활성화 + 서버 `MACHINE_ALLOWED_CLIENTS` 제거(재시작/리로드 후) | 요청마다 introspection 호출은 IdP 의존·지연 증가 | 탈취 토큰이 최대 TTL+오차 동안 유효 | introspection 옵션(캐시·fail-closed) 후속 |
| D8 | JWKS 장애 시 fail closed. 캐시된 `kid`는 기존 캐시 정책 내에서 검증, 미캐시 `kid`는 503. 알 수 없는 `kid` 재조회는 최소 간격으로 제한 | 서명 미검증 허용 금지. 임의 `kid` 폭주로 IdP를 때리는 증폭 방지 | IdP 장애 중 키 회전 직후 토큰 거부 | 키 캐시 TTL·최소 간격 설정화 |
| D9 | client별 in-memory token bucket(rps/burst) + client별 동시 실행 상한 + IP별 인증 실패 throttling. 로그인 limiter와 같은 per-process 의미 | 기존 `loginLimiter` 선례와 일관, 의존성 없음 | 다중 replica에서 pod별 한도(전역 아님), 재시작 시 초기화 | 공유 limiter는 ingress/게이트웨이 계층에 위임 |
| D10 | 감사는 구조화 로그 줄(`event=machine_access`) 추가. actor=`azp`, `sub` 원문은 fingerprint, request id는 기존 `RequestID` 미들웨어 값 사용. 허용·거부·인증 실패 모두 기록. 토큰·`Authorization` 헤더 값 미기록 | 기존 `auth` 이벤트 스키마·`docs/audit-event-schema.md`와 같은 계열, 추가 저장소 불필요 | 로그 수집 파이프라인에 의존 | 별도 감사 저장소는 후속 |
| D11 | 머신 인증은 UI 인증 모드와 독립. 발급자는 `MACHINE_OIDC_ISSUER_URL`, 비어 있고 SSO 활성이면 `SSO_ISSUER_URL` 상속, LDAP 모드는 명시 필요 | “이미 설정된 issuer 재사용” 요구를 SSO 배포에서 충족하면서 LDAP 모드도 허용 | LDAP 모드는 issuer 추가 설정 필요 | LDAP 모드 비지원으로 축소 가능(Q4) |
| D12 | 기본 꺼짐(`MACHINE_AUTH_ENABLED=false`). 꺼지면 bearer 경로·JWKS 조회·머신 라우팅 로직 비활성 | 기존 계약·롤백 단순화 | — | 플래그 한 줄로 롤백 |
| D13 | OpenAPI에 `securitySchemes.machineBearer`(http/bearer/JWT) 추가, 허용 오퍼레이션만 `security: [{cookieAuth:[]},{machineBearer:[scope]}]`와 `x-machine-scope`. 전역 `security` 기본값은 `cookieAuth` 유지. 계약 테스트로 allowlist/denylist 양방향 강제 | 문서가 곧 허용 목록이어야 함(드리프트 방지) | 스펙 소비 도구가 다중 scheme을 처리해야 함 | `x-machine-scope`만 두고 `security`는 유지하는 보수안 |

### v1 허용 오퍼레이션 (읽기 전용 기본 scope)

세션 보호 GET 9개 중 6개를 기본 허용, 2개는 opt-in, 1개는 제외한다. 근거 목록은 `openapi.json`의 `operationId`.

| operationId | 경로 | Scope | 기본 | 비고 |
|---|---|---|---|---|
| `listUsers` | `GET /api/users` | `directory.users.read` | 허용 | 5000 상한·`truncated` 유지, 속성은 명시 목록 |
| `listGroups` | `GET /api/groups` | `directory.groups.read` | 허용 | 〃 |
| `listTree` | `GET /api/tree` | `directory.tree.read` | 허용 | 단일 레벨 조회 |
| `getEntry` | `GET /api/entry` | `directory.entry.read` | 허용 | 임의 DN 읽기 — 범위는 LDAP ACL(Q5), `userPassword` denylist 불변 |
| `listPasswordPolicies` | `GET /api/password-policies` | `directory.policies.read` | 허용 | 정책 조회만, 비밀 아님(T-001 확인) |
| `getMonitor` | `GET /api/monitor` | `server.monitor.read` | 허용 | 노출 필드 T-001에서 확인 |
| `listAuditActions` | `GET /api/audit/actions` | `audit.read` | opt-in | 행위자·대상 DN 노출(민감) |
| `getServerSettings` | `GET /api/server-settings` | `server.settings.read` | opt-in | 설정 노출 범위 T-001에서 확인 |
| `getMe` | `GET /api/me` | — | 제외 | 응답이 세션 DN(`meResponse{DN}`) 의미 — 머신용 whoami는 Q6 |

공개 8개(`getMeta`, `getOpenAPI`, `getAuthConfig`, `getLdapHealth`, `login`, `logout`, `ssoStart`, `ssoCallback`)는 인증 대상이 아니며 변경 없음.

### 명시 denylist (머신 경로에서 항상 거부, 31개)

| 구분 | operationId |
|---|---|
| 사용자 쓰기·비밀번호 (6) | `createUser`, `updateUser`, `deleteUser`, `setPassword`, `unlockUser`, `lockUser` |
| 그룹 쓰기 (5) | `createGroup`, `updateGroup`, `deleteGroup`, `addGroupMember`, `removeGroupMember` |
| 엔트리 이동 (1) | `moveEntry` |
| 애플리케이션 프로파일 x-admin (14) | `getProfileCapabilities`, `listApplications`, `listIntegrationMethods`, `putIntegrationMethod`, `getApplicationProfile`, `putApplicationProfile`, `deleteApplicationProfile`, `getKeycloakRoles`, `getApplicationRoles`, `getIntegrationStatus`, `verifyIntegration`, `applyKeycloakRoleOperation`, `exportApplicationConfiguration`, `previewMapping` |
| 백업 x-admin (5) | `getBackups`, `putBackupPolicies`, `putBackupConnection`, `deleteBackupConnection`, `runBackup` |

프로파일 GET(`listApplications` 등)은 읽기이지만 관리자 DN 경계와 export/검증 부작용(외부 호출)이 있어 v1에서 제외한다. 기본 거부이므로 목록은 계약 테스트의 기대값이다.

### 인증 경로 분리 규칙 (D2 상세)

1. 선택은 순수 함수 하나가 한다: `Authorization` 헤더 유무와 `ldapium_session` 쿠키 유무 → `{cookie, bearer, reject(400), none}`.
2. bearer 경로는 `requireSession`을 거치지 않고, `session.Store`에 항목을 만들지 않으며 `Set-Cookie`를 내지 않는다.
   핸들러 재사용을 위해 요청 수명 한정의 임시 `Session{DN: 머신 bind DN, Bound: 요청별 bind}`를 컨텍스트에 두고 응답 후 닫는다.
3. bearer 경로는 GET만, allowlist 안에서만 통과한다. CORS 허용 헤더를 추가하지 않는다(브라우저 교차 출처 호출 불가 유지).
4. 쿠키 경로는 bearer를 해석하지 않는다. 머신 비활성 시 bearer는 아무 의미가 없다(AC-014).
5. 머신 bind DN이 `BACKUP_ADMIN_DNS`·프로파일 관리자 DN에 들어가면 기동 실패 — 핸들러의 `sess.DN` 기반 관리자 판정에 머신이 걸리지 않게 한다.

### 모드별 동작

| 항목 | LDAP 모드 | SSO 모드 |
|---|---|---|
| 사람 로그인 | `POST /api/login`(불변) | SSO 콜백(불변) |
| 머신 issuer | `MACHINE_OIDC_ISSUER_URL` 필수 | 미지정 시 `SSO_ISSUER_URL` 상속 |
| 머신 audience | `MACHINE_OIDC_AUDIENCE` 필수 | 〃(SSO client id를 audience로 재사용하지 않음) |
| 실행 신원 | 머신 전용 bind DN | 머신 전용 bind DN (`LDAP_SERVICE_ACCOUNT_DN`과 별개) |
| 사람 세션과 관계 | 없음 | 없음 — 사람 SSO access token은 `azp` 검사로 거부 |

### 설정·Helm (제안 이름, 확정 아님)

| env | 기본 | 설명 |
|---|---|---|
| `MACHINE_AUTH_ENABLED` | `false` | 기능 스위치 |
| `MACHINE_OIDC_ISSUER_URL` | `SSO_ISSUER_URL` 상속 | `validateIssuerURL` 규칙 재사용 |
| `MACHINE_OIDC_AUDIENCE` | 없음(활성 시 필수) | 토큰 `aud` |
| `MACHINE_ALLOWED_CLIENTS` | 없음(활성 시 필수) | `clientId=scope,scope;…` — D3 상한 |
| `MACHINE_TOKEN_MAX_TTL` / `MACHINE_CLOCK_SKEW` | `10m` / `30s` | D7 |
| `MACHINE_LDAP_BIND_DN` / `MACHINE_LDAP_BIND_PASSWORD` | 없음(활성 시 필수) | 비밀번호는 기존 Secret 주입 관례(`secret-admin.yaml`, `SSO_CLIENT_SECRET`)를 따르며 차트가 생성·출력하지 않음 |
| `MACHINE_RATE_LIMIT_RPS` / `_BURST` / `MACHINE_MAX_CONCURRENCY` | `5` / `10` / `4` | D9 |

Helm: `ui.machineAuth.{enabled,issuerURL,audience,allowedClients,tokenMaxTTL,clockSkew,ldapBindDN,existingSecret…,rateLimit…}`.
`enabled=false` 기본, 값 검증은 `values.schema`/템플릿 `required`로 활성 시 필수 항목 강제(기존 `ui.sso` 패턴 확인 후, T-016).

### 위협 모델

| 위협 | 시나리오 | 통제 | 잔여 위험 |
|---|---|---|---|
| 토큰 탈취 | 로그·프록시·에이전트 메모리에서 bearer 유출 | 짧은 TTL(D7), 읽기 전용(D6), 요청 rate limit(D9), 감사(D10), TLS 전제, 토큰 미로그 | TTL 동안 읽기 노출. 즉시 폐기 불가(introspection 후속) |
| scope 상승 | IdP에서 과다 scope 부여, 토큰 클레임 위조 | 서명 검증(D5), 서버 상한 교집합(D3), denylist·비-GET 거부(D6) | 상한 자체가 과다하면 허용 범위 내 노출(Q5) |
| confused deputy | 사람 SSO access token·타 서비스 토큰·ID token을 머신 경로에 제시 | `aud` 일치·`azp` 허용 목록·SSO client 제외·토큰 종류 확인(D5) | IdP audience mapper 오설정 시 약화 — e2e 음성 테스트로 방어 |
| 재생(replay) | 유효 토큰 재전송 | 읽기 전용이라 상태 변경 없음, 짧은 TTL, 감사. `jti` 추적은 안 함 | TTL 내 재생 가능(읽기 한정) |
| 쿠키 경계 약화 | CSRF로 bearer 경로 악용/쿠키 경로에 bearer 우회 | 헤더 자격 증명은 브라우저 자동 첨부 아님, 혼용 400, bearer 요청은 쿠키 미발행, CORS 미확장(D2) | 선택 함수 버그 — 단위·e2e 혼용 테스트 |
| 권한 있는 bind 오용 | 머신 경로가 관리자 bind를 쓰게 되는 설정 실수 | 전용 DN·중복 시 기동 실패(D4), LDAP ACL 백스톱, `userPassword` denylist | ACL 오구성은 ldapium이 완전 검증 불가 — 운영 문서·e2e 점검 |
| 발급자 장애·위조 | JWKS 응답 변조/불가 | HTTPS issuer 검증(기존 `validateIssuerURL`), fail closed(D8) | issuer TLS 신뢰는 기존 SSO와 동일 수준 |
| 대량 열람 | 정상 scope로 users/entry 전수 조회 | rate limit·동시성·5000 상한·감사 | 범위 제한은 LDAP ACL/후속 subtree 패키지 |

## Change impact

| Area | Impact / evidence needed |
|---|---|
| Source / API / command | `httpapi` 미들웨어(인증 선택·머신 인증기), 라우팅 가드, 임시 세션 주입, `config` 신규 env. 기존 핸들러 본문 불변 목표. 근거: 계약·단위 테스트 |
| Dependencies / lockfiles | 신규 의존성 없음 목표(`go-oidc`·`oauth2` 재사용). 추가 시 Class C 절차와 `THIRD-PARTY-LICENSES.md` 재생성 |
| Runtime / toolchain | N/A — 런타임·툴체인 변경 없음 |
| CI / CD | 신규 e2e 워크플로(Keycloak 고정 태그, T-022). release 필수 체크로 삼는다면 path 필터 금지(이전 릴리스 교훈) — Q8 |
| Release / packaging | 기본 꺼짐이라 기본 동작 불변. 차트 값 추가, 릴리스 노트에 신규 옵션 |
| Generated output | `openapi.json`, `llms.txt`(생성 방식 T-001 확인) |
| Security / supply chain | 신규 신뢰 경계 — 위협 모델 표, security-reviewer 검토, `security-e2e` 연계 검토 |
| Offline / air-gap | issuer·JWKS 접근 필요(기능 활성 시). 비활성 시 영향 없음. [air-gap](../../air-gap.md) 문서에 명시 |
| Documentation / operations | `docs/api.md`, `docs/auth-provider-policy.md`(예외 명시), `ui/README.md`, `charts/ldapium/README.md`, Keycloak client·audience mapper 설정 가이드, 머신 LDAP 계정 ACL 예시 |
| Portfolio / downstream repositories | 상태 기록·OpenForge 공개 상태 반영 여부 확인(T-033). 다운스트림 SDK 없음(T-001 확인) |

## Verification plan

| Acceptance ID | Verification method | Environment | Expected evidence |
|---|---|---|---|
| `AC-001` | 라이브 e2e: client_credentials 토큰으로 `GET /api/users` | Keycloak(고정 태그)+ldapium 컨테이너, `keycloak-federation-e2e.yml` 패턴 | 워크플로 로그: 200, 로그의 actor/bind DN |
| `AC-002` | 단위(순수 claim 검증기 + 로컬 JWKS `httptest` 서버, 생성 RSA 키로 서명/변조) + e2e 음성(wrong aud, 만료, 변조, ID token, SSO client 토큰) | go test; e2e | 케이스별 401 표, LDAP 미접속 확인 |
| `AC-003` | 단위(scope→오퍼레이션 해석 순수 함수) + e2e | go test; e2e | 403/404 표 |
| `AC-004` | 단위(denylist 31개 전수 테이블 테스트) + 계약 테스트 + e2e 샘플 | go test; e2e | 31/31 거부 |
| `AC-005` | e2e: 과권한 bind + `userPassword` 보유 엔트리; 단위: 기존 redaction 테스트 회귀 | e2e; go test | 응답에서 `userPassword` 부재 |
| `AC-006` | 단위(`selectAuth` 표 테스트) + e2e 혼용 요청 | go test; e2e | 400/401/기존 동작 표, `Set-Cookie` 부재 |
| `AC-007` | e2e 2회(LDAP 모드/SSO 모드) + 기존 로그인 회귀 | docker compose 2구성 | 두 모드 통과 로그 |
| `AC-008` | e2e: Keycloak 중지 후 호출(캐시 hit/miss) | e2e | 503/200 표 |
| `AC-009` | 단위(config 검증: 중복 DN·필수값 누락) + e2e(bind 실패) | go test; e2e | 기동 오류 메시지, 503 |
| `AC-010` | 단위(`buildMachineEvent` 순수 함수: 필드·비밀 비포함) + e2e 로그 grep(토큰 부재) | go test; e2e | 로그 샘플, 토큰 문자열 검색 0건 |
| `AC-011` | 단위(token bucket, 주입 가능한 `now`) + e2e 부하 소량 | go test; e2e | 429+`Retry-After`, client 격리 |
| `AC-012` | 단위(주입 `now`로 exp/nbf/skew/max TTL 경계) | go test | 경계 표 |
| `AC-013` | 계약 테스트 확장 | go test | 스펙↔allowlist 일치 |
| `AC-014` | 기존 CI 전체 + bearer 무시 단위 테스트 | CI | 기존 e2e 무변경 통과 |

단위/정적(순수 함수·계약)과 라이브 e2e를 구분한다. LDAP wire 코드는 저장소 원칙대로 단위 테스트하지 않고 e2e로만 검증하며 모킹 프레임워크를 도입하지 않는다.
JWKS 검증은 외부 모킹 없이 로컬 `httptest` 서버가 실제 JWKS를 서빙하는 방식으로 단위 검증한다.

## Rollout, rollback and recovery

- Rollout sequence: (1) 수용·ADR → (2) 설정·순수 헬퍼·계약 테스트(기능 꺼짐) → (3) 인증기·라우팅 가드 → (4) e2e → (5) 문서·차트 → (6) 스테이징에서 전용 client·ACL로 활성화 → (7) 릴리스 노트. 모든 단계에서 기본 꺼짐.
- Rollback trigger and procedure: 예기치 않은 401/403 오분류, 권한 노출 의심, JWKS 장애 파급 시 `MACHINE_AUTH_ENABLED=false`(Helm `ui.machineAuth.enabled=false`) 후 재배포. 코드 롤백 없이 기능 정지.
- Data/configuration recovery: 영속 데이터 없음(토큰·키 미저장). 머신 LDAP 계정은 운영자가 삭제/비활성화. Keycloak client 비활성화가 1차 차단.
- Compatibility or migration obligations: 기존 경로·쿠키·응답 불변. OpenAPI는 additive(`securitySchemes`, `x-machine-scope`)이며 기존 오퍼레이션의 `cookieAuth`는 유지.

## Evidence and durable synchronization

- Evidence location/format: 구현 시 `research/README.md` 규약에 따른 기록(테스트·e2e 결과, 실패 포함). e2e 로그는 CI 아티팩트.
- Tests or checks that become durable regression controls: 허용/거부 전수 계약 테스트, `selectAuth`·claim 검증기·scope 해석 단위 테스트, 신규 e2e 워크플로, 기동 시 설정 검증.
- Documentation to update: `docs/api.md`(인증 절·머신 호출 예), `docs/auth-provider-policy.md`, `docs/audit-event-schema.md`(`machine_access`), `ui/README.md`, `charts/ldapium/README.md`, `docs/air-gap.md`, 이 패키지.
- ADR/evidence/portfolio records to update: ADR 신규, [IMPLEMENTATION-STATUS](../../IMPLEMENTATION-STATUS.md), 포트폴리오 상태(해당 시).

## Traceability matrix

| Requirement | Acceptance | Task | Evidence |
|---|---|---|---|
| `REQ-001` | AC-001, AC-002 | T-010, T-011, T-020, T-022 | 검증기 단위·e2e 음성 표 |
| `REQ-002` | AC-001, AC-003 | T-012, T-020, T-021 | scope 해석 테스트, 403/404 표 |
| `REQ-003` | AC-004, AC-013 | T-012, T-014, T-020 | denylist 31/31, 계약 테스트 |
| `REQ-004` | AC-001, AC-009 | T-013, T-015, T-021 | 기동 검증 테스트, bind DN 로그 |
| `REQ-005` | AC-005 | T-021 | 과권한 bind e2e |
| `REQ-006` | AC-006 | T-012, T-020, T-021 | `selectAuth` 표, 혼용 e2e |
| `REQ-007` | AC-007 | T-021 | 2모드 e2e |
| `REQ-008` | AC-008, AC-009 | T-011, T-013, T-021 | 503 표, 기동 실패 |
| `REQ-009` | AC-001, AC-010 | T-017, T-020, T-021 | 이벤트 단위·로그 grep |
| `REQ-010` | AC-011 | T-018, T-020, T-021 | limiter 단위, 429 e2e |
| `REQ-011` | AC-002, AC-012 | T-011, T-020 | 경계 표 |
| `REQ-012` | AC-013 | T-014, T-020 | 계약 테스트 |
| `REQ-013` | AC-014 | T-015, T-016, T-021 | 기존 CI 통과, 차트 렌더 |
| `REQ-014` | AC-010 | T-017, T-021 | 로그·응답 grep |

## Review record

- Accepted scope/requirements: 없음 — 수용 대기.
- Material changes after acceptance and re-review: 해당 없음.
- Open questions or blockers: Q1–Q10은 2026-10-04 유지보수자 지시("열린 질문 권장으로 처리")로 권고안 채택. 아래 결정 표 참조. 패키지 자체의 수용(Accepted)은 별도 검토가 필요하며 구현은 그 이후에 시작한다.

### Resolved questions (2026-10-04, 유지보수자 지시: 권고안 채택)

수용 전 검토에서 뒤집을 수 있다. 각 항목의 "뒤집을 때" 비용은 권고 당시 "결정 지연 시 영향"과 같다.

| ID | 결정 | 반영 위치 |
|---|---|---|
| Q1 | 옵션 1(Keycloak bearer)만 v1. 옵션 2(해시 API 키)는 수요가 확인되면 별도 패키지 | D1 |
| Q2 | 머신 전용 LDAP 계정은 운영자 수동 생성 + 문서에 LDIF 예시. image 시드·차트 옵션 제외. ACL 변경은 Class D이며 `ldapium-directory-change` 스킬 대상 | T-015 |
| Q3 | 기존 경로 공용(D2) + 순수 함수 `selectAuth`. 격리 우려가 커지면 `/api/v1/machine/...` 복제로 전환 | D2 |
| Q4 | LDAP 모드도 지원. 별도 `MACHINE_OIDC_ISSUER_URL` 필요, e2e에 LDAP 모드 구성 포함 | D11 |
| Q5 | subtree/base DN allowlist는 v1 제외. LDAP ACL을 백스톱으로 두고 후속 패키지에서 다룬다 | Non-goals, 위협 모델 |
| Q6 | 머신용 whoami는 v1 제외, `getMe`는 세션 의미 유지 | 허용 오퍼레이션 표 |
| Q7 | opt-in scope(`audit.read`, `server.settings.read`)는 포함하되 기본 비허용(서버 상한에서 명시적으로 켠 경우만) | D3 |
| Q8 | 신규 e2e를 release 필수 체크로 지정. path 필터 금지(이전 릴리스 교훈), 3레인 약 20분 증가 수용 | Change impact |
| Q9 | 현재 `openapi.json` 집계(48개 오퍼레이션, 공개 8·보호 40)를 기준으로 사용. "39"는 경로 수였다 | Problem |
| Q10 | 토큰 TTL 10분 수용. 즉시 폐기용 introspection은 후속 | AC-012 |

잔여 차단 사항: 위 결정으로 설계 질문은 닫혔지만, 이 패키지는 여전히 `Proposed / awaiting review`다.
