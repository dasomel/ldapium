# Change: 외부 HTTP API용 머신 주체(서비스) 인증 — 읽기 전용 범위

- Change class: `D` — 인증·인가 경계 추가, 신규 자격 증명 수용 경로
- Owner: 미지정 — 수용 전 지정
- Related issue: 미등록 — 출처 [api-integration PLAN P0](../api-integration/PLAN.md)
- Status: `Proposed / awaiting review`
- Revision 2 (2026-10-07): addresses T-005 security review; re-review pending; acceptance by the maintainer instruction of 2026-10-07 follows a passing re-review
- Accepted by / date: 미수용 — 이 문서는 제안이며 Class D 수용 전 구현 착수 금지
- 작성일: 2026-10-04 (Revision 2: 2026-10-07)

> 이 문서는 설계 제안이다. 코드·ACL·Helm·OpenAPI는 변경하지 않았고, 아래 동작은
> 어느 것도 구현·런타임 검증되지 않았다. Keycloak 토큰·JWKS 거동과 오퍼레이션 집계는
> 2026-10-07에 실제 Keycloak 26.7.4 실행과 코드 읽기로 확인해 [EVIDENCE.md](EVIDENCE.md)에
> 기록했다(T-001, T-004 완료). 이 문서의 규칙은 그 관측에 근거하며, 구현 검증은 별개다.
> Revision 2의 변경 요약은 끝의 “Revision 2” 절.

## Problem

외부 시스템·AI 에이전트는 현재 사람의 로그인 쿠키를 재생하는 방법밖에 없다.
근거: [REVIEW P0](../api-integration/REVIEW.md), [middleware.go](../../../ui/backend/internal/httpapi/middleware.go) `requireSession`.

- LDAP 모드: 에이전트가 `POST /api/login`에 LDAP 비밀번호(대개 관리자급)를 넘겨야 한다.
- SSO 모드: 브라우저 Authorization Code 흐름만 가능하다. `client_credentials`/bearer 수용 경로가
  없어 무인 호출이 불가능하고, 우회하려면 사람 세션 쿠키를 훔쳐 써야 한다([sso.go](../../../ui/backend/internal/httpapi/sso.go)).
- 세션은 프로세스 메모리의 LDAP bind이며(`session.Session.Bound`), 서비스별 권한 분리·회수·감사 주체가 없다.
- 라우트별 scope가 없어 인증된 세션은 문서화된 45개 보호 오퍼레이션 전부(쓰기·비밀번호·백업 포함)에 도달한다.
  (`openapi.json` 기준 전체 53개 중 공개 8개, 세션 보호 45개 — `jq` 재집계, [EVIDENCE §1](EVIDENCE.md). 초안의 48/40은 PATCH 2·백업 job 3개를 빠뜨렸다. Q9의 “현재 openapi 집계 사용” 결정은 유지하고 수치만 갱신.)

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

- `REQ-001` — Bearer JWT를 “토큰 검증 정책”(D5) 표의 규칙대로 검증한다: 서명(알고리즘 allowlist)·JOSE/payload `typ`·`iss`·`aud` 멤버십·`azp`==`client_id`·서비스 계정 판별·`iat`/`exp`/`nbf`·수명 상한. 하나라도 실패하면 401.
- `REQ-002` — 토큰 scope를 서버측 오퍼레이션 allowlist로만 해석한다. allowlist에 없는 오퍼레이션은 기본 거부(403 `scope_denied`)이며 bind·핸들러 실행 전에 거부한다. v1은 GET 읽기만 허용한다.
- `REQ-003` — 쓰기·비밀번호·백업·프로파일 관리·`entry/move`·`getMe`는 어떤 scope 조합으로도 호출 불가임을 명시 denylist(36개 + `getMe`)와 계약 테스트로 고정한다.
- `REQ-004` — 머신 요청은 전용 최소권한 LDAP bind 신원으로 실행한다. rootdn/관리자 비밀번호를 머신 경로의 자격 증명으로 쓰지 않고, 관리자·rootdn DN(ParseDN 동등 비교)과 겹치면 기동 실패한다. 읽기 전용은 ACL로 강제하고 실제 쓰기 시도로 증명한다.
- `REQ-005` — 머신 응답에 비밀 **값**이 나가지 않는다: `userPassword`(`entryRedactedAttrs` 불변, bind 신원이 root여도 동일)와 accesslog `reqMod` 등 다른 경로로 담긴 비밀 값 모두.
- `REQ-006` — 쿠키 경로와 bearer 경로는 서로의 자격 증명을 받지 않는다. 혼용 요청은 거부하고, 쿠키 CSRF/same-origin 규칙은 약화되지 않는다.
- `REQ-007` — LDAP 모드와 SSO 모드 모두에서 동작하되 기존 로그인 경로의 동작은 바뀌지 않는다.
- `REQ-008` — JWKS 조회 불가·설정 불일치·LDAP bind 실패 시 fail closed(허용 폴백 없음).
- `REQ-009` — `Authorization`을 실은 모든 요청(허용·거부·조기 반환 포함)을 구조화 로그 한 줄로 남긴다. actor는 **검증을 통과한 client id**만이고 미검증 claim은 actor로 쓰지 않는다. 토큰·비밀·원문 verifier 오류는 남기지 않는다.
- `REQ-010` — 비용이 큰 서명/JWKS 작업 **이전**의 IP 실패 throttle, 검증된 client별 rate limit·동시 실행 상한, 전역 인증·LDAP 동시성 상한을 제공하고 모든 상태 크기에 상한을 둔다.
- `REQ-011` — 토큰 최대 수명과 시계 오차 허용치를 서버가 강제한다. go-oidc의 하드코딩 5분 nbf leeway는 쓰지 않는다.
- `REQ-012` — OpenAPI에 `securitySchemes`와 오퍼레이션별 scope를 반영하고, 드리프트 테스트가 allowlist/denylist 불일치를 잡는다.
- `REQ-013` — 기본 꺼짐. 꺼진 상태에서 기존 경로·응답·OpenAPI의 기존 오퍼레이션 의미가 동일하다. 설정은 env와 Helm 값으로 제공한다.
- `REQ-014` — ldapium은 토큰·client secret을 저장하지 않고, 머신 bind 비밀번호는 기존 Secret 주입 관례로만 받으며 API·로그에 노출하지 않는다.
- `REQ-015` — 머신 주체는 `cn=accesslog`·`cn=config`·`cn=Monitor` 데이터를 명시 opt-in scope(`audit.read`, `server.monitor.read`) 경로 밖에서 받지 못한다. `getEntry`/`listTree`는 `BASE_DN` 밖 DN을, `getMonitor`는 `audit.read` 없이 최근 감사 로그를 반환하지 않으며 코드 가드와 LDAP ACL 둘 다로 막는다(D14).
- `REQ-016` — 머신 issuer/JWKS 전송은 운영에서 HTTPS만 허용하고(명시 로컬 테스트 예외), JWKS 재조회는 최소 간격·제한된 negative cache·timeout·크기 제한으로 증폭을 막는다. 조회 장애는 503, 정상 조회 후 미지 kid는 401(D8, D15).
- `REQ-017` — 머신 주체의 list cursor는 issuer+client에 안정적으로 묶인다: client 간 재생 거부, 토큰 갱신 후 연속 조회 가능, 사람 cursor와 도메인 분리(D16).
- `REQ-018` — 긴급 차단 경로는 서버 allowlist 제거/기능 끄기 + **모든 replica 교체** + 진행 중 요청 종료 확인이다. Keycloak client 비활성화만으로는 이미 발급된 JWT가 차단되지 않음을 명시한다(D7).

## Acceptance scenarios

### `AC-001` — 유효한 서비스 토큰으로 허용 오퍼레이션 호출

- Covers: `REQ-001`, `REQ-002`, `REQ-004`, `REQ-009`
- Given 머신 인증 활성, `directory.users.read`가 허용된 서비스 클라이언트의 유효 토큰
- When `GET /api/users`를 `Authorization: Bearer`로 호출
- Then 200, 실행 bind DN은 머신 전용 DN, 로그에 actor=client id·request id가 남는다.

### `AC-002` — 검증 실패 토큰 거부

- Covers: `REQ-001`, `REQ-011`
- Given 아래 음성 토큰 각각(전부 서명 유효한 실제 키로 만든 토큰이되 한 항목만 위반 — 서명 변조·`alg=none`·HS256 공개키 혼동 제외):
  `aud`에 `account`만 / `aud` 누락·null·숫자 배열 / 만료(skew 초과) / 서명 변조 / 알 수 없는 `iss`(후행 슬래시 차이 포함) / ID token(payload `typ=ID`, SA가 `scope=openid`로 받은 것) / refresh token / JOSE `typ` 누락·`JWT`·`at+jwt` 외 / payload `typ`≠`Bearer` / `kid` 누락 / 허용 목록 밖 `azp` / `azp`≠`client_id` / `client_id` 누락 / SSO 브라우저 client(`ldapium-sso`)의 access·ID token / **허용 client에서 password grant로 발급된 사람 토큰**(`sid` 있음, `client_id` 없음, `preferred_username`≠`service-account-<client>`) / `iat` 누락·비숫자·미래(skew 초과) / `exp<=iat` / `exp-iat` > MAX_TTL / `nbf` 미래(skew 초과) / `alg=none` / HS256(JWKS 공개키를 HMAC 키로 서명) / 허용 목록 밖 alg(예 RS512) / 8 KiB 초과 토큰
- When 허용 오퍼레이션 호출
- Then 각각 401(`token_invalid`, 순수 만료만 `token_expired`), 응답 본문에 거부 사유 세부 없음(일반 메시지), LDAP bind 시도 없음(bind 카운터 0). 대응 완화: 동일 토큰 구성에서 위반만 고친 양성 대조 토큰은 200.

### `AC-003` — scope 부족·미등록 오퍼레이션

- Covers: `REQ-002`
- Given `directory.groups.read`만 가진 토큰
- When `GET /api/users` 또는 allowlist에 없는 임의 `/api` 경로 호출, 그리고 **allowlist 항목 없이 새로 등록된 보호 GET**(테스트 서버에 합성 등록)
- Then 403 `scope_denied`(scope 부족·미등록 오퍼레이션) / 404(미지 경로는 기존 JSON 404 유지). 어떤 경우에도 bind·핸들러 실행·LDAP 조회 없음(카운터 0).
- 전수: 등록된 모든 보호 오퍼레이션 45개를 모든 scope를 가진 머신 토큰으로 호출 → 허용 후보 8개만 핸들러(스텁) 도달, 나머지 37개는 403·bind 0.

### `AC-004` — denylist 오퍼레이션은 모든 scope에서 거부

- Covers: `REQ-003`
- Given 설정에 허용된 모든 scope를 가진 토큰
- When 쓰기·비밀번호·백업·프로파일·`entry/move`·`PATCH`·`getMe` 등 거부 37개(denylist 36 + `getMe`) 호출
- Then 전부 403 `scope_denied`이고 핸들러가 실행되지 않는다. OpenAPI에 해당 오퍼레이션의 `machineBearer`가 없다.

### `AC-005` — 비밀 값 비노출

- Covers: `REQ-005`, `REQ-015`
- Given **non-admin이지만 의도적으로 과권한**(모든 `userPassword`와 `cn=accesslog` 읽기 가능)인 머신 bind 신원, 알려진 값으로 설정한 사용자 비밀번호와 그 변경이 남긴 accesslog `reqMod` 항목(해시·평문 값 보유)
- When `GET /api/entry`(사용자 DN, **accesslog DN**, `cn=config`, `cn=Monitor`), `/api/users`, `/api/groups`(+cursor 2페이지), `/api/tree`, `/api/monitor`(+`audit.read` 있음/없음), `/api/audit/actions`를 호출
- Then 모든 응답 본문에서 시드한 비밀 **값**(평문·`{SSHA}…` 해시·base64 변형)이 없다. accesslog·config·monitor DN의 `getEntry`는 403이고, `audit.read` 없는 `getMonitor`는 `recentLogs`가 비어 있으며 accesslog 검색이 발행되지 않는다. 감사 DTO가 변경 속성 **이름** `userPassword`를 포함하는 것은 허용(전역 문자열 부재를 요구하지 않는다).

### `AC-006` — 쿠키/bearer 혼용·`selectAuth` 문법

- Covers: `REQ-006`
- Given “인증 경로 분리 규칙”의 문법 표 각 행(유효 bearer / 헤더 중복 / comma 결합 / 빈 값 / 다른 scheme / scheme 대소문자 / 공백 변형 / 유효 쿠키+bearer / 빈·무효·중복 세션 쿠키+bearer / 공개 auth 경로+bearer / foreign·null·중복 `Origin`+bearer / CORS preflight `authorization`)
- When 보호 오퍼레이션(및 표가 지정한 공개 경로) 호출
- Then 표의 상태 코드와 일치한다. 잘못된 `Authorization`은 어떤 경우에도 쿠키 인증으로 폴백하지 않고, 머신 요청은 `Set-Cookie`를 발행하지 않으며, bearer 헤더가 있어도 Origin gate가 먼저 판정한다.

### `AC-007` — 모드 독립

- Covers: `REQ-007`
- Given `SSO_ENABLED=false`(LDAP 모드)와 `true`(SSO 모드) 각각 + 머신 인증 활성
- When 머신 토큰으로 허용 오퍼레이션 호출 및 기존 로그인 회귀 시나리오 실행
- Then 두 모드 모두 AC-001 통과, `/api/login`·SSO 콜백 동작 불변.

### `AC-008` — JWKS/발급자 장애 시 fail closed

- Covers: `REQ-008`, `REQ-016`
- Given Keycloak 중지 또는 JWKS 응답 불가, 주입 가능한 시계. 기본값: JWKS 캐시 TTL 10m, stale-if-error +1h, 최소 재조회 간격 30s, fetch timeout 5s, 실패 backoff 30s→최대 5m
- When 아래 표의 조건으로 호출

  | 조건 | 결과 |
  |---|---|
  | 캐시된 kid, 마지막 성공 조회 후 TTL(10m) 이내 | 200 |
  | 캐시된 kid, TTL 초과·TTL+1h 이내, IdP 계속 장애 | 200(stale-if-error), 재조회는 backoff 간격당 1회 |
  | TTL+1h 초과, IdP 장애 | 모든 토큰 503(캐시된 kid 포함) |
  | 미캐시 kid, IdP 장애(또는 한 번도 성공 못 함) | 503 + `Retry-After`(남은 backoff 초, 1–300) — 401 아님 |
  | 미캐시 kid, 정상 조회 직후 | 401 `token_invalid` |
  | 캐시된 kid + 잘못된 서명 | 401, upstream 조회 0회 |

- Then 위 표와 일치하고, 어떤 경우도 검증 생략 허용이 없다. `Retry-After`는 정수 초.

### `AC-016` — JWKS 폭주·전송 제한

- Covers: `REQ-016`
- Given 로컬 `httptest` JWKS 서버(조회 횟수 계수)와 live Keycloak 앞의 계수 프록시
- When (a) 무작위 kid 토큰 1000건, (b) 알려진 kid + 잘못된 서명 1000건을 동시에 보냄 (c) 키 회전 (d) 응답 크기 1 MiB 초과·키 21개 이상·리다이렉트·5초 초과 지연 (e) `http://` 원격 issuer 설정
- Then (a)(b) upstream 조회 횟수 ≤ 1 + ⌈관측 구간/30s⌉(fake clock 단위 테스트에서 정확히 검증, e2e에서는 상한 확인), 오류는 401이고 negative cache(≤256 kid, TTL 5m)가 상한을 넘지 않는다. (c) 새 kid 토큰은 다음 허용 조회 이후 200이며 그 전 최대 30s는 401(문서화된 비용). (d) 조회 거부·기존 캐시 유지·503. (e) 기동 실패(로컬 테스트 예외 플래그 없이), 플래그가 있으면 기동 시 WARN 로그.

### `AC-009` — 설정 오류·bind 실패 fail closed

- Covers: `REQ-004`, `REQ-008`
- Given 머신 bind DN이 `BACKUP_ADMIN_DNS`/프로파일 관리자 DN/`LDAP_SERVICE_ACCOUNT_DN`/rootdn(`MACHINE_LDAP_ROOT_DNS`)과 ParseDN 동등(대소문자·공백·escape·hex 이스케이프·다중값 RDN 순서 변형 포함) / aud 미설정 / `UI_TRUSTED_PROXIES`가 기본 `private` / bind 비밀번호 불일치 / LDAP 응답 지연
- When 서버 기동 또는 요청
- Then 중복·필수값 누락·파싱 불가 DN은 기동 실패, bind 실패는 503 `unavailable`이며 root 폴백 없음. 지연은 `MACHINE_REQUEST_TIMEOUT`(기본 10s) 안에 503으로 끝나고 슬롯이 반환된다.

### `AC-010` — 감사 추적

- Covers: `REQ-009`, `REQ-014`
- Given 허용 / 검증 실패 / 검증 후 scope 거부 / 검증 후 rate limit / bind 실패 / 조기 반환(`selectAuth` 거부, Origin gate 거부, 혼용 400, 404, IP throttle 429, JWKS 503) 각 1건 이상
- When 로그 확인
- Then `Authorization`을 실은 요청마다 정확히 한 줄이 있고 `event`, `provider`, `actor`, `request_id`, `operation`, `result`, `reason`(고정 enum) 필드를 가진다. `actor`는 서명·claim 검증을 통과한 client id만이고 그 전 단계 실패는 `actor=unknown`+토큰 fingerprint(SHA-256 앞 6바이트)다. 검증 후 scope 거부·limiter·bind 실패는 actor를 기록한다. 토큰·서명 조각·client secret·bind 비밀번호·원문 `Authorization`·go-oidc/go-jose 원문 오류 문자열은 어느 로그·응답에도 없다. live e2e는 모든 컨테이너 로그를 이 값들로 grep해 0건을 확인한다.

### `AC-011` — rate limit·동시성

- Covers: `REQ-010`
- Given 검증된 client별 한도 N rps/burst, client별·전역 동시 M, IP 실패 throttle
- When (a) 한 client가 한도 초과 (b) 다른 client가 동시에 호출 (c) 서로 다른 수만 개 IP에서 무효 토큰 1회씩 (d) 같은 IP의 반복 무효 토큰 (e) 위조 `X-Forwarded-For`
- Then (a) 초과분 429 `machine_rate_limited` + `Retry-After`. (b) **limiter 예산은 격리**된다 — 한 client의 소진이 다른 client의 token bucket을 줄이지 않는다(LDAP·JWKS·전역 동시성 같은 공유 자원의 격리는 보장하지 않으며 문서에 명시). (c) IP limiter 항목 수가 `MACHINE_IP_LIMITER_MAX`(기본 10000)를 넘지 않고 프로세스 메모리가 유계. (d) 임계 초과 후 서명 검증·JWKS 조회 **이전**에 429(검증기 호출 카운터 불변). (e) 신뢰 프록시 밖 피어의 XFF는 무시되고, `UI_TRUSTED_PROXIES`가 `private`(기본)이면 머신 활성 상태에서 기동 실패. unknown client는 limiter 상태를 만들지 않는다.

### `AC-012` — 토큰 수명·시계 오차

- Covers: `REQ-011`
- Given 기본 skew 30s, MAX_TTL 10m, 주입 가능한 `now`. 경계 표: `exp-iat` = MAX_TTL(허용)/MAX_TTL+1s(거부); `nbf` = now+skew(허용)/now+skew+1s(거부), **now+5m 이내여도 skew 밖이면 거부**(go-oidc 기본과 다름); 만료 후 now = exp+skew(허용)/exp+skew+1s(거부); `iat` = now+skew(허용)/+1s(거부); `exp<=iat`(거부); skew 설정 0·60(허용)/-1·61(기동 실패)
- When 실제 서명 검증기(go-oidc `SkipExpiryCheck:true` + 자체 시간 검증, 로컬 JWKS)를 통과해 호출
- Then 표대로 200/401. 시계는 주입 가능한 `now`로 테스트하고 live Keycloak에서는 기본 300s 토큰의 만료 후 거부를 확인한다.

### `AC-015` — 민감 base 경계

- Covers: `REQ-015`
- Given 머신 활성, `directory.entry.read`·`server.monitor.read`만 가진 토큰(그리고 비교용 `audit.read` 추가 토큰)
- When `GET /api/entry?dn=<accesslog 항목 DN>` / `cn=config` / `cn=Monitor` / `BASE_DN` 밖 DN / ParseDN 우회 변형(대소문자·escape·공백) / `GET /api/tree?dn=cn=accesslog` / `GET /api/monitor`
- Then 사용자 DN은 200, 그 외 DN은 403 `scope_denied`(핸들러가 LDAP 검색을 발행하기 전). `getMonitor`는 `audit.read` 없으면 `recentLogs` 비어 있고 accesslog 검색 미발행, `audit.read`와 `server.monitor.read`가 모두 있을 때만 로그 포함. LDAP ACL 백스톱: 머신 DN은 기본 ACL에서 accesslog·config 읽기가 거부된다(code 가드를 끈 시험 빌드에서도 `getEntry(accesslog)`가 실패).

### `AC-017` — cursor 격리

- Covers: `REQ-017`
- Given 허용 client A, B와 사람 세션 cursor
- When A의 `listUsers`/`listGroups` 2페이지 cursor를 B 토큰·사람 세션에서 재생 / 사람 cursor를 머신 경로에서 재생 / A의 토큰 갱신(새 `jti`·`iat`) 후 같은 cursor로 이어서 조회
- Then 교차 재생은 기존 `cursor_invalid` 400, 갱신 후 연속 조회는 200. 머신 요청의 임시 세션 ID는 cursor 바인딩에 쓰이지 않는다.

### `AC-018` — 읽기 전용 실행 신원

- Covers: `REQ-004`
- Given 문서의 ACL LDIF를 적용한 머신 DN
- When 머신 DN으로 slapd에 직접 `ldapadd`/`ldapmodify`(자기 항목 포함)/`ldapdelete`/`ldappasswd`/`modrdn` 시도, 그리고 비허용 subtree·`userPassword`·accesslog·config 읽기 시도
- Then 모든 쓰기·자기 수정은 `insufficient access`(50), 비밀 속성·비허용 base는 읽기 거부. 같은 LDIF가 다른 신원(사용자 self write, 관리자)의 동작을 바꾸지 않음을 같은 시나리오에서 확인한다(규칙 순서: 머신 DN 규칙이 `by self write` catch-all보다 앞).

### `AC-019` — 긴급 차단·롤백

- Covers: `REQ-018`, `REQ-013`
- Given 유효한 발급 토큰을 가진 client
- When (a) Keycloak client 비활성화 (b) `MACHINE_ALLOWED_CLIENTS`에서 제거 후 전 replica 교체 (c) `MACHINE_AUTH_ENABLED=false` 후 전 replica 교체
- Then (a) 이미 발급된 토큰은 **여전히 통과**(관측과 일치, 문서화), 새 토큰 발급만 실패. (b) 교체 완료 후 같은 토큰이 401, (c) bearer 무시. 절차 증거: 이전 revision pod 0개, 진행 중 요청이 `terminationGracePeriodSeconds`(≥ `MACHINE_REQUEST_TIMEOUT`) 안에 종료, 기존 쿠키 e2e 무변경.

### `AC-013` — OpenAPI·드리프트 테스트

- Covers: `REQ-003`, `REQ-012`
- Given 갱신된 `openapi.json`
- When `go test ./internal/httpapi/...`
- Then `machineBearer` 보유 오퍼레이션 집합 == 코드 allowlist(8), denylist 36개와 `getMe`는 `machineBearer` 부재, 비-GET에는 `machineBearer` 금지, 공개 8개 불변, 기존 `TestOpenAPIMatchesRegisteredRoutes`·`HasNoUserPasswordProperty` 통과. 이 계약은 문서 일치만 증명하므로 실제 가드는 AC-003의 전수 호출로 따로 증명한다.

### `AC-014` — 기본 꺼짐·호환

- Covers: `REQ-013`
- Given `MACHINE_AUTH_ENABLED` 미설정(또는 Helm `ui.machineAuth.enabled=false`)
- When bearer 포함 요청, 기존 e2e(ui-e2e·e2e) 실행
- Then bearer는 무시(쿠키 없음 → 기존 401 `not logged in`), 기존 e2e 무변경 통과, 머신 관련 라우트·검증기·JWKS 조회 없음.

## Architecture and decisions

- Relevant ADR/design links: [auth-provider-policy](../../auth-provider-policy.md)(“프로세스당 단일 provider” — 머신 수용 경로는 UI 로그인 provider가 아닌 별도 인바운드 인증으로 명시 예외화 필요, T-031),
  [api.md](../../api.md), [openapi.json](../../../ui/backend/internal/httpapi/openapi/openapi.json),
  [keycloak-federation-e2e.yml](../../../.github/workflows/keycloak-federation-e2e.yml),
  [api-error-envelope](../api-error-envelope/CHANGE.md)(D218-3 코드 표: `token_invalid`·`token_expired`·`scope_denied`는 이 패키지를 위해 예약된 이름이고 아직 방출되지 않는다; D218-14: 새 코드는 표·골든 목록·OpenAPI enum을 같은 PR에서 갱신; [ADR](../api-error-envelope/ADR.md)),
  [api-cursor-pagination](../api-cursor-pagination/CHANGE.md)(커서는 `cursorBinding`이 로그인 세션 ID에 묶는다. 요청마다 임시 세션을 만드는 머신 주체는 `ui/backend/internal/httpapi/cursor.go`의 그 함수에서 안정적인 주체에 묶어야 한다).
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
| D2 | 기존 경로(`/api/users` 등)에 인증기 선택 방식으로 얹는다: `Authorization` 헤더 **존재** → 머신 인증기만(문법이 틀리면 401, 쿠키로 폴백 없음), 없음 → 기존 쿠키 `requireSession`. 둘 다 존재 → 400. 경로 복제 없음. 정확한 문법은 아래 “인증 경로 분리 규칙” 표 | 클라이언트·OpenAPI·SDK 변경 최소, 오퍼레이션 단일 정의 | 한 경로가 두 인증을 받아 테스트 매트릭스 증가, 선택 로직 버그가 곧 경계 약화 | 오퍼레이션 복제 `/api/v1/machine/...` 접두사(경로 분리가 더 강한 격리)로 전환 가능. 순수 함수 `selectAuth`로 격리해 단위 테스트(Q3) |
| D3 | scope는 서버 코드의 정적 `operation→scope` allowlist로만 해석(OpenAPI `x-machine-scope`와 1:1). client별 허용 scope 상한을 서버 설정에 두고, 유효 권한 = 토큰 scope ∩ 서버 상한. 미등록 오퍼레이션 기본 거부 | IdP 설정 실수(과다 scope 부여)가 곧바로 권한 확대가 되지 않게 함. “라우트 추가 시 자동 허용” 방지 | client 추가 시 ldapium 설정도 갱신 필요 | 상한을 `*`(토큰 scope 그대로)로 두는 모드는 두지 않음 — 필요 시 별도 결정으로 도입 |
| D4 | 실행 신원은 배포당 하나의 전용 읽기 전용 LDAP 계정(`MACHINE_LDAP_BIND_DN`). 요청마다 bind 후 종료. 기동 시 `BACKUP_ADMIN_DNS`·프로파일 관리자 DN·`LDAP_SERVICE_ACCOUNT_DN`·**rootdn**과 `ldap.ParseDN` 기반 동등성(문자열 비교 금지)으로 비교해 겹치면 실패. backend에는 rootdn 설정이 없으므로 활성 시 필수 입력 `MACHINE_LDAP_ROOT_DNS`(쉼표 목록; Helm은 차트가 이미 아는 관리자 DN 값에서 파생, T-016)를 신뢰 입력으로 쓴다. 읽기 전용은 **ACL이 강제**(머신 DN 규칙을 `by self write` catch-all 앞에 배치, “머신 LDAP 계정·ACL” 절)하고 실제 쓰기 시도로 증명. 실행 경계: 전역 LDAP 동시성 슬롯을 bind **이전**에 비차단으로 획득, 요청 전체 deadline(dial+bind+search, 기본 10s), 결과 상한, bind 실패 503(root 폴백 없음), 취소·패닉에서 슬롯·연결 반환. 머신 인증·bind 자격에 `SESSION_SECRET`을 쓰지 않는다(list cursor MAC 키는 HTTP 계층의 기존 `cursorKey`를 그대로 공유 — D16, **문구 변경**: 초안은 “`SESSION_SECRET` 무관”이라 cursor 키와 충돌했음) | 최소권한, 세션 저장소 무관, 연결 상태 없음(재연결 로직 부재 문제 회피) | 요청당 bind 지연, client별 신원 분리 불가(v1), rootdn 입력 설정 추가 | 연결 풀 도입, client→DN 매핑 설정 확장, subtree allowlist(Q5) |
| D5 | 검증 정책은 아래 “토큰 검증 정책” 표가 **정본**이다(JOSE·payload `typ`, `aud` 정확 멤버십, `azp`==`client_id`, SA 판별, 시간 규칙, alg allowlist). 요약: `iss` 정확 일치, 허용 client만, SSO 브라우저 client·ID/refresh·같은 client의 사람 발급 토큰 거부, 미검증 claim은 신뢰하지 않음 | audience confusion·ID token 오용·브라우저/사람 토큰의 머신 경로 재사용(confused deputy) 차단. 관측([EVIDENCE §2.3](EVIDENCE.md)): 같은 client의 사람 토큰은 `aud`·`azp`·`scope`가 SA 토큰과 동일 | Keycloak에 audience mapper·전용 client 설정 필요(운영 문서화), 자체 claim 검증 코드 | 허용 알고리즘을 설정화(비대칭 한정), claim 이름 설정화는 IdP 호환 필요 시 별도 결정 |
| D6 | v1은 GET 읽기 전용. 비-GET은 scope와 무관하게 거부 | 가장 작은 위험 표면, 쓰기는 idempotency·조건부 수정 계약(PLAN P1) 선행 필요 | 쓰기 자동화 불가 | 쓰기는 별도 Change Package(Class D) |
| D7 | 즉시 폐기 없음. 토큰 최대 수명 `MACHINE_TOKEN_MAX_TTL`(기본 10m, 허용 범위 (0, 1h], `exp-iat` 초과 시 거부), 시계 오차 `MACHINE_CLOCK_SKEW`(기본 30s, 범위 0–60s, 밖이면 기동 실패). **긴급 차단 경로**: ① `MACHINE_ALLOWED_CLIENTS`에서 제거 또는 `MACHINE_AUTH_ENABLED=false`로 배포(v1은 리로드 없음, 재시작/롤아웃만) → ② **모든 replica 교체 완료와 이전 revision pod 0개 확인**, 진행 중 요청 종료 확인(`terminationGracePeriodSeconds` ≥ `MACHINE_REQUEST_TIMEOUT`) → ③ 그 다음 Keycloak client 비활성화·secret 회전. Keycloak client 비활성화·secret 회전만으로는 이미 발급된 JWT가 차단되지 않는다(관측: 비활성화 후에도 사전 발급 토큰 검증 통과, [EVIDENCE §2.7](EVIDENCE.md)). ①을 하지 않은 최대 노출 = 남은 TTL + skew | 요청마다 introspection 호출은 IdP 의존·지연 증가 | 탈취 토큰이 최대 TTL+오차 동안 유효, 차단에 롤아웃이 필요 | introspection 옵션(`aud`에 있는 resource client 필요, 캐시·fail-closed) 후속 |
| D8 | JWKS: fail closed, **커스텀 `oidc.KeySet`** 사용(go-oidc `RemoteKeySet`은 알려진 kid의 잘못된 서명에도, 최소 간격 없이 재조회하므로 그대로 쓰지 않음). 정책: 캐시 TTL 10m + stale-if-error 1h, 조회 트리거는 (i) 미캐시 kid (ii) TTL 만료뿐 — 알려진 kid의 서명 실패는 조회하지 않음, issuer 단위 최소 재조회 간격 30s(성공·실패 모두 기준)·single-flight, 실패 시 지수 backoff 30s→5m, negative kid 캐시(≤256개, TTL 5m), fetch timeout 5s·응답 1 MiB·키 20개·리다이렉트 금지, `use=sig`(또는 미지정) 키만, alg는 allowlist와 일치하는 키만. 응답 매핑: 정상 조회 후 미지 kid → 401, 조회 장애·backoff 중 미캐시 kid → 503+`Retry-After`(정수 초), 캐시·stale 한도 초과 → 503. 상세 표는 AC-008 | 서명 미검증 허용 금지. 임의/위조 토큰 폭주로 IdP를 때리는 증폭 방지(관측: 변조 토큰마다 조회 발생) | 키 회전 직후 새 kid 토큰이 최대 30s 401, IdP 장애 중 키 회전 직후 토큰 거부, 자체 KeySet 코드 | 캐시 TTL·최소 간격 설정화(범위 검증), 회전 시 overlap 운영 가이드 |
| D9 | 남용 제한 순서: ① `selectAuth` 문법·길이 검사(암호 연산 없음) → ② **IP 실패 throttle 조회(서명·JWKS 이전)** → ③ 전역 인증 동시성 슬롯(`MACHINE_MAX_AUTH_CONCURRENCY`, 기본 16, 비차단, 초과 시 503+`Retry-After`) → ④ 검증 → ⑤ **검증된 client에만** token bucket(rps/burst)·client 동시 실행 상한 → ⑥ 전역 LDAP 동시성(`MACHINE_MAX_CONCURRENCY` 전역, 기본 8) 슬롯을 bind 이전에 비차단 획득. 모든 상태는 유계: IP limiter 항목 ≤ `MACHINE_IP_LIMITER_MAX`(기본 10000, 초과 시 가장 오래된 항목 제거), client limiter는 설정된 allowlist 크기, unknown client는 상태를 만들지 않음. 대기열 없음(즉시 429/503). 클라이언트 IP는 기존 `c.RealIP()`(`ipExtractorFor`)을 재사용하되 머신 활성 시 `UI_TRUSTED_PROXIES`가 기본 `private`이면 기동 실패(내부망 client가 XFF를 위조 가능) — ingress CIDR 명시 또는 `none` 필요, ingress는 클라이언트가 보낸 XFF를 덮어쓰거나 정리해야 함(운영 문서). 기존 `loginLimiter`는 재사용하지 않고(맵 무한 증가·동시 시도 overshoot를 상속하므로) 상한이 있는 별도 구현을 쓴다. per-process 의미(replica별 한도) | 비싼 작업 앞의 값싼 거부, 상태 고갈 방지 | 다중 replica에서 pod별 한도(전역 아님), 재시작 시 초기화, 상한 도달 시 오래된 IP 한도 소실 | 공유 limiter는 ingress/게이트웨이 계층에 위임 |
| D10 | 감사는 구조화 로그 줄(`event=machine_access`) 추가. `Authorization`을 실은 요청은 조기 반환(selectAuth 거부·Origin gate·404·429·503 포함)까지 정확히 한 줄(바깥쪽 미들웨어에서 emit). actor는 **검증 통과 후의 `azp`만**; 그 전 실패는 `actor=unknown`+토큰 fingerprint; 검증 후 scope 거부·limiter·bind 실패는 actor 기록. `reason`은 고정 enum(`bad_header`·`alg`·`typ`·`sig`·`iss`·`aud`·`azp`·`sa_claims`·`time`·`ttl`·`jwks_unavailable`·`scope`·`rate`·… ), verifier 원문 오류 문자열은 응답·로그에 쓰지 않음. `sub` 원문은 fingerprint, request id는 기존 `RequestID` 값. 토큰·`Authorization` 값 미기록 | 기존 `auth` 이벤트 스키마·`docs/audit-event-schema.md`와 같은 계열, 추가 저장소 불필요. 미검증 claim을 actor로 믿으면 로그 위조 | 로그 수집 파이프라인에 의존 | 별도 감사 저장소는 후속 |
| D11 | 머신 인증은 UI 인증 모드와 독립. 발급자는 `MACHINE_OIDC_ISSUER_URL`, 비어 있고 SSO 활성이면 `SSO_ISSUER_URL` 상속(상속값도 D15의 HTTPS 규칙을 통과해야 함), LDAP 모드는 명시 필요 | “이미 설정된 issuer 재사용” 요구를 SSO 배포에서 충족하면서 LDAP 모드도 허용 | LDAP 모드는 issuer 추가 설정 필요 | LDAP 모드 비지원으로 축소 가능(Q4) |
| D12 | 기본 꺼짐(`MACHINE_AUTH_ENABLED=false`). 꺼지면 bearer 경로·JWKS 조회·머신 라우팅 로직 비활성 | 기존 계약·롤백 단순화 | — | 플래그 한 줄로 롤백 |
| D13 | OpenAPI에 `securitySchemes.machineBearer`(http/bearer/JWT) 추가, 허용 오퍼레이션만 `security: [{cookieAuth:[]},{machineBearer:[scope]}]`와 `x-machine-scope`. 전역 `security` 기본값은 `cookieAuth` 유지. 계약 테스트로 allowlist/denylist 양방향 강제. 계약은 문서↔allowlist 일치만 증명하므로 **런타임 deny-by-default 가드**(machine principal이면 `method+route`가 allowlist에 없는 모든 보호 라우트를 bind·핸들러 이전 403)와 그 전수 호출 테스트를 별도로 둔다(AC-003) | 문서가 곧 허용 목록이어야 함(드리프트 방지), 새 GET 라우트 자동 허용 방지 | 스펙 소비 도구가 다중 scheme을 처리해야 함 | `x-machine-scope`만 두고 `security`는 유지하는 보수안 |
| D14 | 민감 base 경계: 머신 principal에 한해 (a) `getEntry`·`listTree`의 DN은 `ParseDN`으로 정규화해 `LDAP_BASE_DN`과 같거나 하위여야 하고, 아니면 403 `scope_denied`(LDAP 검색 전). `cn=accesslog`·`cn=config`·`cn=Monitor`는 어떤 scope로도 이 경로로 읽을 수 없다. (b) `getMonitor`는 `audit.read`가 유효 scope에 없으면 accesslog 검색을 아예 발행하지 않고 `recentLogs`를 비운다(`MonitorStats`에 로그 포함 여부를 넘기는 코드 변경, 사람 세션 동작 불변). (c) accesslog `reqMod` 값은 `userPassword` 속성 denylist로 걸러지지 않으므로(관측) (a)가 유일한 코드 방어선이고, 감사 DTO는 변경 속성 **이름**만 내는 현 동작을 테스트로 고정한다. (d) LDAP ACL 백스톱: 머신 DN에 accesslog·config 읽기를 기본 부여하지 않고, `audit.read`를 쓰는 배포만 문서의 opt-in ACL 조각으로 accesslog 읽기를 추가한다. Q5(client별 subtree allowlist 제외)는 유지 — 여기는 client별 설정이 아닌 **전역 BASE_DN 한정**과 민감 DB 제외다 | 공유 bind에 감사 ACL을 주면 `server.monitor.read`·`directory.entry.read`만으로 opt-in scope 우회·비밀 값 노출이 가능(`getMonitor`는 최근 50건 반환, `getEntry`는 임의 DN `*`) | 머신 principal 분기 코드 추가, `entryRedactedAttrs` 불변 원칙은 유지 | 후속 subtree 패키지에서 client별 base로 세분 |
| D15 | issuer/JWKS 전송: 머신 issuer URL과 discovery의 `jwks_uri`는 `https`만 허용(기동 시 검증, SSO의 `validateIssuerURL`은 변경하지 않고 머신 전용 검증 추가 — 기존 검증은 원격 `http://`도 통과). 로컬 테스트 예외는 env `MACHINE_OIDC_INSECURE_HTTP=true`만(Helm 값으로 노출하지 않음, 켜면 기동 시 WARN). 전용 `http.Client`: timeout 5s, 리다이렉트 금지, 응답 1 MiB 상한, TLS ≥1.2. issuer 문자열은 토큰 `iss`와 byte 단위 정확 일치(Keycloak은 요청 Host 기반이라 `KC_HOSTNAME` 고정 또는 단일 호스트명 사용, [EVIDENCE §2.5](EVIDENCE.md)) | discovery/JWKS 변조로 위조 키 신뢰 방지 | 기존 SSO issuer 규칙과 다름, e2e는 예외 플래그 사용 | 내부 CA 번들 설정은 후속 |
| D16 | list cursor 바인딩: 머신 principal은 `HMAC("machine:" + len(iss) + ":" + iss + client_id)`로 묶는다(`cursorBinding`이 principal 종류별로 도메인 접두사 `sid:`/`machine:`를 분리). 요청별 임시 `Session.ID`는 쓰지 않는다. 키는 기존 `cursorKey`(`SESSION_SECRET` 유래)를 공유 — 자격 증명이 아닌 무결성 키이므로 D4 문구를 좁혔다. 토큰의 `jti`·`exp`·`sub`는 바인딩에 넣지 않아 갱신 후에도 이어진다 | 임시 ID가 비면 모든 client가 같은 바인딩, 랜덤이면 다음 페이지 실패(`cursor.go` 주석이 예고) | `SESSION_SECRET` 회전 시 cursor 무효(기존과 동일) | 별도 `MACHINE_CURSOR_KEY` 분리 |

### v1 오퍼레이션 분류 (전체 53개 = 공개 8 + 보호 45)

`jq` 집계와 일치([EVIDENCE §1](EVIDENCE.md)). 보호 GET 20개 중 6개 기본 허용, 2개 opt-in, 12개 거부(`getMe` 포함). 비-GET 25개는 전부 거부.

| operationId | 경로 | Scope | 기본 | 비고 |
|---|---|---|---|---|
| `listUsers` | `GET /api/users` | `directory.users.read` | 허용 | 5000 상한·`truncated`·cursor 유지, 속성은 명시 목록 |
| `listGroups` | `GET /api/groups` | `directory.groups.read` | 허용 | 〃 |
| `listTree` | `GET /api/tree` | `directory.tree.read` | 허용 | 단일 레벨. D14(a) BASE_DN 한정, 자식 수 상한(T-013) |
| `getEntry` | `GET /api/entry` | `directory.entry.read` | 허용 | D14(a) BASE_DN 한정 + `userPassword` denylist 불변. **`*` 속성을 verbatim 반환하는 유일한 GET** |
| `listPasswordPolicies` | `GET /api/password-policies` | `directory.policies.read` | 허용 | 명시 속성 목록, 비밀 아님 |
| `getMonitor` | `GET /api/monitor` | `server.monitor.read` | 허용 | `audit.read` 없으면 `recentLogs` 비움·accesslog 검색 미발행(D14 b) |
| `listAuditActions` | `GET /api/audit/actions` | `audit.read` | opt-in | 행위자·대상 DN 노출(민감), 변경 속성 이름만(값 없음) |
| `getServerSettings` | `GET /api/server-settings` | `server.settings.read` | opt-in | Root DSE `+`만 조회 |
| `getMe` | `GET /api/me` | — | 거부 | 세션 DN 의미 — 머신용 whoami는 Q6 |

공개 8개(`getMeta`, `getOpenAPI`, `getAuthConfig`, `getLdapHealth`, `login`, `logout`, `ssoStart`, `ssoCallback`)는 인증 대상이 아니며 변경 없음(단 “인증 경로 분리 규칙”의 bearer 거부 행 참조).

### 명시 denylist (머신 경로에서 항상 거부, 36개 + `getMe`)

| 구분 | operationId |
|---|---|
| 사용자 쓰기·비밀번호 (7) | `createUser`, `updateUser`, `patchUser`, `deleteUser`, `setPassword`, `unlockUser`, `lockUser` |
| 그룹 쓰기 (6) | `createGroup`, `updateGroup`, `patchGroup`, `deleteGroup`, `addGroupMember`, `removeGroupMember` |
| 엔트리 이동 (1) | `moveEntry` |
| 애플리케이션 프로파일 x-admin (14) | `getProfileCapabilities`, `listApplications`, `listIntegrationMethods`, `putIntegrationMethod`, `getApplicationProfile`, `putApplicationProfile`, `deleteApplicationProfile`, `getKeycloakRoles`, `getApplicationRoles`, `getIntegrationStatus`, `verifyIntegration`, `applyKeycloakRoleOperation`, `exportApplicationConfiguration`, `previewMapping` |
| 백업 x-admin (8) | `getBackups`, `putBackupPolicies`, `putBackupConnection`, `deleteBackupConnection`, `runBackup`, `getBackupJob`, `listBackupJobs`, `cancelBackupJob` |

7+6+1+14+8 = 36, 여기에 `getMe` 1개 = 거부 37개. 허용 후보 8 + 거부 37 = 보호 45. 초안 목록은 `patchUser`·`patchGroup`·`getBackupJob`·`listBackupJobs`·`cancelBackupJob` 5개가 빠져 있었다.

프로파일·백업 GET은 읽기이지만 관리자 DN 경계와 export/검증 부작용(외부 호출)이 있어 v1에서 제외한다. 기본 거부이므로 목록은 계약 테스트의 기대값이고, 런타임 가드는 목록이 아니라 **allowlist 부재**로 거부한다.

### 토큰 검증 정책 (D5 정본)

검증 순서는 위에서 아래이며(값싼 검사 먼저) 하나라도 실패하면 401 `token_invalid`(순수 만료는 `token_expired`), 조회 장애는 503. 아래 값은 기본값이고 괄호는 설정 범위다. 시각 비교는 모두 주입 가능한 `now`.

| 항목 | 규칙 | 관측 근거 |
|---|---|---|
| 크기 | `Authorization` 값 ≤ 8 KiB | — |
| 알고리즘 | `MACHINE_OIDC_ALGS`(기본 `RS256,ES256`; 비대칭만, `none`·`HS*`·빈 값은 기동 실패). 동일 목록을 go-oidc `Config.SupportedSigningAlgs`에 명시. 허용 밖 alg·HS256 공개키 혼동은 거부 | discovery가 `HS*`를 광고 → 기본 설정이면 허용됨 |
| JOSE `typ` | 필수, `JWT` 또는 `at+jwt`(대소문자 무시). 그 외·누락 거부. JOSE `typ`은 access/ID 구분에 쓰지 않는다 | access·ID 모두 `JWT` |
| `kid` | 필수 | 항상 존재 |
| payload `typ` | 필수, 정확히 `Bearer`. `ID`·`Refresh` 등 거부 | access `Bearer`, ID `ID`, refresh `Refresh` |
| `iss` | `MACHINE_OIDC_ISSUER_URL`과 byte 정확 일치 | issuer는 요청 Host 기반 |
| `aud` | 문자열 또는 문자열 배열. `MACHINE_OIDC_AUDIENCE`가 **정확히 멤버**여야 함. 누락·null·비문자열 원소·`account`만 있는 경우 거부. go-oidc는 `SkipClientIDCheck:true`로 두고 이 규칙을 자체 검사 | 기본 `"account"` 문자열, mapper 후 `["ldapium-api","account"]` |
| `azp` / `client_id` | **둘 다 필수**, 문자열, `azp == client_id`. 우선순위 개념 없음(한쪽만 있거나 불일치면 거부). 값은 `MACHINE_ALLOWED_CLIENTS`에 있어야 하고 SSO 브라우저 client id면 거부 | SA 토큰은 둘 다 존재, 사람 토큰엔 `client_id` 없음 |
| 서비스 계정 판별 | `sid` **없음**, `preferred_username == "service-account-" + client_id`, `sub` 비어 있지 않은 문자열. 하나라도 어긋나면 거부(허용 client에서 발급된 사람·token exchange 토큰 차단) | 사람 토큰은 `sid` 있음·`preferred_username`=사용자 |
| `scope` | 공백 구분 문자열 필수. 유효 scope = 토큰 scope ∩ client 상한(D3). 교집합 밖은 요청 시 403 | Keycloak은 `profile`·`email`을 섞어 발급 |
| `iat` | 필수·JSON 숫자, `iat ≤ now + skew` | `iat` 존재 |
| `exp` | 필수·JSON 숫자, `exp > iat`, `exp − iat ≤ MAX_TTL`(기본 10m, 범위 (0,1h]), `now ≤ exp + skew` | 기본 300s |
| `nbf` | 선택. 있으면 숫자, `nbf ≤ now + skew`, `nbf ≤ exp`. go-oidc의 하드코딩 **5분 leeway는 쓰지 않는다**: `SkipExpiryCheck:true`로 go-oidc의 exp·nbf 검사를 끄고(nbf 검사는 그 블록 안) 위 규칙을 자체 구현 | Keycloak은 `nbf` 없음 |
| skew | `MACHINE_CLOCK_SKEW` 기본 30s, 0–60s, 범위 밖 기동 실패 | — |
| 서명 | 커스텀 KeySet(D8)으로 검증, `use=sig`(또는 미지정) 키·alg 일치 키만 | JWKS에 `use=enc` 키 존재 |
| `jti` | 사용하지 않음(재생 추적 없음, 위협 모델 참조) | — |

null·누락·타입 오류 claim은 모두 거부이며 기본값으로 대체하지 않는다. 토큰 발급 측 요구(운영 문서): 머신 client는 service account 전용(standard flow·direct access grant 비활성화), `aud` mapper는 **그 client의 전용 scope**에만 두고 `ldapium-sso`와 공유하는 scope에 두지 않는다(공유 시 SSO 사용자 토큰에 `ldapium-api`가 들어갈 수 있음 — 미실행 가설, e2e 항목), 필요 scope는 client 기본 scope로 부여. `audience` mapper가 없으면 `aud`가 `account`뿐이라 모든 토큰이 거부된다.

### 인증 경로 분리 규칙 (D2 상세)

`selectAuth`는 순수 함수이며 입력은 `Authorization` 헤더 값 목록, `ldapium_session` 쿠키 존재 여부, 기능 활성 여부, 대상 라우트 종류(보호/공개 auth/기타 공개)다. 출력은 `{cookie, bearer(token), reject(status), none}`.

| # | 입력 | 결과 |
|---|---|---|
| 1 | 기능 꺼짐 | `Authorization`은 완전히 무시, 기존 동작(AC-014) |
| 2 | `Authorization` 헤더가 2줄 이상 | 401 `token_invalid` |
| 3 | 단일 값에 `,`(comma 결합) 포함 | 401 |
| 4 | 값이 비어 있음 / `Bearer` 뒤 토큰 없음 / 토큰이 token68 문자(`A-Za-z0-9-._~+/` 뒤 `=*`) 밖 | 401 |
| 5 | scheme이 `Bearer`가 아님(`Basic` 등) | 401 (쿠키로 폴백하지 않음) |
| 6 | scheme 대소문자(`bearer`·`BEARER`) | 허용(RFC 9110: scheme은 대소문자 무시) |
| 7 | scheme과 토큰 사이가 정확히 공백 1개가 아님(탭·2개 이상), 앞뒤 공백 | 401 |
| 8 | 유효 bearer + 보호 라우트 + 세션 쿠키 없음 | `bearer` |
| 9 | 유효 bearer + `ldapium_session` 쿠키가 하나라도 있음(빈 값·무효·중복 포함) | 400 (혼용) |
| 10 | 쿠키만(헤더 없음) — 빈·무효·중복 쿠키 포함 | 기존 쿠키 경로 그대로(`requireSession` 결과) |
| 11 | `login`·`logout`·`ssoStart`·`ssoCallback`(쿠키를 발행·삭제하는 공개 auth 경로)에 `Authorization` 존재 | 400, 쿠키 미발행·미삭제 |
| 12 | 그 외 공개 4개(`getMeta`·`getOpenAPI`·`getAuthConfig`·`getLdapHealth`)에 `Authorization` 존재 | 무시(공개 응답 그대로, 감사 줄은 남김) |
| 13 | bearer로 비-GET 또는 allowlist 밖 라우트 | 403 `scope_denied`(bind·핸들러 이전) |

미들웨어 순서(바깥→안): RequestID → (bearer 감사 emit 래퍼) → CORS(설정 시) → **Origin gate(변경 없음, 가장 바깥의 상태 변경 보호)** → `selectAuth`/인증 → deny-by-default 가드 → scope 해석 → 핸들러. Origin gate는 `Authorization` 헤더가 있어도 건너뛰지 않는다: foreign/`null`/중복 `Origin` + bearer(또는 쿠키 혼용)는 gate의 기존 응답이 우선하고 핸들러는 실행되지 않는다. CORS는 `Authorization`을 허용 헤더에 추가하지 않으며(현재도 없음) preflight의 `Access-Control-Request-Headers: authorization`은 거부된다(회귀 테스트).

1. 선택은 위 표의 순수 함수 하나가 한다.
2. bearer 경로는 `requireSession`을 거치지 않고, `session.Store`에 항목을 만들지 않으며 `Set-Cookie`를 내지 않는다. 핸들러 재사용을 위해 요청 수명 한정의 임시 `Session{DN: 머신 bind DN, Bound: 요청별 bind}`를 컨텍스트에 두고 응답 후(취소·패닉 포함) 닫는다. 임시 `Session.ID`는 cursor 바인딩에 쓰지 않는다(D16).
3. bearer 경로는 GET만, allowlist 안에서만 통과한다(런타임 가드, D13).
4. 쿠키 경로는 bearer를 해석하지 않는다.
5. 머신 bind DN이 `BACKUP_ADMIN_DNS`·프로파일 관리자 DN에 들어가면 기동 실패(D4).

### 머신 LDAP 계정·ACL (D4/D14 상세, Q2: 운영자 수동 + 문서 LDIF)

- 계정 항목은 `getEntry`/`listUsers` 검색 base 밖(예 `ou=system`)에 둔다.
- 머신 DN 전용 규칙은 **기존 `to * by self write by users read` catch-all(`image/entrypoint.sh` 렌더링의 `{4}`/`{2}` 규칙, ~:894·:905)보다 앞에** 와야 한다. 순서가 뒤면 `by self write`가 자기 항목 수정을 허용한다. 필수 규칙: ① `userPassword` 등 비밀 속성 `none` ② 허용 base subtree의 `entry`·검색·`read`만 부여 ③ 그 밖 DB·`cn=config`·accesslog `none`(accesslog 읽기는 `audit.read` 배포의 opt-in 조각으로만) ④ `cn=Monitor`는 `server.monitor.read` 배포에서만 `read`. 머신 전용 규칙은 slapd의 first-match 의미 때문에 다른 신원이 영향받지 않도록 `by * break` 구조여야 하며, 이 의미는 T-015에서 라이브로 확인하고 AC-018이 다른 신원 불변을 검증한다.
- 위 LDIF·ACL 변경은 Class D이며 구현 시 `ldapium-directory-change` 스킬을 먼저 로드한다. 이 패키지는 LDIF를 확정하지 않고 위 규칙과 AC-018 수용 기준을 확정한다.

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
| `MACHINE_OIDC_ISSUER_URL` | `SSO_ISSUER_URL` 상속 | **https만**(D15). SSO의 `validateIssuerURL`은 재사용하지 않음(원격 http 허용) |
| `MACHINE_OIDC_INSECURE_HTTP` | `false` | 로컬 테스트 전용 예외, 켜면 기동 WARN, Helm 미노출 |
| `MACHINE_OIDC_AUDIENCE` | 없음(활성 시 필수) | 토큰 `aud` 멤버십 |
| `MACHINE_OIDC_ALGS` | `RS256,ES256` | 비대칭 한정, D5 |
| `MACHINE_ALLOWED_CLIENTS` | 없음(활성 시 필수) | `clientId=scope,scope;…` — D3 상한 |
| `MACHINE_TOKEN_MAX_TTL` / `MACHINE_CLOCK_SKEW` | `10m`(≤1h) / `30s`(0–60s) | D7 |
| `MACHINE_JWKS_CACHE_TTL` / `_MAX_STALE` / `_MIN_REFRESH` | `10m` / `1h` / `30s` | D8, 범위 검증 |
| `MACHINE_LDAP_BIND_DN` / `MACHINE_LDAP_BIND_PASSWORD` | 없음(활성 시 필수) | 비밀번호는 기존 Secret 주입 관례(`secret-admin.yaml`, `SSO_CLIENT_SECRET`)를 따르며 차트가 생성·출력하지 않음 |
| `MACHINE_LDAP_ROOT_DNS` | 없음(활성 시 필수) | rootdn 식별 입력, D4 |
| `MACHINE_RATE_LIMIT_RPS` / `_BURST` / `MACHINE_CLIENT_CONCURRENCY` | `5` / `10` / `4` | D9, client별 |
| `MACHINE_MAX_CONCURRENCY` / `MACHINE_MAX_AUTH_CONCURRENCY` | `8` / `16` | D9, 전역 |
| `MACHINE_REQUEST_TIMEOUT` / `MACHINE_IP_LIMITER_MAX` | `10s` / `10000` | D4, D9 |
| `UI_TRUSTED_PROXIES`(기존) | — | 머신 활성 시 `private`(기본) 금지: CIDR 목록 또는 `none` |

Helm: `ui.machineAuth.{enabled,issuerURL,audience,allowedClients,tokenMaxTTL,clockSkew,ldapBindDN,existingSecret…,rateLimit…}`.
`enabled=false` 기본, 값 검증은 `values.schema`/템플릿 `required`로 활성 시 필수 항목 강제(기존 `ui.sso` 패턴 확인 후, T-016).

### 위협 모델

| 위협 | 시나리오 | 통제 | 잔여 위험 |
|---|---|---|---|
| 토큰 탈취 | 로그·프록시·에이전트 메모리에서 bearer 유출 | 짧은 TTL(D7), 읽기 전용(D6), 요청 rate limit(D9), 감사(D10), TLS 전제, 토큰 미로그, 긴급 차단 절차(D7: allowlist 제거 + 전 replica 교체) | TTL 동안 읽기 노출. Keycloak 비활성화로는 즉시 폐기 불가(introspection 후속) |
| 비밀 값 우회 노출 | 공유 bind의 accesslog/Monitor 권한을 `getEntry`·`getMonitor`로 사용(accesslog `reqMod`의 비밀 값) | D14: BASE_DN 한정, `audit.read` 없는 monitor 로그 제거, ACL 기본 거부 | `audit.read` 부여 배포는 감사 메타데이터(이름·DN·필터) 노출을 감수 |
| JWKS 증폭·DoS | 무작위 kid·위조 서명으로 IdP/서명 검증 비용 유발 | D8 재조회 최소 간격·negative cache, D9 IP throttle이 서명 이전, 전역 인증 동시성 | 분산 IP 공격은 상한(전역 동시성)까지만 방어 |
| scope 상승 | IdP에서 과다 scope 부여, 토큰 클레임 위조 | 서명 검증(D5), 서버 상한 교집합(D3), denylist·비-GET 거부(D6) | 상한 자체가 과다하면 허용 범위 내 노출(Q5) |
| confused deputy | 사람 SSO access token·타 서비스 토큰·ID token·**허용 client에서 발급된 사람 토큰**을 머신 경로에 제시 | `aud` 정확 멤버십·`azp`==`client_id`·SA 판별(`sid` 부재, `preferred_username`)·SSO client 제외·payload `typ=Bearer`(D5) | audience mapper를 SSO와 공유 scope에 두는 오설정 — e2e 음성 테스트(T-021), 머신 client의 사람 로그인 흐름 비활성화 운영 요건 |
| 재생(replay) | 유효 토큰 재전송 | 읽기 전용이라 상태 변경 없음, 짧은 TTL, 감사. `jti` 추적은 안 함 | TTL 내 재생 가능(읽기 한정) |
| 쿠키 경계 약화 | CSRF로 bearer 경로 악용/쿠키 경로에 bearer 우회 | 헤더 자격 증명은 브라우저 자동 첨부 아님, 혼용 400, `Authorization` 문법 표(폴백 없음), Origin gate 최외곽 유지, 공개 auth 경로 bearer 거부, bearer 요청 쿠키 미발행, CORS 미확장(D2) | 선택 함수 버그 — 단위·e2e 혼용 테스트 |
| 권한 있는 bind 오용 | 머신 경로가 관리자 bind를 쓰게 되는 설정 실수 | 전용 DN·rootdn 포함 ParseDN 비교 기동 실패(D4), ACL 순서·읽기 전용 쓰기 시도 증명(AC-018), `userPassword` denylist | ACL 오구성은 ldapium이 완전 검증 불가 — 운영 문서·e2e 점검 |
| 발급자 장애·위조 | JWKS 응답 변조/불가, 평문 http issuer | HTTPS 강제(D15), fail closed·503/401 구분(D8) | 내부 CA 신뢰는 시스템 번들 의존 |
| LDAP 자원 점유 | 느린 LDAP·무제한 결과·client 연결 끊김으로 슬롯 점유 | bind 이전 비차단 슬롯, 전체 deadline, 결과 상한, defer 해제(D4, D9) | 공유 LDAP 자원은 client 간 격리되지 않음 |
| 대량 열람 | 정상 scope로 users/entry 전수 조회 | rate limit·동시성·5000 상한·감사 | 범위 제한은 LDAP ACL/후속 subtree 패키지 |

## Change impact

| Area | Impact / evidence needed |
|---|---|
| Source / API / command | `httpapi` 미들웨어(인증 선택·머신 인증기·deny-by-default 가드·감사 래퍼), 임시 세션 주입, `cursorBinding` principal 분기, `config` 신규 env. **핸들러 불변 조건 완화**(Revision 2): `handleGetEntry`/`handleTreeChildren`(BASE_DN 가드, 머신 한정), `MonitorStats`(accesslog 포함 여부 인자, 사람 세션 동작 불변), `ldapclient` dial/bind/search deadline(deadline이 있는 ctx에서만 적용, 사람 경로 무변경), 결과 상한. 근거: 계약·단위 테스트와 기존 e2e 무변경 |
| Dependencies / lockfiles | 신규 의존성 없음 목표(`go-oidc`·`oauth2` 재사용). 추가 시 Class C 절차와 `THIRD-PARTY-LICENSES.md` 재생성 |
| Runtime / toolchain | N/A — 런타임·툴체인 변경 없음 |
| CI / CD | 신규 e2e 워크플로(Keycloak 고정 태그, T-022). Q8 결정대로 release 필수: `.github/workflows/release.yml`의 “Require release-critical checks specifically” 단계의 `release_critical` 배열에 신규 워크플로의 **정확한 job 이름**을 추가하고, 그 단계가 `success <job 이름>`을 태그 SHA에서 확인(동일 SHA 성공)해야 한다. path 필터 금지(이전 릴리스 교훈). 이름이 어긋나면 모든 릴리스가 실패하므로 job 이름은 워크플로 PR과 같은 PR에서 확정 |
| Release / packaging | 기본 꺼짐이라 기본 동작 불변. 차트 값 추가, 릴리스 노트에 신규 옵션 |
| Generated output | `openapi.json`, `llms.txt` — 둘 다 코드 생성이 아닌 수작업 관리(T-001 확인, [EVIDENCE §1](EVIDENCE.md)) |
| Security / supply chain | 신규 신뢰 경계 — 위협 모델 표, security-reviewer 검토, `security-e2e` 연계 검토 |
| Offline / air-gap | issuer·JWKS 접근 필요(기능 활성 시). 비활성 시 영향 없음. [air-gap](../../air-gap.md) 문서에 명시 |
| Documentation / operations | `docs/api.md`, `docs/auth-provider-policy.md`(예외 명시), `ui/README.md`, `charts/ldapium/README.md`, Keycloak client·audience mapper 설정 가이드, 머신 LDAP 계정 ACL 예시 |
| Portfolio / downstream repositories | 상태 기록·OpenForge 공개 상태 반영 여부 확인(T-033). 다운스트림 SDK 없음(T-001 확인) |

## Verification plan

| Acceptance ID | Verification method | Environment | Expected evidence |
|---|---|---|---|
| `AC-001` | 라이브 e2e: client_credentials 토큰으로 `GET /api/users` | Keycloak(고정 태그)+ldapium 컨테이너, `keycloak-federation-e2e.yml` 패턴 | 워크플로 로그: 200, 로그의 actor/bind DN |
| `AC-002` | 단위(순수 claim 검증기 + 로컬 JWKS `httptest` 서버, 생성 RSA/EC 키로 서명·변조·HS256 혼동 토큰) + e2e 음성(실제 Keycloak: ID token, SSO client 토큰, **같은 client의 password-grant 사람 토큰**, aud `account`-only, 만료) | go test; e2e | 케이스별 401 표와 양성 대조 200, bind 카운터 0 |
| `AC-003` | 단위(scope 해석 순수 함수) + **런타임 가드 전수 테스트**(합성 보호 GET을 allowlist 없이 등록 → 403·bind/핸들러 0, 등록된 보호 45개 전수 호출) + e2e | go test; e2e | 허용 8 / 거부 37 표, 합성 라우트 403 |
| `AC-004` | 단위(거부 37개 전수 테이블) + 계약 테스트 + e2e 샘플 | go test; e2e | 37/37 거부 |
| `AC-005` | e2e: non-admin 과권한 bind + 시드한 비밀 값(비밀번호 변경이 남긴 accesslog `reqMod` 포함); 응답 전수 값 grep; 단위: 감사 DTO가 `reqMod` 값을 내지 않음, 기존 redaction 회귀 | e2e; go test | 비밀 값 0건, accesslog/config/monitor DN 403 |
| `AC-006` | 단위(`selectAuth` 13행 표) + e2e 혼용·Origin·CORS preflight | go test; e2e | 표의 상태 코드, `Set-Cookie` 부재 |
| `AC-007` | e2e 2회(LDAP 모드/SSO 모드) + 기존 로그인 회귀 | docker compose 2구성 | 두 모드 통과 로그 |
| `AC-008` | 단위(fake clock + 계수 JWKS 서버: TTL/stale/backoff 표 전 행) + e2e(Keycloak 중지 후 캐시 hit/miss) | go test; e2e | 200/401/503 표, `Retry-After` |
| `AC-009` | 단위(config 검증: 중복 DN 변형·rootdn·필수값·`UI_TRUSTED_PROXIES`) + e2e(bind 실패, 느린 LDAP/deadline, 연결 끊김 후 슬롯 반환) | go test; e2e | 기동 오류 메시지, 503, 슬롯 수 복귀 |
| `AC-010` | 단위(`buildMachineEvent`·reason enum·조기 반환 표: 각 1줄) + **e2e 전 컨테이너 로그 secret scan**(토큰·서명 조각·secret·bind 비밀번호) | go test; e2e | 줄 수 표, 검색 0건 |
| `AC-011` | 단위(bounded limiter, 주입 `now`, 순서: 검증기 호출 카운터) + e2e 실제 동시성·위조 XFF | go test; e2e | 429+`Retry-After`, 예산 격리, 상태 크기 상한 |
| `AC-012` | 단위(주입 `now`, 실제 서명 검증기 경유 경계 표) + e2e 만료 후 거부 | go test; e2e | 경계 표 |
| `AC-013` | 계약 테스트 확장 | go test | 스펙↔allowlist 일치(8/37) |
| `AC-014` | 기존 CI 전체 + bearer 무시 단위 테스트 | CI | 기존 e2e 무변경 통과 |
| `AC-015` | 단위(DN 정규화·BASE_DN 가드, `MonitorStats` 로그 포함 여부) + e2e(accesslog/config/Monitor DN, 가드 끈 빌드의 ACL 백스톱) | go test; e2e | 403 표, accesslog 검색 미발행 |
| `AC-016` | 단위(계수 서버, fake clock: 폭주 시 조회 ≤ 1+⌈T/30s⌉, 크기·키 수·리다이렉트·timeout) + e2e(계수 프록시 뒤 실제 Keycloak 회전·폭주) | go test; e2e | 조회 횟수 표 |
| `AC-017` | 단위(`cursorBinding` 도메인 분리) + e2e(client 2개, 사람 cursor, 토큰 갱신) | go test; e2e | 400/200 표 |
| `AC-018` | e2e: 머신 DN으로 slapd에 직접 쓰기·자기 수정·비밀 읽기 시도 + 타 신원 불변 | 컨테이너 e2e | 50 거부 로그, 타 신원 회귀 통과 |
| `AC-019` | 롤아웃 드릴(2 replica Helm 또는 compose 2개): 비활성화 후 구토큰 통과 → allowlist 제거 전 replica 교체 후 401 → rollback | e2e/드릴 | 단계별 응답 표, 이전 pod 0개 |

단위/정적(순수 함수·계약)과 라이브 e2e를 구분한다. LDAP wire 코드는 저장소 원칙대로 단위 테스트하지 않고 e2e로만 검증하며 모킹 프레임워크를 도입하지 않는다.
JWKS 검증은 외부 모킹 없이 로컬 `httptest` 서버가 실제 JWKS를 서빙하는 방식으로 단위 검증한다.

## Rollout, rollback and recovery

- Rollout sequence: (1) 수용·ADR → (2) 설정·순수 헬퍼·계약 테스트(기능 꺼짐) → (3) 인증기·라우팅 가드 → (4) e2e → (5) 문서·차트 → (6) 스테이징에서 전용 client·ACL로 활성화 → (7) 릴리스 노트. 모든 단계에서 기본 꺼짐.
- Rollback trigger and procedure: 예기치 않은 401/403 오분류, 권한 노출 의심, JWKS 장애 파급 시 `MACHINE_AUTH_ENABLED=false`(Helm `ui.machineAuth.enabled=false`) 후 재배포하고 **모든 replica 교체 완료·이전 revision pod 0개·진행 중 요청 종료**를 확인한다(롤아웃 중에는 일부 replica가 아직 bearer를 받는다). 코드 롤백 없이 기능 정지. 롤백 후 기존 쿠키 e2e 무변경 통과(AC-019).
- Data/configuration recovery: 영속 데이터 없음(토큰·키 미저장). 머신 LDAP 계정은 운영자가 삭제/비활성화. **긴급 차단의 1차 수단은 서버측 allowlist 제거/기능 끄기(D7)**이며 Keycloak client 비활성화·secret 회전은 새 토큰 발급을 막는 보조 수단이다(이미 발급된 JWT는 비활성화 후에도 만료까지 유효 — 관측).
- 병합 단위(수용 후): 모든 단위가 기능 꺼짐 상태로 병합된다 — S1 config·계약 골격·순수 검증기(T-010/011/014/019) → S2 `selectAuth`·가드·감사·limiter(T-012/017/018/041) → S3 실행 신원·경계 가드(T-013/040) → S4 ACL 가이드·Helm(T-015/016) → S5 e2e·CI·release 게이트(T-021/022/024–027) → S6 문서·릴리스 노트(T-030–033). 활성화는 S5 통과 후 스테이징에서만.
- Compatibility or migration obligations: 기존 경로·쿠키·응답 불변. OpenAPI는 additive(`securitySchemes`, `x-machine-scope`)이며 기존 오퍼레이션의 `cookieAuth`는 유지.

## Evidence and durable synchronization

- Evidence location/format: 구현 시 `research/README.md` 규약에 따른 기록(테스트·e2e 결과, 실패 포함). e2e 로그는 CI 아티팩트.
- Tests or checks that become durable regression controls: 허용/거부 전수 계약 테스트, `selectAuth`·claim 검증기·scope 해석 단위 테스트, 신규 e2e 워크플로, 기동 시 설정 검증.
- Documentation to update: `docs/api.md`(인증 절·머신 호출 예), `docs/auth-provider-policy.md`, `docs/audit-event-schema.md`(`machine_access`), `ui/README.md`, `charts/ldapium/README.md`, `docs/air-gap.md`, 이 패키지.
- ADR/evidence/portfolio records to update: ADR 신규, [IMPLEMENTATION-STATUS](../../IMPLEMENTATION-STATUS.md), 포트폴리오 상태(해당 시).

## Traceability matrix

| Requirement | Acceptance | Task | Evidence |
|---|---|---|---|
| `REQ-001` | AC-001, AC-002 | T-010, T-011, T-019, T-020, T-021 | 검증기 단위·e2e 음성 표(양성 대조 포함), [EVIDENCE §2](EVIDENCE.md) |
| `REQ-002` | AC-001, AC-003 | T-012, T-024, T-020, T-021 | scope 해석 테스트, 가드 전수 호출 8/37, 합성 라우트 403 |
| `REQ-003` | AC-004, AC-013 | T-012, T-014, T-024 | 거부 37개 전수, 계약 테스트 |
| `REQ-004` | AC-001, AC-009, AC-018 | T-010, T-013, T-015, T-026 | 기동 검증(ParseDN 변형), bind DN 로그, 쓰기 시도 거부 |
| `REQ-005` | AC-005 | T-040, T-021 | non-admin 과권한 bind e2e, 값 grep |
| `REQ-006` | AC-006 | T-012, T-020, T-021 | `selectAuth` 13행 표, Origin·CORS·혼용 e2e |
| `REQ-007` | AC-007 | T-021 | 2모드 e2e |
| `REQ-008` | AC-008, AC-009 | T-011, T-013, T-019, T-021 | 503 표, 기동 실패 |
| `REQ-009` | AC-001, AC-010 | T-017, T-020, T-021 | 줄 수 표·로그 secret scan |
| `REQ-010` | AC-011 | T-018, T-020, T-021 | limiter 단위(순서·상한), 429 e2e, 위조 XFF |
| `REQ-011` | AC-002, AC-012 | T-011, T-020 | 실제 서명 검증기 경유 경계 표 |
| `REQ-012` | AC-013 | T-014, T-020 | 계약 테스트 |
| `REQ-013` | AC-014, AC-019 | T-015, T-016, T-021, T-027 | 기존 CI 통과, 차트 렌더, 롤백 드릴 |
| `REQ-014` | AC-010 | T-017, T-021 | 로그·응답 grep |
| `REQ-015` | AC-005, AC-015 | T-040, T-021 | accesslog/config/Monitor 403 표, 로그 미발행 |
| `REQ-016` | AC-008, AC-016 | T-010, T-019, T-025 | 조회 횟수 표, https 기동 검증 |
| `REQ-017` | AC-017 | T-041, T-021 | cursor 교차 재생·갱신 후 연속 |
| `REQ-018` | AC-019 | T-027, T-030, T-032 | 롤아웃 드릴 표, 운영 문서 |

## Review record

- Accepted scope/requirements: 없음 — 수용 대기. 2026-10-07 유지보수자 지시('승인 후 구현까지')는 Revision 2의 재검토 통과 후 수용·단계 병합으로 이행한다. T-005 1차 독립 보안 검토(Codex)는 BLOCKER였고 Revision 2가 이를 반영했다.
- Material changes after acceptance and re-review: 해당 없음.
- Open questions or blockers: Q1–Q10은 2026-10-04 유지보수자 지시("열린 질문 권장으로 처리")로 권고안 채택(Revision 2에서 뒤집힌 것 없음, Q5·Q9·Q10에 주석). 아래 결정 표 참조. 패키지 자체의 수용(Accepted)은 별도 검토가 필요하며 구현은 그 이후에 시작한다.

### Resolved questions (2026-10-04, 유지보수자 지시: 권고안 채택)

수용 전 검토에서 뒤집을 수 있다. 각 항목의 "뒤집을 때" 비용은 권고 당시 "결정 지연 시 영향"과 같다.

| ID | 결정 | 반영 위치 |
|---|---|---|
| Q1 | 옵션 1(Keycloak bearer)만 v1. 옵션 2(해시 API 키)는 수요가 확인되면 별도 패키지 | D1 |
| Q2 | 머신 전용 LDAP 계정은 운영자 수동 생성 + 문서에 LDIF 예시. image 시드·차트 옵션 제외. ACL 변경은 Class D이며 `ldapium-directory-change` 스킬 대상 | T-015 |
| Q3 | 기존 경로 공용(D2) + 순수 함수 `selectAuth`. 격리 우려가 커지면 `/api/v1/machine/...` 복제로 전환 | D2 |
| Q4 | LDAP 모드도 지원. 별도 `MACHINE_OIDC_ISSUER_URL` 필요, e2e에 LDAP 모드 구성 포함 | D11 |
| Q5 | client별 subtree/base DN allowlist는 v1 제외. LDAP ACL을 백스톱으로 두고 후속 패키지에서 다룬다. **Revision 2: 결정 유지**, 단 전역 `BASE_DN` 한정과 accesslog·config·Monitor 제외는 allowlist가 아니라 보안 경계로 추가(D14) | Non-goals, 위협 모델, D14 |
| Q6 | 머신용 whoami는 v1 제외, `getMe`는 세션 의미 유지 | 분류 표 |
| Q7 | opt-in scope(`audit.read`, `server.settings.read`)는 포함하되 기본 비허용(서버 상한에서 명시적으로 켠 경우만) | D3 |
| Q8 | 신규 e2e를 release 필수 체크로 지정. path 필터 금지(이전 릴리스 교훈), 3레인 약 20분 증가 수용 | Change impact |
| Q9 | 현재 `openapi.json` 집계를 기준으로 사용. "39"는 경로 수였다. **Revision 2: 결정 유지, 수치 갱신** — `jq` 재집계 53개(공개 8·보호 45); 초안의 48/40은 5개 누락 | Problem, 분류 표 |
| Q10 | 토큰 TTL 10분 수용. 즉시 폐기용 introspection은 후속. **Revision 2: 결정 유지**; 관측상 Keycloak 기본 TTL은 300s이고 MAX_TTL은 상한일 뿐이며 상한 범위 (0,1h]를 추가 | AC-012, D7 |

잔여 차단 사항: 위 결정으로 설계 질문은 닫혔지만, 이 패키지는 여전히 `Proposed / awaiting review`다.

## Revision 2 (2026-10-07)

T-005 독립 보안 검토(Codex, 총평 BLOCKER, 7개 영역)와 [EVIDENCE.md](EVIDENCE.md)(실제 Keycloak 26.7.4 관측 + 코드 읽기)를 반영했다. 상태는 `Proposed / awaiting review`로 유지하며 재검토가 남았다. 코드 읽기 결과는 Gemini 워커의 재집계를 코드·`openapi.json`과 대조해 사용했고, 대조하지 못한 핸들러 file:line은 옮기지 않았다(EVIDENCE §1). 검토의 file:line 지적 중 `config.go:562`(원격 http 허용), `monitor.go:98`, `tree.go:117`, `cursor.go:67`, `login_limiter` 무상한은 코드에서 직접 확인했다.

### 지적 → 처리

| # | 지적 (영역, 검토 판정) | 처리 | 위치 · 검증 |
|---|---|---|---|
| 1a | 토큰 종류·SA 판별이 검증 불가 문구, 같은 client 사람 토큰 (FIX-IN-PACKAGE) | JOSE `typ`·payload `typ`=`Bearer`·SA 판별(`sid` 부재, `preferred_username`) 고정. 관측: 같은 client 사람 토큰은 `aud`/`azp`/`scope`가 동일 | D5 표, AC-002 · T-011, T-021 |
| 1b | `azp`/`client_id` 우선순위·불일치, alg 목록, ID/SSO 토큰 | 둘 다 필수·동일, alg 기본 `RS256,ES256`+`SupportedSigningAlgs`, ID(`typ=ID`)·SSO client 거부 | D5 표, AC-002 · T-011 |
| 1c | `iat`·`exp<=iat`·MAX_TTL·skew 범위 | 필수 숫자 규칙·`exp>iat`·MAX_TTL (0,1h]·skew 0–60s 기동 검증 | D5 표, AC-012 · T-010, T-011 |
| 1d | go-oidc nbf 5분 leeway | `SkipExpiryCheck:true`+자체 시간 검증(nbf 검사가 그 블록 안임을 소스·관측으로 확인), 실제 서명 검증기 경유 경계 테스트 | D5 표, AC-012 · T-011 |
| 1e | audience mapper·`account` 거부 | 관측 반영: 기본 `aud="account"` 문자열, mapper 후 배열; 정확 멤버십, mapper 설정 예와 전용 scope 요건 | D5 표, EVIDENCE §2.2 · T-021, T-030 |
| 2a | HTTPS 주장이 현 코드와 다름 (BLOCKER) | 머신 전용 https 검증(D15), 예외 `MACHINE_OIDC_INSECURE_HTTP`+WARN, SSO 검증은 불변 | D15, AC-016 · T-010 |
| 2b | JWKS 재조회 증폭·TTL·timeout | 커스텀 KeySet, TTL/stale/최소 간격/backoff/negative cache/크기·timeout 수치 | D8, AC-008, AC-016 · T-019, T-025 |
| 2c | 401 vs 503, `Retry-After` | AC-008 표로 고정 | AC-008 · T-019 |
| 3a | Authorization 문법·쿠키 혼용 | 13행 `selectAuth` 표, 폴백 금지 | 인증 경로 분리 규칙, AC-006 · T-012 |
| 3b | 공개 auth 경로·`Set-Cookie` | 4개 쿠키 경로에서 bearer 400, 나머지 공개는 무시, 보호 경로 쿠키 미발행 | 표 11–12행 · T-012 |
| 3c | Origin gate 순서·CORS | gate 최외곽 불변, CORS `Authorization` 비허용 회귀 | 미들웨어 순서 · T-012, T-021 |
| 4a | 53개 vs 48개, 누락 5개 (BLOCKER) | 분류 재작성: 허용 8 / denylist 36 + `getMe`. `jq`로 확인 | 분류 표, EVIDENCE §1 |
| 4b | `getMonitor` accesslog 노출 (BLOCKER) | `audit.read` 없으면 accesslog 검색 미발행·`recentLogs` 비움 | D14(b), AC-015 · T-040 |
| 4c | `getEntry` 임의 DN·`reqMod` 비밀 값 (BLOCKER) | 머신 한정 BASE_DN 가드(ParseDN), accesslog/config/Monitor 불가, 핸들러 불변 조건 완화 명시 | D14(a)(c), AC-015, Change impact · T-040 |
| 4d | 계약 테스트만으로 가드 증명 불가 | 런타임 deny-by-default 가드+합성 라우트·전수 호출 | D13, AC-003 · T-012, T-024 |
| 5a | rootdn 식별·DN 비교 | `MACHINE_LDAP_ROOT_DNS` 필수 입력, `ParseDN` 동등 비교와 변형 테스트 | D4, AC-009 · T-010, T-013 |
| 5b | ACL 읽기 전용 증명 | 머신 규칙을 `by self write` catch-all 앞에, `by * break` 구조, 쓰기 시도 거부 e2e | 머신 LDAP 계정·ACL, AC-018 · T-015, T-026 |
| 5c | timeout·동시성·결과 상한·bind 실패 | bind 전 비차단 슬롯, 요청 deadline 10s, 결과 상한, defer 해제, 503 | D4, D9, AC-009 · T-013, T-021 |
| 5d | cursor 바인딩, SESSION_SECRET 충돌 | issuer+client 안정 바인딩·도메인 분리, D4 문구 변경(키는 무결성 키라 공유) | D16, AC-017 · T-041 |
| 6a | 남용 제한 순서·상태 상한 | ①–⑥ 순서와 모든 상태 상한, `loginLimiter` 비재사용 | D9, AC-011 · T-018 |
| 6b | XFF 위조 | `UI_TRUSTED_PROXIES` 기본 `private` 금지, ingress 정리 요구, 위조 XFF 테스트 | D9, AC-011 · T-010, T-018 |
| 6c | 감사 actor 모순·조기 반환·원문 오류 | 검증 전 `unknown`+fingerprint, 검증 후 actor, 조기 반환 1줄, reason enum | D10, AC-010 · T-017 |
| 7a | AC-005 | non-admin 과권한 bind, 비밀 **값** 부재, accesslog DN·monitor·groups·cursor 포함, 이름 `userPassword`는 허용 | AC-005 · T-021 |
| 7b | AC-008 수치·“다른 client 영향 없음” | TTL 수치·만료 후 동작, 격리 범위를 limiter 예산으로 축소 | AC-008, AC-011 |
| 7c | client 비활성화≠JWT 폐기 | 긴급 경로를 allowlist 제거/기능 off+전 replica 교체+진행 요청 종료로 재정의, 관측 반영 | D7, AC-019, Rollback · T-027, T-030 |
| 7d | live e2e·CI·release 이름 | e2e 항목 확장(JWKS 회전·폭주, scope 우회, proxy·Origin, cursor, rollback, secret scan, 실제 동시성), `release.yml` `release_critical` 배열에 정확한 job 이름 추가·동일 SHA 성공 | Verification plan, Change impact · T-021–T-027 |

### 결정 변경 (Q1–Q10 외)

- D4: “`SESSION_SECRET` 무관” → “머신 인증·bind 자격에는 쓰지 않음, cursor MAC 키는 공유”(D16 충돌 해소).
- D2: Bearer **존재** 기준 → `Authorization` **헤더 존재** 기준(잘못된 값도 쿠키로 폴백 안 함).
- D7: “재시작/리로드 후” → v1은 리로드 없음, 롤아웃만.
- D9: client별 limiter 위주 → 검증된 client에만 적용, IP throttle은 서명 이전.
- 핸들러 본문 불변 목표 → 머신 한정 가드·`MonitorStats` 인자·ldapclient deadline 변경 허용(Change impact).

### 미결 (구현 단계에서 확정, 수용을 막지 않음)

- `listTree`가 머신 경로에서 자식 수 상한을 넘을 때의 응답(DTO에 additive `truncated`를 둘지 거부할지)은 T-013에서 현 DTO를 확인한 뒤 같은 PR에서 이 문서에 반영한다. 사람 경로 응답은 바꾸지 않는다.
- 기존 `loginLimiter`의 무상한 맵(사람 로그인 경로)은 머신 범위 밖이며 별도 이슈로 보고한다(T-018).
