# Change: 외부 HTTP API용 머신 주체(서비스) 인증 — 읽기 전용 범위

- Change class: `D` — 인증·인가 경계 추가, 신규 자격 증명 수용 경로
- Owner: 유지보수자 dasomel(수용자와 동일; 2026-10-07 close-out 감사에서 확정)
- Related issue: [#214](https://github.com/dasomel/ldapium/issues/214)(열림; 닫기는 close-out 감사 병합 후 유지보수자 결정) — 출처 [api-integration PLAN P0](../api-integration/PLAN.md)
- Status: `Accepted (2026-10-07; Revision 5; staged implementation, default off)`
- Revision 2 (2026-10-07): addresses T-005 security review round 1 (BLOCKER).
- Revision 3 (2026-10-07): addresses T-005 round 2 (ACL order, rootdn list syntax, service-account identification, JWKS state machine, selectAuth precedence, IP throttle numbers); re-review pending; acceptance by the maintainer instruction of 2026-10-07 follows a passing re-review
- Revision 5 (2026-10-07): precision fixes from T-005 round 4 (test model, budget bound, response split, selectAuth wording, ACL verification sync); re-review pending
- Revision 4 (2026-10-07): addresses T-005 round 3 (JWKS state table, duplicate-cookie behaviour, IP throttle reservation/boundaries, ACL readback); re-review pending
- Accepted by / date: dasomel / 2026-10-07 — 근거: 유지보수자(사용자) 지시('승인 후 구현까지', 2026-10-07)와 독립 Codex 보안 재검토 5라운드(1라운드 BLOCKER → Revision 2–5 반영 → 최종 확인 PASS). 수용 범위는 **설계(v1 읽기 전용, 기본 꺼짐)**이며 구현은 TASKS.md 순서대로 단계 병합한다. 각 구현 PR은 Class D로 독립 검토를 받는다. 코드 수준 항목(ACL 적용 후 `olcAccess` 읽기 확인, 라이브 e2e 등)은 해당 task의 완료 조건이다.
- 작성일: 2026-10-04 (Revision 2: 2026-10-07)

> 이 문서는 수용된 설계 정본이다(구현은 2026-10-07 수용 이후 기본 꺼짐으로 단계 병합됨). 본문(Problem, Requirements, Architecture 등)은 수용 시점의 설계 서술이고,
> **구현·검증 상태의 정본은 아래 "Traceability matrix"와 끝의 "Close-out audit (2026-10-07)"** 이다. Keycloak 토큰·JWKS 거동과 오퍼레이션 집계는
> 2026-10-07에 실제 Keycloak 26.7.4 실행과 코드 읽기로 확인해 [EVIDENCE.md](EVIDENCE.md)에 기록했다(T-001, T-004). Revision 2의 변경 요약은 끝의 “Revision 2” 절.

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
- `REQ-009` — `Authorization`을 실은 모든 요청(허용·거부·조기 반환 포함)을 구조화 로그 한 줄로 남긴다. actor는 **검증을 통과한 client id**만이고 미검증 claim은 actor로 쓰지 않는다. 토큰·비밀·원문 verifier 오류는 남기지 않는다. **예외(D25)**: Go HTTP 서버가 핸들러 실행 전에 거부한 요청(헤더 초과 431, 요청 줄 형식 오류 400, TLS 실패)은 애플리케이션에 도달하지 않아 이 줄이 없다. 그 요청은 서버/ingress의 접근·오류 로그에만 남는다.
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
  `aud`에 `account`만 / `aud` 누락·null·숫자 배열 / 만료(skew 초과) / 서명 변조 / 알 수 없는 `iss`(후행 슬래시 차이 포함) / ID token(payload `typ=ID`, SA가 `scope=openid`로 받은 것) / refresh token / JOSE `typ` 누락·`JWT`·`at+jwt` 외 / payload `typ`≠`Bearer` / `kid` 누락 / 허용 목록 밖 `azp` / `azp`≠`client_id` / `client_id` 누락 / SSO 브라우저 client(`ldapium-sso`)의 access·ID token / **허용 client에서 password grant로 발급된 사람 토큰**(`client_id` 없음, `preferred_username`≠`service-account-<client>`; `sid`는 판정에 쓰지 않음) / **exchange로 만든 토큰**(사람 subject·SA subject 둘 다, `client_id` 없음) / **lightweight access token** / `service_account`·`profile` scope 제거로 `client_id` 또는 `preferred_username`이 없는 토큰 / `preferred_username`이 같지만 `client_id`가 없는 토큰 / `iat` 누락·비숫자·미래(skew 초과) / `exp<=iat` / `exp-iat` > MAX_TTL / `nbf` 미래(skew 초과) / `alg=none` / HS256(JWKS 공개키를 HMAC 키로 서명) / 허용 목록 밖 alg(예 RS512) / 8 KiB 초과 토큰
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

### `AC-006` — 쿠키/bearer 혼용·`selectAuth` 매트릭스

- Covers: `REQ-006`
- Given “인증 경로 분리 규칙”의 매트릭스 전 셀(경로 P/PA/PO/N × Authorization A0/AV/AI/AD × 쿠키 C0/CV/CI/Cp)과 기능 꺼짐, 그리고 Origin 조합(foreign·`null`·중복·없음 × POST/GET)
- When 해당 요청 호출
- Then 각 셀이 표의 단일 결과와 일치한다. Authorization이 없는 요청의 중복 `ldapium_session` 쿠키는 **기존과 동일**하다([유효, 무효]=200, [무효, 유효]=401: 첫 쿠키만 읽음, 회귀 테스트). **보호(P) 경로에서, 앞선 게이트(Origin gate 403 등)를 통과한 뒤** 형식이 틀리거나 중복된 `Authorization`은 쿠키 인증으로 폴백하지 않고(401; 그 밖 경로 분류와 우선순위는 매트릭스가 정본), 유효 bearer+쿠키 이름 존재는 400, PA 경로의 Authorization은 400이며 쿠키가 발행·삭제되지 않고, 머신 요청은 `Set-Cookie`를 발행하지 않는다. 상태 변경 메서드에 foreign/`null`/중복 `Origin`이 있으면 bearer가 유효해도 gate의 403이 우선하고 핸들러가 실행되지 않는다. **GET은 gate 대상이 아니므로** foreign `Origin`이어도 유효 bearer GET은 200이다(CORS 헤더 부재로 브라우저 읽기는 막힘). preflight `authorization`은 거부.

### `AC-007` — 모드 독립

- Covers: `REQ-007`
- Given `SSO_ENABLED=false`(LDAP 모드)와 `true`(SSO 모드) 각각 + 머신 인증 활성
- When 머신 토큰으로 허용 오퍼레이션 호출 및 기존 로그인 회귀 시나리오 실행
- Then 두 모드 모두 AC-001 통과, `/api/login`·SSO 콜백 동작 불변.

### `AC-008` — JWKS/발급자 장애 시 fail closed

- Covers: `REQ-008`, `REQ-016`
- Given Keycloak 중지 또는 JWKS 응답 불가, 주입 가능한 시계. 기본값: JWKS 캐시 TTL 10m, stale-if-error +1h, 최소 재조회 간격 30s, fetch timeout 5s, 실패 backoff 30s→최대 5m
- When “JWKS·discovery 상태 기계”(D8 정본)의 7개 행과 시나리오 a–h를 fake clock으로 재현하고, (i) Keycloak 중지 상태에서 ldapium 기동 → Keycloak 기동(e2e)
- Then 표의 응답·`Retry-After`·**조회 횟수**와 정확히 일치한다: a=10건(t=30…300), b=0, c=1 후 0, d=5건(t0·+30·+90·+210·+450), e 경계(age=TTL+MAX_STALE 200 / +1s 조회·503), f 시도 t=0·30·90·210 후 재시작 없이 200, g t=29 401·0건 / t=30 200·1건, h 503+`Retry-After`=30. 새 키 거부 상한 30s는 표에서 도출한 값(`S+MIN`)으로 검증하며 별도 단언 테스트를 두지 않는다. 어떤 경우도 검증 생략 허용이 없다.

### `AC-016` — JWKS 폭주·전송 제한

- Covers: `REQ-016`
- Given 로컬 `httptest` JWKS 서버(조회 횟수 계수)와 live Keycloak 앞의 계수 프록시
- When (a) 무작위 kid 토큰 1000건, (b) 알려진 kid + 잘못된 서명 1000건을 동시에 보냄 (c) 키 회전 (d) 응답 크기 1 MiB 초과·키 21개 이상·리다이렉트·5초 초과 지연 (e) `http://` 원격 issuer 설정
- Then (a)(b) upstream 조회 횟수는 상태 기계 시나리오 a·b·c·d의 정확한 값(단위, fake clock)이고 e2e는 닫힌 구간 [t0, t0+T]에서 조회 시작이 1+⌈T/30s⌉ 이하임을 확인, 응답은 상태 기계 표의 조건별 단일 규칙을 따른다(정상 조회 후 미지 kid=401, 조회 실패·backoff=503+`Retry-After`; 알려진 kid의 위조 서명=401)이며 negative cache(≤256 kid, 만료=삽입 시점의 `R`, 조회 완료마다 비움)가 상한을 넘지 않는다. (c) 새 kid 토큰은 `R`(마지막 성공 + 30s) 이후 첫 요청에서 200이며 그 전은 401(시나리오 g, 문서화된 비용). (d) 조회 거부·기존 캐시 유지·503. (e) 기동 실패(로컬 테스트 예외 플래그 없이), 플래그가 있으면 기동 시 WARN 로그.

### `AC-009` — 설정 오류·bind 실패 fail closed

- Covers: `REQ-004`, `REQ-008`
- Given 머신 bind DN이 `BACKUP_ADMIN_DNS`/프로파일 관리자 DN/`LDAP_SERVICE_ACCOUNT_DN`/메인 rootdn(`MACHINE_LDAP_ROOT_DNS`, `cn=admin,dc=example,dc=org`처럼 쉼표가 있는 DN 포함)/내장 rootdn 3종과 ParseDN 동등(대소문자·공백·escape·`\3B`·다중값 RDN 순서 변형 포함), `MACHINE_LDAP_ROOT_DNS`에 쉼표로 이어 쓴 값·파싱 불가 항목 / aud 미설정 / `UI_TRUSTED_PROXIES`가 기본 `private` / bind 비밀번호 불일치 / LDAP 응답 지연
- When 서버 기동 또는 요청
- Then 중복·필수값 누락·파싱 불가 DN은 기동 실패, bind 실패는 503 `unavailable`이며 root 폴백 없음. 지연은 `MACHINE_REQUEST_TIMEOUT`(기본 10s) 안에 503으로 끝나고 슬롯이 반환된다.

### `AC-010` — 감사 추적

- Covers: `REQ-009`, `REQ-014`
- Given 허용 / 검증 실패 / 검증 후 scope 거부 / 검증 후 rate limit / bind 실패 / 조기 반환(`selectAuth` 거부, Origin gate 거부, 혼용 400, 404, IP throttle 429, JWKS 503) 각 1건 이상
- When 로그 확인
- Then `Authorization`을 실은 요청마다 정확히 한 줄이 있고 `event`, `provider`, `actor`, `request_id`, `operation`, `result`, `reason`(고정 enum) 필드를 가진다. `actor`는 서명·claim 검증을 통과한 client id만이고 그 전 단계 실패는 `actor=unknown`+토큰 fingerprint(SHA-256 앞 6바이트)다. 검증 후 scope 거부·limiter·bind 실패는 actor를 기록한다. 토큰·서명 조각·client secret·bind 비밀번호·원문 `Authorization`·go-oidc/go-jose 원문 오류 문자열은 어느 로그·응답에도 없다. live e2e는 모든 컨테이너 로그를 이 값들로 grep해 0건을 확인한다.

### `AC-011` — rate limit·동시성

- Covers: `REQ-010`
- Given 검증된 client별 한도 N rps/burst, client별·전역 동시 M, IP 실패 throttle(기본 한도 10 / 윈도우 1m, 주입 가능한 시계)
- When (a) 한 client가 한도 초과 (b) 다른 client가 동시에 호출 (c) 서로 다른 수만 개 IP에서 무효 토큰 1회씩 (d) 아래 경계 표 (e) 위조 `X-Forwarded-For`
- Then (a) 초과분 429 `machine_rate_limited` + `Retry-After`. (b) **limiter 예산은 격리**된다 — 한 client의 소진이 다른 client의 token bucket을 줄이지 않는다(LDAP·JWKS·전역 동시성 같은 공유 자원의 격리는 보장하지 않으며 문서에 명시). (c) IP limiter 항목 수가 `MACHINE_IP_LIMITER_MAX`(기본 10000)를 넘지 않고 프로세스 메모리가 유계(#270 수정 구현). (e) 신뢰 프록시 밖 피어의 XFF는 무시되고, `UI_TRUSTED_PROXIES`가 `private`(기본)이면 머신 활성 상태에서 기동 실패. unknown client는 limiter 상태를 만들지 않는다.
- (d) IP 실패 throttle 경계(N=10, W=60s, 시간 해상도 1ms):

  | 시나리오 | 기대 |
  |---|---|
  | 실패 N−1=9회 후 10번째 요청 | 통과해 검증기까지 도달(401로 실패 10회째 기록) |
  | 실패 N=10회 후 11번째 요청 | 429, 검증기 호출 카운터 불변(서명·JWKS 조회 없음), `Retry-After`=`max(1, ⌈60−나이⌉)` |
  | N+1: 429를 받은 뒤 추가 요청 반복 | 429는 실패로 세지 않아 카운터가 10에 머묾; 윈도우가 지나면 풀림 |
  | **정확히 60s**: 가장 오래된 실패가 t0, 요청이 t0+60.000s | 아직 센다 → 429, `Retry-After: 1` |
  | 60s+1ms: 요청이 t0+60.001s | 그 실패는 빠져 9회 → 통과 |
  | 실패가 0회인데 예약이 한도(10)를 채움(동시 10건 진행 중) | 11번째 동시 요청은 429, `Retry-After: 1`(고정) |
  | 같은 IP에서 무효 토큰 20건 동시(실패 0회 상태) | 정확히 10건만 검증기 도달, 10건 429(`Retry-After: 1`) |
  | 예약 해제: 동시 10건이 각각 ①성공 ②JWKS 503 ③클라이언트 끊김 ④핸들러 panic ⑤scope 403으로 끝남 | 각각 끝난 뒤 예약 0·실패 0(①②③④⑤ 모두 카운터 불변), 곧바로 10건 더 통과 |
  | 401로 끝난 요청 | 예약이 실패로 확정되어 실패 수 +1, 예약 수 −1 |
  | 해제 누락 주입(예약만 하고 반납 안 함) | 10s(`MACHINE_REQUEST_TIMEOUT`) 후 자동 만료, 그 전에는 동시 한도에 포함 |
  | 유효 토큰 성공 | 카운터 불변(초기화도 가산도 없음); 실패 10회 상태의 IP에서는 유효 토큰도 429 |
  | 403(scope)·503(JWKS)·429 응답 | 실패로 세지 않음 |
  | 서로 다른 IP | 서로 영향 없음(IPv6는 같은 /64를 한 키로) |

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
- Given 위 LDIF를 **새로 초기화한 컨테이너 세 구성**에 적용: (a) `LDAP_ANONYMOUS_READ_BASE` 미설정, (b) 설정(예 `ou=people,<root>`), (c) 운영자 추가 선행 allow가 있는 구성. `B`=`ou=people,<root>`, `M`은 `ou=system`에 위치, 비교용으로 일반 사용자·관리자·익명 신원
- When 머신 DN으로 slapd에 직접: ① 자기 비밀번호 변경(`ldappasswd`, `ldapmodify`로 `userPassword`/`shadowLastChange`) ② 자기 항목의 일반 속성 수정 ③ 다른 항목 `ldapadd`/`ldapmodify`/`ldapdelete`/`modrdn` ④ `B` 밖 항목(예 `ou=system`, 루트, 다른 OU) base 검색(`(objectClass=*)`)과 `entry`/`uid`/`objectClass` 요청 ⑤ `B` 안 검색에서 `userPassword`·`shadowLastChange`를 명시 요청 ⑥ accesslog·config·Monitor 읽기
- 추가 구성 (c): 적용 전 운영자가 **선행 allow 규칙을 직접 추가**해 둔 DB(예 `{0}to attrs=description by users write`)에 같은 LDIF를 적용. 모든 구성에서 적용 직후 `olcDatabase={1}mdb,cn=config`의 `olcAccess`를 **읽어** 머신 규칙 3개가 `{0}`–`{2}`이고 기존 규칙(운영자 추가분 포함)이 그 뒤로 밀렸음을 확인한다(읽은 순서가 기대와 다르면 실패).
- Then ①②③은 모두 `insufficient access`(50), ④는 항목이 반환되지 않고(`noSuchObject`/빈 결과) 세 구성에서 동일, ⑤ `B` 항목은 반환되되 비밀 속성은 없음, ⑥ 거부(opt-in 미적용 상태). 같은 LDIF 적용 전후로 일반 사용자의 자기 비밀번호 변경(성공)·관리자·익명(구성 (a)/(b)/(c)별 기존 동작)의 결과가 변하지 않는다. `M` bind 자체는 성공한다.

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
- ADR threshold result: `required` — 신규 자격 증명 수용 경로, 신뢰 경계 확대, 정책 문서 예외. 수용 전 ADR 초안 필요(T-005). ADR: [ADR.md](ADR.md)(T-031에서 확정).

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
| D2 | 기존 경로(`/api/users` 등)에 인증기 선택 방식으로 얹는다: `Authorization` 헤더 **존재** → 머신 인증기만(문법이 틀리면 401, 쿠키로 폴백 없음), 없음 → 기존 쿠키 `requireSession`. 유효 형식 `Authorization`과 세션 쿠키가 함께 있으면 400(형식이 틀린 `Authorization`은 쿠키와 무관하게 401). 경로 복제 없음. 분류·우선순위·매트릭스는 아래 “인증 경로 분리 규칙” | 클라이언트·OpenAPI·SDK 변경 최소, 오퍼레이션 단일 정의 | 한 경로가 두 인증을 받아 테스트 매트릭스 증가, 선택 로직 버그가 곧 경계 약화 | 오퍼레이션 복제 `/api/v1/machine/...` 접두사(경로 분리가 더 강한 격리)로 전환 가능. 순수 함수 `selectAuth`로 격리해 단위 테스트(Q3) |
| D3 | scope는 서버 코드의 정적 `operation→scope` allowlist로만 해석(OpenAPI `x-machine-scope`와 1:1). client별 허용 scope 상한을 서버 설정에 두고, 유효 권한 = 토큰 scope ∩ 서버 상한. 미등록 오퍼레이션 기본 거부 | IdP 설정 실수(과다 scope 부여)가 곧바로 권한 확대가 되지 않게 함. “라우트 추가 시 자동 허용” 방지 | client 추가 시 ldapium 설정도 갱신 필요 | 상한을 `*`(토큰 scope 그대로)로 두는 모드는 두지 않음 — 필요 시 별도 결정으로 도입 |
| D4 | 실행 신원은 배포당 하나의 전용 읽기 전용 LDAP 계정(`MACHINE_LDAP_BIND_DN`). 요청마다 bind 후 종료. 기동 시 `BACKUP_ADMIN_DNS`·프로파일 관리자 DN·`LDAP_SERVICE_ACCOUNT_DN`·**rootdn**과 `ldap.ParseDN` 기반 동등성(문자열 비교 금지)으로 비교해 겹치면 실패. backend에는 rootdn 설정이 없으므로 활성 시 필수 입력 `MACHINE_LDAP_ROOT_DNS`를 신뢰 입력으로 쓴다: **세미콜론(`;`) 구분**(DN 내부에 쉼표가 있어 쉼표 목록은 `cn=admin,dc=example,dc=org`를 쪼개 실제 rootdn 충돌을 놓침 — `BACKUP_ADMIN_DNS`·`APP_PROFILES_ADMIN_DNS`와 같은 직렬화, `splitEntries` 재사용), 각 항목은 `ldap.ParseDN` 가능해야 하고 아니면 기동 실패, 항목 안의 리터럴 `;`는 RFC 4514 hex escape `\3B`로만 쓸 수 있음(분할이 파싱보다 먼저이므로), 빈 항목 무시·공백 제거·중복 제거. 이 이미지의 나머지 rootdn 3종(`cn=monitoring,cn=Monitor`, `cn=admin,cn=accesslog`, `cn=admin,cn=config`)은 **내장 금지 목록**으로 항상 비교하므로 운영자는 메인 DB rootdn(`LDAP_ADMIN_DN`, 기본 `cn=admin,<LDAP_ROOT_DN>`)만 넣으면 된다. Helm은 `ldap.adminDN`(기본 파생)에서 값을 만들고 `ui.machineAuth.extraRootDNs`로 추가할 수 있다(T-016). 읽기 전용은 **ACL이 강제**(머신 DN 규칙을 `by self write` catch-all 앞에 배치, “머신 LDAP 계정·ACL” 절)하고 실제 쓰기 시도로 증명. 실행 경계: 전역 LDAP 동시성 슬롯을 bind **이전**에 비차단으로 획득, 요청 전체 deadline(dial+bind+search, 기본 10s), 결과 상한, bind 실패 503(root 폴백 없음), 취소·패닉에서 슬롯·연결 반환. 머신 인증·bind 자격에 `SESSION_SECRET`을 쓰지 않는다(list cursor MAC 키는 HTTP 계층의 기존 `cursorKey`를 그대로 공유 — D16, **문구 변경**: 초안은 “`SESSION_SECRET` 무관”이라 cursor 키와 충돌했음) | 최소권한, 세션 저장소 무관, 연결 상태 없음(재연결 로직 부재 문제 회피) | 요청당 bind 지연, client별 신원 분리 불가(v1), rootdn 입력 설정 추가 | 연결 풀 도입, client→DN 매핑 설정 확장, subtree allowlist(Q5) |
| D5 | 검증 정책은 아래 “토큰 검증 정책” 표가 **정본**이다(JOSE·payload `typ`, `aud` 정확 멤버십, `azp`==`client_id`, SA 판별, 시간 규칙, alg allowlist). 요약: `iss` 정확 일치, 허용 client만, SSO 브라우저 client·ID/refresh·같은 client의 사람 발급 토큰 거부, 미검증 claim은 신뢰하지 않음 | audience confusion·ID token 오용·브라우저/사람 토큰의 머신 경로 재사용(confused deputy) 차단. 관측([EVIDENCE §2.3](EVIDENCE.md)): 같은 client의 사람 토큰은 `aud`·`azp`·`scope`가 SA 토큰과 동일 | Keycloak에 audience mapper·전용 client 설정 필요(운영 문서화), 자체 claim 검증 코드 | 허용 알고리즘을 설정화(비대칭 한정), claim 이름 설정화는 IdP 호환 필요 시 별도 결정 |
| D6 | v1은 GET 읽기 전용. 비-GET은 scope와 무관하게 거부 | 가장 작은 위험 표면, 쓰기는 idempotency·조건부 수정 계약(PLAN P1) 선행 필요 | 쓰기 자동화 불가 | 쓰기는 별도 Change Package(Class D) |
| D7 | 즉시 폐기 없음. 토큰 최대 수명 `MACHINE_TOKEN_MAX_TTL`(기본 10m, 허용 범위 (0, 1h], `exp-iat` 초과 시 거부), 시계 오차 `MACHINE_CLOCK_SKEW`(기본 30s, 범위 0–60s, 밖이면 기동 실패). **긴급 차단 경로**: ① `MACHINE_ALLOWED_CLIENTS`에서 제거 또는 `MACHINE_AUTH_ENABLED=false`로 배포(v1은 리로드 없음, 재시작/롤아웃만) → ② **모든 replica 교체 완료와 이전 revision pod 0개 확인**, 진행 중 요청 종료 확인(`terminationGracePeriodSeconds` ≥ `MACHINE_REQUEST_TIMEOUT`) → ③ 그 다음 Keycloak client 비활성화·secret 회전. Keycloak client 비활성화·secret 회전만으로는 이미 발급된 JWT가 차단되지 않는다(관측: 비활성화 후에도 사전 발급 토큰 검증 통과, [EVIDENCE §2.7](EVIDENCE.md)). ①을 하지 않은 최대 노출 = 남은 TTL + skew | 요청마다 introspection 호출은 IdP 의존·지연 증가 | 탈취 토큰이 최대 TTL+오차 동안 유효, 차단에 롤아웃이 필요 | introspection 옵션(`aud`에 있는 resource client 필요, 캐시·fail-closed) 후속 |
| D8 | JWKS: fail closed, **커스텀 `oidc.KeySet`** 사용(go-oidc `RemoteKeySet`은 알려진 kid의 잘못된 서명에도, 최소 간격 없이 재조회하므로 그대로 쓰지 않음). 모든 캐시·조회·응답 규칙은 아래 “JWKS·discovery 상태 기계”의 **한 개 표가 정본**이다: TTL 10m + `MAX_STALE` 1h, 조회 예산 게이트 `R`(성공 후 30s, 실패 후 backoff 30s→5m), negative cache는 kid 키·만료=삽입 시점의 `R`·≤256개·조회 완료마다 비움(결과를 바꾸지 않는 메모), fetch timeout 5s·응답 1 MiB·키 20개·리다이렉트 금지, `use=sig`(또는 미지정) 키·alg 일치 키만. 응답: 정상 조회 후 미지 kid 401, 조회 장애·backoff 중 미지 kid 또는 키 만료 503+`Retry-After`, 알려진 kid는 stale 한도 안에서 로컬 검증 | 서명 미검증 허용 금지. 임의/위조 토큰 폭주로 IdP를 때리는 증폭 방지(관측: 변조 토큰마다 조회 발생) | 키 회전 직후 새 kid 토큰이 마지막 조회 성공 후 30s까지 401(표에서 도출), IdP 장애 중 키 회전 직후 토큰 거부, stale 키가 IdP 키 제거 후 최대 1h10m 통용, 자체 KeySet 코드 | 캐시 TTL·최소 간격 설정화(범위 검증), 회전 시 overlap 운영 가이드 |
| D9 | 남용 제한 순서: ① `selectAuth` 문법·길이 검사(암호 연산 없음) → ② **IP 실패 throttle 조회(서명·JWKS 이전)** → ③ 전역 인증 동시성 슬롯(`MACHINE_MAX_AUTH_CONCURRENCY`, 기본 16, 비차단, 초과 시 503+`Retry-After`) → ④ 검증 → ⑤ **검증된 client에만** token bucket(rps/burst)·client 동시 실행 상한 → ⑥ 전역 LDAP 동시성(`MACHINE_MAX_CONCURRENCY` 전역, 기본 8) 슬롯을 bind 이전에 비차단 획득. **IP 실패 throttle 정의**: 키는 `c.RealIP()`(IPv6는 /64 묶음, #270과 동일). 실패 = 이 IP의 요청이 `selectAuth` 문법 거부 또는 토큰 검증에서 401(`token_invalid`/`token_expired`)로 끝난 것(403·429·503·취소는 세지 않음). 한도 `MACHINE_AUTH_FAILURE_LIMIT`=N=10회 / 슬라이딩 윈도우 `MACHINE_AUTH_FAILURE_WINDOW`=W=60s. **경계는 포함형**: 시각 `t`의 실패는 `now − t ≤ W`인 동안 센다(기존 `loginLimiter.prune`의 `Before(now−W)` 의미와 같음 — 정확히 60s에서도 아직 센다, 60s+1ms부터 빠짐). `실패 수 + 진행 중 예약 ≥ N`이면 이후 요청은 서명·JWKS 이전에 429 `machine_rate_limited`. **Retry-After**: 실패 수 ≥ N이면 `max(1, ⌈W − (now − (실패 수−N+1)번째로 오래된 실패 시각)⌉)`초(실패가 N개면 가장 오래된 실패 기준, 정확히 경계에서는 0이 아니라 1); 실패 수 < N인데 예약이 한도를 채운 경우(0건이어도 동일)는 **고정 1초**(예약은 밀리초 단위로 끝나므로). **성공은 카운터를 초기화하지도 올리지도 않는다**(한도 이상인 IP는 유효 토큰이어도 검증 이전에 막힘 — 문서화된 비용). **reservation**: 검사와 동시에 원자적으로 슬롯 1개를 예약하고(`실패 수 + 예약 < N`일 때만 통과), 정확히 한 번 `defer`로 해제한다 — 성공 → 반납(미계수), 401 → 실패로 확정(반납과 동시에 기록), 503(JWKS·인증 동시성)·403·429 이후 단계·요청 취소/클라이언트 끊김·타임아웃·panic → 반납(미계수). 해제가 누락되는 버그에 대비해 예약은 `MACHINE_REQUEST_TIMEOUT`(10s) 뒤 스스로 만료된다. 한 IP의 동시 진행 인증은 최대 N−실패 수. 모든 상태는 유계: IP limiter 항목 ≤ `MACHINE_IP_LIMITER_MAX`(기본 10000), 항목 상한·제거·sweep은 **#270의 수정된 limiter 구현을 재사용**(그 이슈가 기존 `loginLimiter`의 무상한 맵을 다룬다; 머신 limiter가 먼저 필요하면 같은 구현을 공유 타입으로 먼저 PR), client limiter는 설정된 allowlist 크기, unknown client는 상태를 만들지 않음. 대기열 없음(즉시 429/503). 클라이언트 IP는 기존 `c.RealIP()`(`ipExtractorFor`)을 재사용하되 머신 활성 시 `UI_TRUSTED_PROXIES`가 기본 `private`이면 기동 실패(내부망 client가 XFF를 위조 가능) — ingress CIDR 명시 또는 `none` 필요, ingress는 클라이언트가 보낸 XFF를 덮어쓰거나 정리해야 함(운영 문서). 현재 `loginLimiter`는 그대로는 쓰지 않는다(맵 무한 증가·동시 시도 overshoot를 상속하므로 #270 수정본·reservation 필요). per-process 의미(replica별 한도) | 비싼 작업 앞의 값싼 거부, 상태 고갈 방지 | 다중 replica에서 pod별 한도(전역 아님), 재시작 시 초기화, 상한 도달 시 오래된 IP 한도 소실 | 공유 limiter는 ingress/게이트웨이 계층에 위임 |
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
| 서비스 계정 판별 | **양성 요건, 모두 충족**: (i) `client_id`가 있는 문자열이고 `== azp`; (ii) `preferred_username == MACHINE_SA_USERNAME_PREFIX(기본 "service-account-") + client_id`; (iii) `sub`가 비어 있지 않은 문자열. 규칙은 AND이며 (ii)만 보는 OR 규칙은 금지. **`sid`는 요건이 아니다**(refresh 사용 SA 토큰이 `sid`를 가짐) — 값은 감사 필드로만 기록. 이 규칙은 사람 토큰·exchange로 만든 토큰(사람·SA 모두)·lightweight 토큰을 `client_id` 부재로 거부한다. 사람이 `service-account-*` 이름을 갖는 것을 전역 예약 이름으로 취급하지 않는다 — 규칙은 `client_id`+`preferred_username`의 **AND**에 의존하고, 추가로 Keycloak이 실제 서비스 계정 사용자의 사람 인증을 `serviceAccountClientLink`로 차단한다는 점에 기댄다(Codex가 Keycloak 26.7.4 `AuthenticationProcessor` 소스에서 확인; 본 패키지의 라이브 실험으로는 확인하지 않음). 같은 이름의 일반 사용자가 있어도 그 토큰에는 기본 mapper상 `client_id`가 없어 (i)에서 거부된다. 정상 SA 토큰이 (i)–(ii)를 만족하려면 Keycloak client 설정 요건(아래 표 아래 문단)이 필요하다 | 사람 토큰·exchange 토큰은 `client_id` 없음(EVIDENCE §2.3, §2.9 행 4·7·8·11), lightweight는 `client_id`·`preferred_username` 없음(행 2), refresh SA는 `sid` 있음(행 3) |
| `scope` | 공백 구분 문자열 필수. 유효 scope = 토큰 scope ∩ client 상한(D3). 교집합 밖은 요청 시 403 | Keycloak은 `profile`·`email`을 섞어 발급 |
| `iat` | 필수·JSON 숫자, `iat ≤ now + skew` | `iat` 존재 |
| `exp` | 필수·JSON 숫자, `exp > iat`, `exp − iat ≤ MAX_TTL`(기본 10m, 범위 (0,1h]), `now ≤ exp + skew` | 기본 300s |
| `nbf` | 선택. 있으면 숫자, `nbf ≤ now + skew`, `nbf ≤ exp`. go-oidc의 하드코딩 **5분 leeway는 쓰지 않는다**: `SkipExpiryCheck:true`로 go-oidc의 exp·nbf 검사를 끄고(nbf 검사는 그 블록 안) 위 규칙을 자체 구현 | Keycloak은 `nbf` 없음 |
| skew | `MACHINE_CLOCK_SKEW` 기본 30s, 0–60s, 범위 밖 기동 실패 | — |
| 서명 | 커스텀 KeySet(D8)으로 검증, `use=sig`(또는 미지정) 키·alg 일치 키만 | JWKS에 `use=enc` 키 존재 |
| `jti` | 사용하지 않음(재생 추적 없음, 위협 모델 참조) | — |

null·누락·타입 오류 claim은 모두 거부이며 기본값으로 대체하지 않는다. 토큰 발급 측 요구(운영 문서·라이브 점검 T-028; 모두 [EVIDENCE §2.9](EVIDENCE.md)의 관측에 근거): ① **lightweight access token OFF**(`client.use.lightweight.access.token.enabled`, 기본값; 켜면 `client_id`·`preferred_username`·`aud`가 사라져 모든 토큰이 거부됨) ② `service_account`(`client_id`·`clientHost`·`clientAddress`)와 `profile`(`preferred_username`) default client scope 유지 — 제거하면 모든 토큰 거부 ③ **token exchange 비허용**: client 속성 `standard.token.exchange.enabled`는 false(기본)이고 서버에 legacy `token-exchange` feature를 켜지 않는다(켜면 client 설정 없이도 same-client exchange가 성공함, 행 11; 그렇게 만든 토큰은 `client_id`가 없어 ldapium이 거부하지만 방어는 이중으로 둔다) ④ refresh token 사용은 허용(`sid`가 생겨도 거부 사유가 아님) ⑤ 머신 client는 service account 전용(standard flow·direct access grant 비활성화), `aud` mapper는 **그 client의 전용 scope**에만 두고 `ldapium-sso`와 공유하는 scope에 두지 않는다(공유 시 SSO 사용자 토큰에 `ldapium-api`가 들어갈 수 있음 — 미실행 가설, e2e 항목), 필요 scope는 client 기본 scope로 부여. `audience` mapper가 없으면 `aud`가 `account`뿐이라 모든 토큰이 거부된다.

### JWKS·discovery 상태 기계 (D8 정본)

단일 issuer, 상태는 프로세스 메모리. 시각 비교는 모두 주입 가능한 시계.

**파라미터(기본)**: `TTL`=10m, `MAX_STALE`=1h, `MIN`=30s, backoff `b(n)=min(30s·2^(n−1), 300s)`(n=연속 실패 횟수), fetch timeout 5s, negative cache ≤256개.
**변수**: `S`(마지막 조회 성공 시각), `A`(마지막 조회 시도 시각), `fails`(연속 실패), `R`(**다음 조회 허용 시각**, 아래 갱신 규칙), `K`(키 집합), `N`(negative cache), `D`∈{none, ok}(discovery).
**조회 예산 게이트** `G = (now ≥ R)`(경계 포함: `now == R`이면 허용). 조회 시도가 끝날 때마다 `R`을 다시 계산한다: 성공 → `S=A=now, fails=0, R=now+MIN`, `K` 교체, **`N` 전체 비움**; 실패 → `A=now, fails++, R=now+b(fails)`. 기동 시 `R=0`. 모든 조회(요청 구동·백그라운드)는 `G`가 참일 때만 시작하며, 동시에 필요한 요청은 진행 중인 1건(single-flight, timeout 5s)을 공유하고 추가 조회로 세지 않는다.
**테스트 모델(시작 vs 완료)**: 조회 한 번(= discovery가 필요하면 discovery+JWKS를 합친 **1회 refresh**, 예산에는 1건으로 센다)은 시작 시각 `t_s`, 소요 `δ`, 완료 시각 `t_c = t_s + δ`를 가진다. `G`는 **시작 시점**에 `now ≥ R`로 판정하고, `R`·`S`·`A`는 **완료 시각 `t_c`** 기준으로 갱신한다(성공 `R=t_c+MIN`, 실패 `R=t_c+b(fails)`). 조회 결과를 **기다리는 요청**(응답이 그 조회에 달린 요청)의 응답은 조회 완료 뒤에 나간다(성공 시 200은 `t_c`). 조회를 기다리지 않는 요청(예: 행 3의 STALE·known kid는 백그라운드 조회를 시작하지만 **즉시** 응답)은 `δ`와 무관하다. 아래 시나리오는 fake clock에서 달리 적지 않으면 `δ=0`이다.
**키 상태**: `age = now − S`. `NONE`(성공한 적 없음 또는 `D=none`) / `FRESH`(age ≤ TTL) / `STALE`(TTL < age ≤ TTL+MAX_STALE, 경계 포함) / `EXPIRED`(age > TTL+MAX_STALE).
**negative cache 항목**: 키 = `kid`. 값 = 만료 시각 `e_k`. 삽입은 “직전 조회가 성공이었고(`fails=0`) 그 kid가 `K`에 없다”는 판정을 낸 시점이며 `e_k = R`(삽입 시점의 다음 조회 허용 시각). 항목은 `now < e_k`인 동안만 유효하다 → 항목은 조회가 다시 허용되는 바로 그 시각에 사라지고, 어떤 조회 완료도 `N`을 비운다. negative cache는 단지 `G` 판정을 반복하지 않게 하는 메모이며 **결과를 바꾸지 않는다**(항목을 지워도 아래 표의 응답은 같다).

**평가 순서(위에서 첫 일치 행, 요청의 kid=k)**:

| # | 키 상태 | k | 조건 | 응답 | 이 요청이 시작하는 조회 |
|---|---|---|---|---|---|
| 1 | `NONE`/`EXPIRED` | 무관 | `!G` | 503 `unavailable` + `Retry-After`=⌈R−now⌉ | 없음 |
| 2 | `NONE`/`EXPIRED` | 무관 | `G` | 조회 성공 시 새 `K`로 아래 행 재평가, 실패 시 503 + `Retry-After`=⌈b(fails)⌉ | 1건(`D=none`이면 discovery부터) |
| 3 | `FRESH`/`STALE` | `K`에 있음 | — | 서명 검증 결과대로 200/401(**알려진 kid의 잘못된 서명은 항상 401**) | `STALE`이고 `G`이면 **응답과 무관한 백그라운드 조회 1건**(서명이 위조여도 동일, 예산 `G` 안에서만); `FRESH`이면 0건 |
| 4 | `FRESH`/`STALE` | `K`에 없음 | `N`에 k가 있고 `now < e_k` | 401 `token_invalid` | 없음 |
| 5 | `FRESH`/`STALE` | `K`에 없음 | `!G`, `fails=0` | 401, `N`에 (k, `e_k=R`) 삽입 | 없음 |
| 6 | `FRESH`/`STALE` | `K`에 없음 | `!G`, `fails>0` | 503 + `Retry-After`=⌈R−now⌉ (조회 장애 중에는 미지 kid를 401로 단정하지 않음) | 없음 |
| 7 | `FRESH`/`STALE` | `K`에 없음 | `G` | 성공: 새 `K`에 k가 있으면 서명 검증 결과, 없으면 401 + `N`에 (k, `e_k=R`) 삽입; 실패: 503 + `Retry-After`=⌈b(fails)⌉ | 1건 |

**파생되는 성질(단언이 아니라 표에서 도출)**: 새 키의 kid가 처음 보이는 시각을 `t`라 하면, 마지막 조회 성공 시각이 `S`일 때 `t < S+MIN`이면 `R=S+MIN`이므로 행 5가 401을 내고 `e_k=S+MIN`, `t ≥ S+MIN`이면 `G`가 참이라 행 7이 조회해 새 키를 반영한다. 따라서 **새 키가 거부되는 최대 시간은 `S+MIN`까지**(예: S=0에서 t=29에 본 kid는 `e_k=30`으로 401, t=30의 같은 kid는 항목이 만료되어 행 7로 조회·반영). 직전 조회가 실패했다면 `R`이 backoff `b(fails)`만큼 밀리므로 그동안은 행 6의 503이다. 다른 kid의 negative 항목은 `e_k=R` 이후 존재하지 않으므로 backoff 판정(행 6·7)을 앞지르지 않는다(예: k1이 t=29에 `e=30`으로 저장, t=30의 k2는 `G` 참 → 행 7 조회 실패 시 503, `R=60`).

**시나리오별 정확한 조회 횟수(fake clock, 모두 단위 테스트)**:

| # | 시나리오 | 기대 조회 |
|---|---|---|
| a | `S=0`, FRESH, 초당 1000건 무작위 kid를 0–300s 동안 | 정확히 t=30,60,…,300에 1건씩 = 10건(조회마다 성공·키 없음), t<30에는 0건, 응답은 전부 401 |
| b | FRESH에서 알려진 kid + 위조 서명 1000건/초를 임의 시간 | 0건, 응답 401 |
| c | `STALE`(age=TTL+1s)에서 알려진 kid + 위조 서명 폭주, IdP 정상 | 첫 요청이 백그라운드 1건 시작·성공 → `FRESH`가 되어 이후 0건; 위조 요청의 응답은 401 |
| d | c와 같으나 IdP 중지 600s | 시도 시각 t0, t0+30, t0+90, t0+210, t0+450 = 5건(backoff 30·60·120·240), 응답은 알려진 kid라 401(위조)/200(진짜 서명) |
| e | age=TTL+MAX_STALE(경계) vs +1s | 경계: 알려진 kid 200(`STALE`), +1s: `EXPIRED`라 `G`이면 조회(IdP 중지 시 503), `!G`이면 503 + `Retry-After` |
| f1 | discovery 실패 후 복구(`D=none`, `δ=0`, IdP 중지로 기동 → t=100에 IdP 복구) | 시작 t=0, 30, 90, 210(성공): 그 사이 모든 bearer 요청 503 + `Retry-After`=⌈R−now⌉, 쿠키 로그인은 정상; t=210의 시도(백그라운드 타이머 또는 요청) 후 재시작 없이 200 |
| f2 | f1과 같으나 실패 조회가 timeout으로 `δ=5s`(IdP는 t=100에 복구) | 시작 t=0(완료 5, `R=35`), 35(완료 40, `R=100`), 100(성공, 완료 100): 그 사이 bearer는 503 + `Retry-After`=⌈R−now⌉, t=100 시작 조회가 성공해 재시작 없이 200 |
| g | 새 키 회전: S=0(완료 0), t=29의 새 kid, t=30의 새 kid | t=29 조회 0건·401; t=30 조회 **시작** 1건·성공, 200은 완료 시각 `30+δ`(δ=0이면 30) |
| h | t=29에 k1 부정 항목(e=30), t=30에 다른 kid k2, 이 조회가 실패 | t=30 조회 1건, 503 + `Retry-After`=30, `R=60`; k1은 t=59까지 행 6의 503 |

불변식: ① **닫힌 구간 `[t0, t0+T]`에서 조회 시작은 최대 `1 + ⌈T/MIN⌉`건**이며(예: `[30,330]`에서 t=30,60,…,330의 11건) 실패 시 backoff로 더 드물다(a·d). 이 정의를 AC-016·검증 표·TASKS 전부에 쓴다. ② 조회를 시작하는 요청은 행 2·3(STALE)·7뿐이고 모두 `G`가 참일 때다. ③ stale 키로 200을 주는 것은 행 3뿐이며 최대 `TTL+MAX_STALE`(1h10m)까지(IdP 키 compromise 시 이 한계가 제거 지연이므로 긴급 차단은 D7의 서버측 경로). ④ 전 행의 `Retry-After`는 정수 초(1–300).

**discovery**(`NewProvider` 상당): 기동 시 1회(timeout 5s) 시도(`R=0`이므로 `G` 참). 실패는 기동 실패가 아니다(기존 SSO 초기화 `server.go:79-86`은 기동 실패를 유지하며 머신 인증과 독립) — 로그 ERROR 후 `D=none`이 되어 모든 bearer 요청이 행 1·2에 따라 503. `D=none`인 동안 **백그라운드 타이머가 `R` 시각에** discovery를 재시도하고(트래픽이 없어도 복구), 성공하면 즉시 JWKS를 조회해 `D=ok`·`K` 설정(둘 다 같은 `R`/backoff 일정). 설정 오류(issuer 형식·https 위반)는 기동 실패. discovery 문서의 `issuer`가 설정값과 다르면: 기동 시점 접촉에서 발견되면 기동 실패(설정 오류), 이후 재시도에서 발견되면 `D=none` 유지 + ERROR 로그(503). 쿠키 로그인·SSO는 어느 경우에도 영향받지 않는다.

### 인증 경로 분리 규칙 (D2 상세)

`selectAuth`는 순수 함수다. 입력: 기능 활성 여부, 메서드, 경로, `Authorization` 헤더 값 목록, `ldapium_session` 쿠키 존재 여부. 출력: `{ignore, cookie, bearer(token), reject(status)}`.

**분류**
- Authorization: `A0` 없음 / `AV` 형식이 유효한 단일 줄 `Bearer <token68>`(scheme 대소문자 무시, scheme과 토큰 사이 정확히 공백 1개, 앞뒤 공백·comma 없음, 토큰은 `A-Za-z0-9-._~+/` 뒤 `=*`, 8 KiB 이하) / `AI` 있으나 형식 무효(빈 값, 토큰 없음, token68 밖 문자, 다른 scheme, 공백 변형, comma 결합) / `AD` 헤더가 2줄 이상(내용 무관).
- 쿠키: Authorization이 **없을 때** 쿠키 경로는 **기존 동작 그대로**다 — `requireSession`은 `c.Cookie("ldapium_session")`로 **첫 번째** 쿠키 하나만 읽고(`middleware.go:30`) 뒤의 중복 쿠키는 무시한다. 분류는 `C0` 없음/빈 값 / `CV` 첫 쿠키가 유효 세션 / `CI` 첫 쿠키가 무효·만료. **중복 쿠키에 대한 새 규칙을 만들지 않는다**(브라우저 세션 호환; 예: [유효, 무효]는 200, [무효, 유효]는 401 — 현재와 동일, 회귀 테스트). “중복이면 401”은 **`Authorization` 헤더 줄에만** 적용된다. Authorization이 **있을 때**의 쿠키는 이름 존재 여부만 본다: `C0`(해당 이름의 쿠키 없음) / `Cp`(값·개수·유효성 무관하게 하나라도 있음).
- 경로: `P` 보호 45개 / `PA` 쿠키를 발행·삭제하는 공개 auth 4개(`login`·`logout`·`ssoStart`·`ssoCallback`) / `PO` 나머지 공개 4개(`getMeta`·`getOpenAPI`·`getAuthConfig`·`getLdapHealth`) / `N` 미등록 `/api` 경로·비-`/api` 경로.

**우선순위(위에서 첫 일치)**: ① 기능 꺼짐 → `Authorization` 완전 무시, 기존 동작(AC-014). ② Origin gate(기존, 가장 바깥): `/api`의 POST/PUT/PATCH/DELETE이고 `Origin` 헤더가 있으며 단일 same-origin 값이 아니면(foreign·`null`·중복) 403 `origin_mismatch` — `Authorization` 유무와 무관하게 이후 단계 실행 없음. **GET·`Origin` 없는 요청에는 gate가 적용되지 않는다**(`origin_gate.go:37-54`; 외부 Origin의 GET을 거부하는 규칙이 아니다). ③ 경로 분류 `N` → 기존 응답(Authorization 무시). ④ `PO` → Authorization 무시. ⑤ `PA` → 아래 표. ⑥ `P` → 아래 표.

| 경로 | Authorization | 쿠키 | 결과(셀당 정확히 하나) |
|---|---|---|---|
| P | A0 | C0 | 기존 401 `unauthenticated`(쿠키 없음·빈 값) |
| P | A0 | CV | 기존 경로(첫 쿠키가 유효 → 핸들러; 중복 쿠키가 있어도 첫 쿠키만 봄) |
| P | A0 | CI | 기존 401(첫 쿠키가 무효·만료; 뒤에 유효한 중복 쿠키가 있어도 동일) |
| P | AI 또는 AD | C0·Cp | 401 `token_invalid`(쿠키 폴백 없음, 혼용 400보다 우선) |
| P | AV | Cp | 400 `bad_request`(혼용; 쿠키가 유효·무효·빈 값·중복 어느 것이든 동일, 토큰 검증 이전, 암호 연산 없음) |
| P | AV | C0 | bearer 경로: IP throttle(429) → 인증 동시성(503) → 검증(401/503) → deny-by-default 가드(allowlist 밖·비-GET은 403 `scope_denied`) → scope(403) → 핸들러. **검증 실패(401)가 비-GET 거부(403)보다 먼저** |
| PA | A0 | 무관 | 기존 동작(쿠키 발행·삭제 포함) |
| PA | AV·AI·AD | 무관 | 400 `bad_request`, 쿠키 미발행·미삭제, 핸들러 미실행 |
| PO | 무관 | 무관 | 기존 공개 응답(Authorization 무시, 감사 줄은 `reason=ignored_public`) |
| N | 무관 | 무관 | 기존 404(또는 비-`/api` 정적 응답); `/api`이면 감사 줄 1개 |

미들웨어 순서(바깥→안): RequestID → (Authorization 감사 emit 래퍼) → CORS(설정 시) → Origin gate → `selectAuth`/인증 → deny-by-default 가드 → scope 해석 → 핸들러. CORS는 `Authorization`을 허용 헤더에 추가하지 않으며(현재도 없음, `cors.go`) preflight의 `Access-Control-Request-Headers: authorization`은 거부된다(회귀 테스트).

1. 선택은 위 분류·우선순위의 순수 함수 하나가 한다. 매트릭스의 모든 셀(+기능 꺼짐, +상태 변경 메서드×Origin 조합)이 단위 테스트의 한 행이며, 서로 다른 결과를 내는 두 규칙이 겹치는 셀이 없어야 한다.
2. bearer 경로는 `requireSession`을 거치지 않고, `session.Store`에 항목을 만들지 않으며 `Set-Cookie`를 내지 않는다. 핸들러 재사용을 위해 요청 수명 한정의 임시 `Session{DN: 머신 bind DN, Bound: 요청별 bind}`를 컨텍스트에 두고 응답 후(취소·패닉 포함) 닫는다. 임시 `Session.ID`는 cursor 바인딩에 쓰지 않는다(D16).
3. bearer 경로는 GET만, allowlist 안에서만 통과한다(런타임 가드, D13).
4. 쿠키 경로는 bearer를 해석하지 않는다.
5. 머신 bind DN이 `BACKUP_ADMIN_DNS`·프로파일 관리자 DN에 들어가면 기동 실패(D4).

### 머신 LDAP 계정·ACL (D4/D14 상세, Q2: 운영자 수동 + 문서 LDIF)

기존 규칙이 머신 DN에 어떻게 작용하는지가 출발점이다([EVIDENCE §1](EVIDENCE.md)): 메인 DB의 `{0}to attrs=userPassword,shadowLastChange by self write …`가 이미 템플릿 맨 앞에 있고, 뒤따르는 렌더링에는 `LDAP_ANONYMOUS_READ_BASE` 미설정 시 `{1}…by users read`·`{2}to * by self write by users read`, 설정 시 `{1}`–`{4}`가 있다. 따라서 머신 규칙을 `to *` catch-all 앞에만 두는 것으로는 부족하다 — 선행 `{0}`의 `by self write`(자기 비밀번호 수정)와 선행 `by users read`(허용 subtree 밖의 `entry`/`uid`/`objectClass` 노출)가 먼저 적용된다. **요건: 머신 DN 규칙은 기존 모든 allow 규칙보다 앞(`{0}`부터)에 삽입하고, 두 렌더링 분기 모두에서 검증한다.**

`M`=머신 DN, `B`=허용 subtree(기본 `LDAP_BASE_DN`; `getEntry`/`listTree` 코드 가드 D14(a)의 BASE_DN과 같거나 그 하위). 운영자는 메인 DB(`olcDatabase={1}mdb,cn=config`)에 아래를 `add: olcAccess`로 적용한다(`{n}` 명시 삽입은 기존 규칙을 뒤로 민다).

```
dn: olcDatabase={1}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange
  by dn.exact="M" none
  by * break
olcAccess: {1}to dn.subtree="B"
  by dn.exact="M" read
  by * break
olcAccess: {2}to *
  by dn.exact="M" none
  by * break
```

- `{0}`: 머신 DN의 비밀 속성(이미지 스키마의 다른 비밀 속성이 있으면 같은 목록에 추가 — T-015가 스키마에서 목록을 도출) 읽기·**자기 쓰기까지** 차단. `M`이 bind할 때의 요청자는 아직 익명이므로 `by * break` 뒤 기존 `by anonymous auth`로 bind는 계속 성공한다(라이브 확인 대상).
- `{1}`: `B` 아래 항목·속성은 `read`(검색·비교 포함, 쓰기 불가). `{0}`이 먼저라 비밀 속성은 여기서 열리지 않는다.
- `{2}`: 그 밖 전부(`B` 밖 `entry`/`uid`/`objectClass`, `M` 자기 항목 쓰기 포함)를 `none`. `M`의 결정은 `{0}`–`{2}`에서 끝나므로 기존 `by users read`·`by self write`에 도달하지 않는다.
- 모든 규칙이 `by * break`로 끝나 **`M`이 아닌 신원은 기존 규칙 그대로** 이어진다(first-match/`break` 의미는 slapd.access(5) 근거이며 T-015·AC-018에서 라이브로 확인한다).
- 계정 항목은 `B` 밖(예 `ou=system`)에 둔다. 허용 subtree에 있으면 안 되는 비밀·권한 정보를 `M` 항목에 넣지 않는다.
- 별도 DB(규칙은 서로 독립): `cn=Monitor`·accesslog DB는 기본 ACL이 `by * none`이라 `M`은 기본 거부. `server.monitor.read`를 쓰는 배포만 monitor DB에 `{0}to * by dn.exact="M" read by * break`를, `audit.read`를 쓰는 배포만 accesslog DB에 같은 형태를 opt-in으로 추가한다. `cn=config`는 `M`에게 어떤 규칙도 주지 않는다.
- `cn=config` ACL은 복제되지 않고 컨테이너 재초기화 시 템플릿에서 다시 렌더링되므로, 모든 노드에 적용하고 재초기화 후 재적용하는 절차를 운영 문서에 두며 AC-018은 새로 초기화한 컨테이너에서 처음부터 수행한다(T-015).
- 위 LDIF·ACL 변경은 Class D이며 구현 시 `ldapium-directory-change` 스킬을 먼저 로드한다. 이 패키지는 규칙 순서·내용과 AC-018 수용 기준을 확정하고, 속성 목록과 `break` 동작은 T-015가 라이브로 확정한다.

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
| `MACHINE_LDAP_ROOT_DNS` | 없음(활성 시 필수) | 메인 DB rootdn 식별 입력, `;` 구분·ParseDN·`\3B` escape(D4). monitor/accesslog/config rootdn 3종은 내장 금지 |
| `MACHINE_SA_USERNAME_PREFIX` | `service-account-` | D5 SA 판별 (ii) |
| `MACHINE_AUTH_FAILURE_LIMIT` / `_WINDOW` | `10` / `1m` | D9 IP 실패 throttle |
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
| confused deputy | 사람 SSO access token·타 서비스 토큰·ID token·**허용 client에서 발급된 사람 토큰**을 머신 경로에 제시 | `aud` 정확 멤버십·`azp`==`client_id`·SA 판별(`client_id==azp` AND `preferred_username`, `sid` 미사용)·SSO client 제외·payload `typ=Bearer`(D5) | audience mapper를 SSO와 공유 scope에 두는 오설정 — e2e 음성 테스트(T-021), 머신 client의 사람 로그인 흐름 비활성화 운영 요건 |
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
| `AC-006` | 단위(`selectAuth` 매트릭스 전 셀·Origin 조합) + e2e 혼용·Origin·CORS preflight | go test; e2e | 셀별 상태 코드 표, `Set-Cookie` 부재 |
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
| `AC-018` | e2e: 새로 초기화한 컨테이너 **세 구성**((a) `LDAP_ANONYMOUS_READ_BASE` 미설정 (b) 설정 (c) 운영자 추가 선행 allow가 있는 DB; 적용 후 `olcAccess` 순서를 읽어 확인)에서 머신 DN으로 slapd에 직접 자기 비밀번호 변경·쓰기·`B` 밖 검색·비밀 속성 요청 + 타 신원(일반 사용자·관리자·익명) 전후 불변 | 컨테이너 e2e | 구성별 `olcAccess` 순서 확인·50 거부 로그·빈 결과 표, 타 신원 회귀 통과 |
| `AC-019` | 롤아웃 드릴(2 replica Helm 또는 compose 2개): 비활성화 후 구토큰 통과 → allowlist 제거 전 replica 교체 후 401 → rollback | e2e/드릴 | 단계별 응답 표, 이전 pod 0개 |

단위/정적(순수 함수·계약)과 라이브 e2e를 구분한다. LDAP wire 코드는 저장소 원칙대로 단위 테스트하지 않고 e2e로만 검증하며 모킹 프레임워크를 도입하지 않는다.
JWKS 검증은 외부 모킹 없이 로컬 `httptest` 서버가 실제 JWKS를 서빙하는 방식으로 단위 검증한다.

## Rollout, rollback and recovery

- Rollout sequence: (1) 수용·ADR → (2) 설정·순수 헬퍼·계약 테스트(기능 꺼짐) → (3) 인증기·라우팅 가드 → (4) e2e → (5) 문서·차트 → (6) 스테이징에서 전용 client·ACL로 활성화 → (7) 릴리스 노트. 모든 단계에서 기본 꺼짐.
- Rollback trigger and procedure: 예기치 않은 401/403 오분류, 권한 노출 의심, JWKS 장애 파급 시 `MACHINE_AUTH_ENABLED=false`(Helm `ui.machineAuth.enabled=false`) 후 재배포하고 **모든 replica 교체 완료·이전 revision pod 0개·진행 중 요청 종료**를 확인한다(롤아웃 중에는 일부 replica가 아직 bearer를 받는다). 코드 롤백 없이 기능 정지. 롤백 후 기존 쿠키 e2e 무변경 통과(AC-019).
- Data/configuration recovery: 영속 데이터 없음(토큰·키 미저장). 머신 LDAP 계정은 운영자가 삭제/비활성화. **긴급 차단의 1차 수단은 서버측 allowlist 제거/기능 끄기(D7)**이며 Keycloak client 비활성화·secret 회전은 새 토큰 발급을 막는 보조 수단이다(이미 발급된 JWT는 비활성화 후에도 만료까지 유효 — 관측).
- 병합 단위(수용 후): 모든 단위가 기능 꺼짐 상태로 병합된다 — S1 config·계약 골격·순수 검증기(T-010/011/014/019) → S2 `selectAuth`·가드·감사·limiter(T-012/017/018/041) → S3 실행 신원·경계 가드(T-013/040) → S4 ACL 가이드·Helm(T-015/016) → S5 e2e·CI·release 게이트(T-021/022/024–028) → S6 문서·릴리스 노트(T-030–033). 활성화는 S5 통과 후 스테이징에서만.
- Compatibility or migration obligations: 기존 경로·쿠키·응답 불변. OpenAPI는 additive(`securitySchemes`, `x-machine-scope`)이며 기존 오퍼레이션의 `cookieAuth`는 유지.

## Evidence and durable synchronization

- Evidence location/format: 구현 시 `research/README.md` 규약에 따른 기록(테스트·e2e 결과, 실패 포함). e2e 로그는 CI 아티팩트.
- Tests or checks that become durable regression controls: 허용/거부 전수 계약 테스트, `selectAuth`·claim 검증기·scope 해석 단위 테스트, 신규 e2e 워크플로, 기동 시 설정 검증.
- Documentation to update: `docs/api.md`(인증 절·머신 호출 예), `docs/auth-provider-policy.md`, `docs/audit-event-schema.md`(`machine_access`), `ui/README.md`, `charts/ldapium/README.md`, `docs/air-gap.md`, 이 패키지.
- ADR/evidence/portfolio records to update: ADR 신규, [IMPLEMENTATION-STATUS](../../IMPLEMENTATION-STATUS.md), 포트폴리오 상태(해당 시).

## Traceability matrix

실제 산출물과 판정(2026-10-07 close-out 감사, main `5c74f73`; 테스트 이름·라이브 스크립트 전체 목록은 아래 "Close-out audit" 표). 약어: `h/`=`ui/backend/internal/httpapi/`, `m/`=`.../machineauth/`, `c/`=`.../config/`, `l/`=`.../ldapclient/`; 라이브 = `scripts/test/test-machine-*-live.py`·`test-machine-revocation-drill.py`, CI job `machine bearer auth (real Keycloak)`·`api-credentials-e2e.yml`.

| Requirement | Acceptance | Task | Verifying artifacts | Verdict |
|---|---|---|---|---|
| `REQ-001` | AC-001, AC-002 | T-010, T-011, T-019, T-020, T-021, T-028 | `m/verifier_test.go`(`TestVerify_NegativeTable` 48 하위 케이스 외), keycloak-live·settings-live, [EVIDENCE §2·§5](EVIDENCE.md) | MET |
| `REQ-002` | AC-001, AC-003 | T-012, T-024, T-020, T-021 | `h/machine_test.go` `TestMachine_EveryProtectedOperationExercised`(8/37)·`_NewProtectedGetWithoutAllowlistIsDenied`, keycloak-live | MET |
| `REQ-003` | AC-004, AC-013 | T-012, T-014, T-024 | `h/machine_contract_test.go`, `TestMachine_NonGetAlwaysDenied`, `jq` 8/37/53 | MET |
| `REQ-004` | AC-001, AC-009, AC-018 | T-010, T-013, T-015, T-026 | `c/machine_test.go` `TestMachine_BindDNEquivalence`, ACL 라이브 349 검사(3구성)+변이 11 | MET(결합 제한 #277) |
| `REQ-005` | AC-005 | T-040, T-021 | `l/secret_boundary_test.go`, keycloak-live 비밀 값 0건 | MET |
| `REQ-006` | AC-006 | T-012, T-020, T-021 | `TestSelectAuth_Matrix`, `TestMachine_DuplicateCookiesUnchanged`, keycloak-live | MET |
| `REQ-007` | AC-007 | T-021 | keycloak-live(LDAP·SSO 모드) | MET |
| `REQ-008` | AC-008, AC-009 | T-006, T-011, T-013, T-019, T-021, T-025 | `m/keyset_test.go` `TestKeySet_A…H`, `TestMachine_StartupDiscoveryPolicy`, jwks-live | MET |
| `REQ-009` | AC-001, AC-010 | T-017, T-020, T-021 | `h/machine_audit_test.go`, 로그 스캔 0건 | MET(예외 D25) |
| `REQ-010` | AC-011 | T-018(#270 의존), T-020, T-021 | `h/machine_limiter_test.go`(경계 표), execution-live, keycloak-live | MET(replica별) |
| `REQ-011` | AC-002, AC-012 | T-011, T-020 | `m/verifier_test.go` `TestVerify_TimeBoundaries` | MET |
| `REQ-012` | AC-013 | T-014, T-020 | `h/machine_contract_test.go`, `jq` | MET |
| `REQ-013` | AC-014, AC-019 | T-015, T-016, T-021, T-027 | 꺼짐 단위 테스트 4종, `scripts/test/test-chart-machine-auth.sh`, 드릴 (c) | MET(클러스터 설치 미실행 #284) |
| `REQ-014` | AC-010 | T-017, T-021 | `TestMachineAudit_NoTokenMaterialInLogsOrResponses`, 로그 스캔 | MET |
| `REQ-015` | AC-005, AC-015 | T-040, T-021 | `TestDNWithinBase`, `TestMachineGuard_*`, keycloak-live | MET |
| `REQ-016` | AC-008, AC-016 | T-010, T-019, T-025 | `m/keyset_test.go`, `TestHTTPFetcher_Limits`, jwks-live | MET |
| `REQ-017` | AC-017 | T-041, T-021 | `h/machine_boundary_test.go` `TestMachineCursor_Isolation` | MET |
| `REQ-018` | AC-019 | T-027, T-030, T-032 | `test-machine-revocation-drill.py` 18 검사, `docs/machine-auth-operations.md` | MET(#280, #284) |

## Review record

- Accepted scope/requirements: REQ-001–REQ-018 설계(Revision 5), 읽기 전용 v1, 기본 꺼짐. 2026-10-07 유지보수자 지시('승인 후 구현까지')를 재검토 5라운드 통과 후 이행해 수용했다(Revision 5 최종 확인 PASS). T-005 1차 독립 보안 검토(Codex)는 BLOCKER였고 Revision 2가 이를 반영했다.
- Material changes after acceptance and re-review: 수용 뒤 구현 중 확정된 결정 D17–D32는 이 문서 끝의 "Implementation notes"와 [ADR.md](ADR.md)에 설계 변경이 아닌 명확화로 기록돼 있다(T-006 미결이던 `listTree` 상한은 D21, 최소 ACL 비밀 속성 목록 확장은 D26, 결합 순서 D30은 #277에서 해결). 이 close-out 감사는 설계 서술을 바꾸지 않았다.
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

잔여 차단 사항: 위 결정으로 설계 질문은 닫혔고, 재검토 5라운드 통과로 이 패키지는 2026-10-07 `Accepted`가 되었다(맨 아래 기록 참조).

## Revision 2 (2026-10-07)

T-005 독립 보안 검토(Codex, 총평 BLOCKER, 7개 영역)와 [EVIDENCE.md](EVIDENCE.md)(실제 Keycloak 26.7.4 관측 + 코드 읽기)를 반영했다. 상태는 `Proposed / awaiting review`로 유지하며 재검토가 남았다. 코드 읽기 결과는 Gemini 워커의 재집계를 코드·`openapi.json`과 대조해 사용했고, 대조하지 못한 핸들러 file:line은 옮기지 않았다(EVIDENCE §1). 검토의 file:line 지적 중 `config.go:562`(원격 http 허용), `monitor.go:98`, `tree.go:117`, `cursor.go:67`, `login_limiter` 무상한은 코드에서 직접 확인했다.

### 지적 → 처리

| # | 지적 (영역, 검토 판정) | 처리 | 위치 · 검증 |
|---|---|---|---|
| 1a | 토큰 종류·SA 판별이 검증 불가 문구, 같은 client 사람 토큰 (FIX-IN-PACKAGE) | JOSE `typ`·payload `typ`=`Bearer`·SA 판별(`client_id==azp` AND `preferred_username`, `sid` 미사용) 고정. 관측: 같은 client 사람 토큰은 `aud`/`azp`/`scope`가 동일 | D5 표, AC-002 · T-011, T-021 |
| 1b | `azp`/`client_id` 우선순위·불일치, alg 목록, ID/SSO 토큰 | 둘 다 필수·동일, alg 기본 `RS256,ES256`+`SupportedSigningAlgs`, ID(`typ=ID`)·SSO client 거부 | D5 표, AC-002 · T-011 |
| 1c | `iat`·`exp<=iat`·MAX_TTL·skew 범위 | 필수 숫자 규칙·`exp>iat`·MAX_TTL (0,1h]·skew 0–60s 기동 검증 | D5 표, AC-012 · T-010, T-011 |
| 1d | go-oidc nbf 5분 leeway | `SkipExpiryCheck:true`+자체 시간 검증(nbf 검사가 그 블록 안임을 소스·관측으로 확인), 실제 서명 검증기 경유 경계 테스트 | D5 표, AC-012 · T-011 |
| 1e | audience mapper·`account` 거부 | 관측 반영: 기본 `aud="account"` 문자열, mapper 후 배열; 정확 멤버십, mapper 설정 예와 전용 scope 요건 | D5 표, EVIDENCE §2.2 · T-021, T-030 |
| 2a | HTTPS 주장이 현 코드와 다름 (BLOCKER) | 머신 전용 https 검증(D15), 예외 `MACHINE_OIDC_INSECURE_HTTP`+WARN, SSO 검증은 불변 | D15, AC-016 · T-010 |
| 2b | JWKS 재조회 증폭·TTL·timeout | 커스텀 KeySet, TTL/stale/최소 간격/backoff/negative cache/크기·timeout 수치 | D8, AC-008, AC-016 · T-019, T-025 |
| 2c | 401 vs 503, `Retry-After` | AC-008 표로 고정 | AC-008 · T-019 |
| 3a | Authorization 문법·쿠키 혼용 | `selectAuth` 분류·우선순위 매트릭스(Revision 3에서 재작성), 폴백 금지 | 인증 경로 분리 규칙, AC-006 · T-012 |
| 3b | 공개 auth 경로·`Set-Cookie` | 4개 쿠키 경로에서 bearer 400, 나머지 공개는 무시, 보호 경로 쿠키 미발행 | 매트릭스 PA·PO 행 · T-012 |
| 3c | Origin gate 순서·CORS | gate 최외곽 불변, CORS `Authorization` 비허용 회귀 | 미들웨어 순서 · T-012, T-021 |
| 4a | 53개 vs 48개, 누락 5개 (BLOCKER) | 분류 재작성: 허용 8 / denylist 36 + `getMe`. `jq`로 확인 | 분류 표, EVIDENCE §1 |
| 4b | `getMonitor` accesslog 노출 (BLOCKER) | `audit.read` 없으면 accesslog 검색 미발행·`recentLogs` 비움 | D14(b), AC-015 · T-040 |
| 4c | `getEntry` 임의 DN·`reqMod` 비밀 값 (BLOCKER) | 머신 한정 BASE_DN 가드(ParseDN), accesslog/config/Monitor 불가, 핸들러 불변 조건 완화 명시 | D14(a)(c), AC-015, Change impact · T-040 |
| 4d | 계약 테스트만으로 가드 증명 불가 | 런타임 deny-by-default 가드+합성 라우트·전수 호출 | D13, AC-003 · T-012, T-024 |
| 5a | rootdn 식별·DN 비교 | `MACHINE_LDAP_ROOT_DNS` 필수 입력, `ParseDN` 동등 비교와 변형 테스트 | D4, AC-009 · T-010, T-013 |
| 5b | ACL 읽기 전용 증명 | 머신 규칙을 `by self write` catch-all 앞에, `by * break` 구조, 쓰기 시도 거부 e2e | 머신 LDAP 계정·ACL, AC-018 · T-015, T-026 |
| 5c | timeout·동시성·결과 상한·bind 실패 | bind 전 비차단 슬롯, 요청 deadline 10s, 결과 상한, defer 해제, 503 | D4, D9, AC-009 · T-013, T-021 |
| 5d | cursor 바인딩, SESSION_SECRET 충돌 | issuer+client 안정 바인딩·도메인 분리, D4 문구 변경(키는 무결성 키라 공유) | D16, AC-017 · T-041 |
| 6a | 남용 제한 순서·상태 상한 | ①–⑥ 순서와 모든 상태 상한, `loginLimiter` 현 구현 비재사용(#270 수정본 재사용) | D9, AC-011 · T-018 |
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
- 기존 `loginLimiter`의 무상한 맵(사람 로그인 경로)은 이슈 #270이 다룬다. 머신 limiter는 그 수정본을 재사용하므로 T-018은 #270(또는 같은 구현을 공유 타입으로 먼저 낸 PR)에 의존한다.

## Revision 3 (2026-10-07)

T-005 재검토 2라운드(Codex)는 round 1 지적이 해소되었음(53 = 8 + 45, 허용 8 / 거부 37, REQ 번호 누락 없음)을 확인했고 아래 6건을 남겼다(BLOCKER 2, FIX-IN-PACKAGE 4). 코드 근거(`image/ldifs/01-cn-config.ldif`, `image/entrypoint.sh`, `config/keycloak.go`, `origin_gate.go`, `server.go`, `login_limiter.go`)는 이 개정에서 직접 읽어 [EVIDENCE §1](EVIDENCE.md)에 옮겼고, 서비스 계정 판별은 같은 고정 이미지로 **실제 실험**해 [EVIDENCE §2.9](EVIDENCE.md)에 기록했다. 상태는 `Proposed / awaiting review; Revision 3 re-review pending`이다.

| # | 지적 (판정) | 처리 | 위치 · 검증 |
|---|---|---|---|
| R3-1 | ACL 순서가 읽기 전용을 보장하지 않음: `{0}` `by self write`, 선행 `by users read` (BLOCKER) | 머신 규칙을 기존 모든 allow 앞(`{0}`–`{2}`)에 삽입하는 정확한 LDIF(비밀 속성 none → `B` read → 나머지 none, 전부 `by * break`), 두 렌더링 분기 모두 라이브 검증, 모니터·accesslog·config는 별도 DB 규칙·opt-in | 머신 LDAP 계정·ACL, AC-018 · T-015, T-026 |
| R3-2 | rootdn 목록 쉼표 구분이 DN과 충돌, Monitor rootdn 누락 (BLOCKER) | `;` 구분(기존 목록과 동일 `splitEntries`), `\3B` escape, ParseDN 비교, 내장 금지 rootdn 3종(monitor·accesslog·config)+운영자 입력 메인 rootdn, Helm 파생 | D4, 설정 표, AC-009 · T-010, T-016 |
| R3-3 | SA 판별의 token exchange·mapper 제거·lightweight·refresh 호환 (FIX-IN-PACKAGE) | 실험: refresh 사용 SA는 `sid`를 가짐 → **`sid` 요건 폐기**; exchange(사람·SA)·lightweight·mapper 제거 토큰은 `client_id`가 없음 → 양성 AND 규칙 `client_id==azp ∧ preferred_username==prefix+client_id`(OR 금지); 필수 Keycloak 설정(lightweight OFF, `service_account`·`profile` scope 유지, exchange 비허용·legacy feature OFF)과 라이브 양·음성 점검 | D5 표, EVIDENCE §2.9, AC-002 · T-011, T-028, T-021 |
| R3-4 | JWKS 상태표 모순, negative cache 5m vs 30s, discovery 재시도 없음 (FIX-IN-PACKAGE) | 단일 상태 기계 표(키 상태 × kid × 이벤트, 우선순위, stale 최대 1h10m, negative cache TTL 30s·성공 시 무효화, discovery 재시도·복구) | JWKS·discovery 상태 기계, AC-008, D8 · T-019, T-025 |
| R3-5 | `selectAuth` 우선순위 중복, “둘 다 존재→400”과 불일치, Origin gate 범위 (FIX-IN-PACKAGE) | 분류·우선순위·경로 × Authorization × 쿠키 매트릭스(셀당 한 결과), 문법 오류는 쿠키와 무관하게 401 > 혼용 400, PA는 400, PO·N은 무시, Origin gate는 상태 변경 메서드+`Origin` 존재 시에만(GET 비대상) | 인증 경로 분리 규칙, AC-006, D2 · T-012 |
| R3-6 | IP throttle 수치·경계 부재 (FIX-IN-PACKAGE) | 한도 10/1m·실패 정의·성공 시 불변·원자적 reservation·경계 표, #270 수정 limiter 재사용 | D9, AC-011 · T-018 |

### 결정 변경 (Revision 3)

- D5: SA 판별에서 `sid` 부재 요건을 **삭제**하고 `client_id==azp`를 필수 AND 조건으로 승격(Revision 2의 “`sid` 부재” 문구는 실험으로 반증됨).
- D4: `MACHINE_LDAP_ROOT_DNS` 직렬화를 쉼표에서 세미콜론으로 변경, rootdn 3종을 내장 금지로 추가.
- D8: negative cache TTL 5m → 30s(=`MIN`), 성공 조회 시 전체 무효화; 기동 시 discovery 실패는 기동 실패가 아니라 재시도 상태(`D=none`).
- D2: “둘 다 존재 → 400”을 “유효 형식 Authorization + 쿠키 이름 존재 → 400”으로 정밀화.

### 미결

- 위 6건 외 새 미결 없음. 유지: `listTree` 머신 경로 초과 응답(T-013/T-006). 유지보수자 판단이 필요한 항목: 머신 활성 시 `UI_TRUSTED_PROXIES=private` 금지와 `MACHINE_LDAP_ROOT_DNS` 필수 입력(둘 다 Revision 2에서 도입, 재확인 요청); 정상 SA 토큰에 `client_id` 등을 요구하므로 lightweight/mapper 제거 client는 의도적으로 거부됨(fail closed)을 수용해야 한다.

## Revision 4 (2026-10-07)

T-005 재검토 3라운드(Codex): ACL·rootdn·서비스 계정 규칙은 OK(ACL은 FIX-IN-CODE로 T-026에 라이브 읽기 확인 추가), 남은 FIX-IN-PACKAGE 3건을 처리했다. 상태는 `Proposed / awaiting review`이며 재검토 대기다.

| # | 지적 (판정) | 처리 | 위치 · 검증 |
|---|---|---|---|
| R4-1 | JWKS 표: t=29 negative 항목이 t=30에도 401(“30s”와 모순), 다른 kid 실패가 negative에 선점됨, STALE의 위조 서명이 백그라운드 조회를 촉발하는데 “0회” (FIX-IN-PACKAGE) | **하나의 결정적 표**로 재작성: 조회 예산 게이트 `R`(성공 후 +30s, 실패 후 backoff), negative 항목 키=kid·만료=삽입 시점의 `R`(결과를 바꾸지 않는 메모, 조회 완료마다 비움), 평가 순서(예산 게이트→negative→backoff→stale), STALE의 known-kid 위조 서명은 응답 401이되 백그라운드 조회는 예산 `G` 안에서만, 30s는 표에서 **도출**, 시나리오 a–h의 정확한 조회 횟수·복구 테스트 | JWKS·discovery 상태 기계, AC-008, AC-016, D8 · T-019, T-025 |
| R4-2 | 중복 세션 쿠키 → 401 규정이 `middleware.go:30`(첫 쿠키만 읽음)과 충돌 (FIX-IN-PACKAGE) | 기존 동작 유지로 결정: Authorization 없을 때 쿠키 경로 불변(첫 쿠키만, [유효, 무효]=200·[무효, 유효]=401 회귀 테스트), “중복이면 401”은 `Authorization` 헤더 줄에만; Authorization 있을 때 쿠키는 이름 존재 여부만(→400). Origin gate는 상태 변경 메서드+`Origin` 존재 시에만(이미 일치) | 인증 경로 분리 규칙, AC-006 · T-012 |
| R4-3 | IP throttle: 예약 해제 경로, 실패 0건·예약 가득 시 Retry-After, 60s 경계 포함 여부 (FIX-IN-PACKAGE) | 예약은 정확히 한 번 defer 해제(성공·401 확정·503·403·취소·타임아웃·panic), 누락 대비 10s 자동 만료; 실패 0건+예약 가득은 고정 `Retry-After: 1`, 실패 ≥N은 `max(1, ⌈W−나이⌉)`; 경계는 **포함형**(정확히 60s는 아직 셈, 60s+1ms부터 풀림, 기존 `loginLimiter`와 동일 의미); N−1/N/N+1/정확히 60s 경계 표; 상태 상한은 #270 | D9, AC-011 · T-018 |
| R4-4 | ACL 라이브 증거 (FIX-IN-CODE) | 적용 후 실제 `olcAccess` 순서를 읽어 확인, 운영자 추가 선행 allow가 있는 구성(c) 추가 | AC-018 · T-026 |
| R4-5 | 서비스 계정 판별 근거 보강 (OK, 서술 요청) | AND 규칙 유지, `service-account-*` 사람 이름을 전역 예약으로 보지 않음, Keycloak의 `serviceAccountClientLink` 사람 인증 차단(Codex가 26.7.4 `AuthenticationProcessor` 확인)에 기댐을 명시 | D5 표 · T-028 |

### 결정 변경 (Revision 4)

- D8: negative cache 만료 기준을 고정 TTL 30s에서 “삽입 시점의 다음 조회 허용 시각 `R`”로 변경(30s 거부 상한은 표에서 도출되는 성질로 격하).
- D9: IP throttle 경계를 포함형으로 확정, reservation 해제 경로·Retry-After 규칙 추가.
- D2: 중복 세션 쿠키는 기존 브라우저 동작을 유지(Authorization 헤더에만 중복 거부 규칙).

## Revision 5 (2026-10-07)

T-005 재검토 4라운드(Codex): 설계 차단 없음, 정밀도·일관성 결함 5건만 지적됐다. 새 장치를 추가하지 않고 정의만 고쳤다.

| # | 지적 | 처리 | 위치 |
|---|---|---|---|
| R5-1 | `R`은 조회 완료 기준인데 시나리오는 `δ=0`을 가정 | 테스트 모델 명시(시작 `t_s`·소요 `δ`·완료 `t_c`, `G`는 시작 시점, `R`은 완료 기준, 기본 `δ=0`); f를 f1(`δ=0`: 0/30/90/210)과 f2(실패 `δ=5s`: 시작 0/35/100, t=100 복구)로 분리; g의 200은 완료 시각 | JWKS 상태 기계 |
| R5-2 | 예산 상한 `⌈T/30⌉` vs `1+⌈T/30⌉` 불일치, discovery→JWKS 계수 | 닫힌 구간 `[t0, t0+T]`에서 시작 ≤ `1+⌈T/30⌉`로 통일; discovery+JWKS는 **1회 refresh = 예산 1건** | 불변식 ①, AC-016, 검증 표, T-019 |
| R5-3 | 폭주 요구 “오류는 401” vs 조회 실패 503 | AC-016이 상태 기계 표의 조건별 규칙을 참조(정상 조회 후 미지 kid 401, 조회 실패·backoff 503) | AC-016 |
| R5-4 | “잘못된 Authorization은 모든 경우 401”이 매트릭스와 충돌 | 보호 경로에서 앞선 게이트 통과 후로 한정, 정본은 매트릭스 | AC-006 |
| R5-5 | AC-018 검증 표 2구성 vs T-026 3구성 | 표를 3구성(운영자 선행 allow, `olcAccess` 순서 읽기)으로 동기화 | 검증 표, AC-018 |

### Acceptance (2026-10-07)

T-005 재검토 5라운드(Codex): 4라운드는 정밀도 5건을 남겼고(JWKS 시험 모델·예산 구간 정의·응답 분리, selectAuth 문장 범위, ACL 검증표 동기화) Revision 5가 처리했다. 5라운드는 새 모순 1건(`CHANGE.md` 테스트 모델의 "응답은 조회 완료 뒤" 문장이 행 3의 즉시 응답과 충돌)만 남겼고, 조회를 기다리는 요청으로 한정해 해소했다. 최종 확인은 **PASS**. 유지보수자(사용자) 지시에 따라 상태를 `Accepted`로 바꾸고 구현을 TASKS.md 순서로 단계 병합한다(기본 꺼짐, 단계마다 독립 검토).

### Implementation notes (unit 1 fix round, 2026-10-07; clarifications, no design change)

- D17: **HEAD on the machine path.** The matrix is silent on HEAD. `headPreMiddleware` rewrites HEAD to GET before routing, so the machine path judges the method the client *sent*: HEAD is refused exactly like any non-GET (after verification: 401 before 403, then 403 `scope_denied`, no bind, no handler). A cookie session's HEAD is unchanged. OPTIONS is not rewritten and stays class N (204/404, `Authorization` ignored).
- D18: **Audience `account`.** `MACHINE_OIDC_AUDIENCE` equal (case-insensitive, trimmed) to `account` is a startup failure, and the verifier rejects `account` as an audience regardless of configuration (Keycloak's default `aud`, D5).
- D19: **Comma-joined DN lists.** Besides ParseDN equality, startup fails when the machine bind DN equals ANY contiguous run of RDNs (every i..j, ParseDN-equivalent comparison) of a configured admin/service-account/rootdn entry: a comma-joined list is one long valid DN containing each real DN as such a run (leading, second, middle...). Side effect, accepted: a bind DN identical to a pure suffix such as the directory base is refused too (not a sensible machine identity). A "repeated suffix" check was rejected: legitimate DNs can look the same.
- D20: **One deadline per refresh.** Discovery and JWKS share one 5 s context deadline (`RefreshTimeout`), per the "one refresh" accounting.

### Implementation notes (unit 2, 2026-10-07; clarifications, no design change)

- D21: **Tree child cap.** `listTree`'s body is a bare array, so a machine listing of more than 1000 children is refused with 422 `size_limit_exceeded` rather than cut (T-006 open item). Human responses are unchanged. The cap bounds the response; the per-child `hasChildren` probes are bounded by the request deadline.
- D22: **Where the DN guard runs.** A DN outside `LDAP_BASE_DN` is refused in `serve`, before the execution step, so a refused DN costs no LDAP connection (AC-015: no search; this is stronger). The handlers repeat the check (`machineDNGuard`). A malformed DN is still the handlers' 400 (`validate.DN` first), never a 403.
- D23: **Machine failures are 503.** On a machine request a directory failure that is not a domain error (lost connection, an expired request deadline, a canceled client) answers 503 `unavailable` instead of the human path's 500, because the execution step, not the handler, owns that failure. A panic keeps its 500. The audit reason distinguishes `deadline`, `canceled`, `upstream_error`.
- D24: **Deadline mechanics.** The request deadline applies only when the context carries one: `Dialer.Bind` bounds the dial and the connection's operations, and a watchdog closes the connection at the deadline or when the client cancels, which also ends a search blocked on the wire. Without a deadline (the interactive login path) none of this runs. Fix round: the watchdog is armed right after the TCP connect and BEFORE StartTLS (a per-operation timeout cannot bound a TLS handshake); the ldaps handshake is bounded by the dialer deadline. Human sessions have no deadline, so their dial behaviour (including its lack of a handshake bound) is unchanged.
- D23 (fix round): **Strict secondary reads.** The machine execution step marks its context (`ldapclient.WithStrictSecondaryReads`). In such a context an infrastructure failure (lost connection, expired deadline) of listTree's child probes or getMonitor's contextCSN/accesslog follow-ups is returned, hence 503 and an audit failure line, instead of a 200 with missing fields. Server answers (no access, no such object, size limit) stay the documented empty result, and contexts without the mark behave exactly as before.
- D25: **Server-level rejections are not audited.** Requests the Go HTTP server rejects before any handler runs (oversized headers 431, malformed request line 400, TLS failures) never reach the application, so REQ-009's "one line per Authorization-carrying request" holds for every request that reaches the handler chain and not for those. Chosen over a server-layer hook because an `http.Server` ErrorLog/ConnState hook does not see the parsed Authorization header, and a fabricated line without it would be a weaker, misleading audit record. **Where such requests leave a trace:** only in an access log of whatever sits in front of the backend (ingress, load balancer, reverse proxy). In the default directly exposed configuration there is no ingress and the backend has no server access logger; the Go HTTP server answers 431 and a malformed-request-line 400 without an `ErrorLog` entry, so such a request is recorded NOWHERE (not in the audit, access or error logs). The same holds for other rejections that happen before a handler runs: header read timeouts, other request-parse rejections, connection-level TLS failures and the TLS termination point when TLS ends at an ingress (the backend never sees those requests), and HTTP/2 stream or connection errors raised by the server before the handler. Operators who need a record of these must enable access logging at the ingress or proxy; the chart documentation (T-030) must say so. There is no cheap, sound server-layer alternative inside the backend: an `http.Server` ErrorLog/ConnState hook cannot tell whether the rejected request carried an `Authorization` header. Pinned by `TestMachineAudit_ServerLevelRejectionsAreNotAudited`.

### Implementation notes (unit 3, 2026-10-07; clarifications, no design change)

Documentation and proof only: the operator guide [machine-ldap-account.md](../../machine-ldap-account.md) and the live proof `scripts/test/test-machine-acl-readonly-live.py` (T-015, T-026, AC-018). No change to `image/entrypoint.sh`, the chart or the backend.

- D26: **Secret attribute list (T-015 derivation).** Rule `{0}` lists `userPassword,shadowLastChange,pwdHistory,pKCS8PrivateKey,userPKCS12,oathSecret,oathEncKey,oathTokenPIN`, derived from the schema this image loads (`core`, `cosine`, `inetorgperson`, `nis`, plus the `ppolicy` and `otp` overlays). The rule shape, order and `by * break` are as accepted above; only the attribute list grew. Live-proven: `userPassword`, `shadowLastChange`, `pwdHistory` (a value exists after a password change, `pwdInHistory` 5). The other attributes are only proven to be accepted by slapd.
- D27: **Config changes bind as `cn=admin,cn=config`, not ldapi EXTERNAL.** In this image ldapi EXTERNAL has no `cn=config` access for uid 999 or root (`No such object (32)`); the config administrator of `02-cn-config-admin.ldif` (admin password) over the local ldapi socket works and is the documented path. The ACL takes effect online.
- D28: **A search must start inside `B`.** `M` has no access to the base entry, so with `B` narrower than the root a search that starts at the root is `noSuchObject` even for entries in `B`. Not a leak; it means narrowing `B` makes root-level calls (`listTree` of the root, `getEntry` outside `B`) fail. The default `B` (`LDAP_BASE_DN`) is what the unit 2 live test exercises through the UI.
- D29: **Password proof form.** The default password policy has `pwdSafeModify: TRUE`: a `replace` or `ldappasswd` of `userPassword` is refused by the policy overlay before any ACL decides, so it cannot prove the ACL. The proof uses the one self-service form the policy accepts (delete the old value and add the new one in one modify): it succeeds for an ordinary user and for `M` before the rules, and is `insufficient access (50)` for `M` after them. The same policy has `pwdLockout: TRUE` (5 failures / 900 s): a wrong `MACHINE_LDAP_BIND_PASSWORD` locks `M` and every machine request becomes 503 until an admin deletes `pwdAccountLockedTime` (guide, section 13).
- D30: **Resolved (#277): `LDAP_REPLICATION_IDENTITY=prepare`/`dedicated` and the machine rules coexist in a defined order.** Layout: `olcAccess` `{0}` = the replication identity rule (always first; the entrypoint's "is the first stored value" check is unchanged), `{1}`-`{3}` = the three machine rules, then the image's own rules in their original order. Both install orders converge on it: (A) prepare first, then the machine LDIF shifted to `{1}`-`{3}` (guide 5.1); (B) the machine LDIF at `{0}`-`{2}` first, then prepare, whose `add: olcAccess {0}` pushes the machine rules to `{1}`-`{3}` (no entrypoint change was needed, and the entrypoint refusals are untouched). The one unsupported sequence stays refused by prepare itself: the plain `{0}`-`{2}` LDIF applied on a node whose identity rule is already `{0}` moves it to `{3}` and the next start is refused (observed in a manual run of the combined test with the wrong apply command: identity rule at `{3}`, container never ready; not a committed check). Rollback is independent: the documented machine rollback detects the offset (identity rule at `{0}` => delete `{3}`,`{2}`,`{1}`, else `{2}`,`{1}`,`{0}`) and refuses when the three indexes are not the machine rules; the identity side is rolled back by deleting `{0}` (checked to be the identity rule) and its `olcLimits` value, after which the machine rules are `{0}`-`{2}` again (the image never removes a stored identity rule, also not when switching back to `admin`). Evidence: `scripts/test/test-machine-acl-with-identity.sh` (both orders, three restarts each, read-only machine DN, read-only/TLS-only identity, both rollbacks) and configuration (d) of `scripts/test/test-machine-acl-readonly-live.py` (exact `{1}`-`{3}` read back, byte-exact rollback). Not covered: a multi-node cluster (cn=config is per node; apply on every node), `dedicated` end to end (same ACL path, only `prepare` was started).
- D31: **Reservation lifetime and the authentication deadline.** An IP reservation (D9) is held for the whole request: the authentication phase and then the execution step, which starts its own `MACHINE_REQUEST_TIMEOUT` only at the LDAP step. The self-expiry was `MACHINE_REQUEST_TIMEOUT` (minimum 1 s) while authentication can wait up to two 5 s JWKS refreshes, so a live request could lose its reservation and the per-IP "N minus failures" bound broke (Codex reproduction: N=1, timeout 1 s, two simultaneous authentications and two failures admitted). Fix: the authentication phase now has one explicit deadline `machineAuthTimeout` = 2 x `FetchTimeout` = 10 s (context passed to the verifier; the JWKS wait honors it), and the reservation self-expires after `authentication deadline + MACHINE_REQUEST_TIMEOUT + 1 s`, so it outlives the longest possible request. Reaching the authentication deadline fails closed with 503 `Retry-After: 1` (audit reason `deadline`), releases the reservation and is not counted as a failure (503 is never a failure, D9). A verification that succeeds only after the deadline (a key source that ignored the context) is also refused with 503. Escape hatch: a truly leaked reservation is still reclaimed at its expiry. Cost: a leaked reservation now blocks up to ~16 s (default timeout) instead of 10 s. Not covered: a handler that ignores its context after the execution deadline.
- D32: **Explicit `UI_TRUSTED_PROXIES` CIDRs trust only those CIDRs.** `ipExtractorFor` passed only `TrustIPRange` options to Echo's XFF extractor, which keeps its defaults (loopback, link-local, private networks) trusted unless disabled, so with `UI_TRUSTED_PROXIES=10.0.0.0/8` a private peer such as `192.168.50.2` outside the list could forge `X-Forwarded-For` and get a fresh failure budget per request (Codex reproduction: failure limit 1, `XFF=198.51.100.1` 401, again 429, `XFF=198.51.100.2` 401 with `peer_failures=0`). Fix: the three defaults are switched off in explicit-list mode, so an unlisted peer keys on its own address. `none` and `private` are unchanged. This is a deliberate behaviour change for operators who set explicit CIDRs and relied on implicit private-network trust (shared by the login limiter and the machine limiter only; the machine audit line has no IP field): list every proxy CIDR explicitly. No other extractor option or default-trust setting exists in the unit; the other limiter TTLs (JWKS cache, neg cache, failure window) guard no in-flight work.
- Replication (code reading, not run on a cluster): `olcSyncrepl` exists only on the main mdb database with `searchbase=$LDAP_ROOT_DN`; `cn=config` is not replicated. The machine account entry replicates, the ACL does not: apply and verify on every node and again after a fresh config volume.

## Close-out audit (2026-10-07)

감사 기준: `origin/main` `5c74f73`(단위 A0–A5b #269 #272 #274 #276 #278 #279 #281, 수정 #273 #282 병합 후). 문서만 바꿨다(코드 변경 없음; 별도 커밋으로 테스트 스크립트의 `assert`를 실제 raise로 바꿨다). 판정 어휘: **MET** = main에 증명 산출물이 있고 이 감사가 실행 가능한 것은 직접 실행함, **PARTIAL**, **NOT MET**. 라이브 Keycloak 스크립트는 다시 돌리지 않았고 CI 결과와 [EVIDENCE.md](EVIDENCE.md)의 기록을 인용한다.

### 이 감사가 실제로 실행한 것

| 확인 | 명령 | 결과 |
|---|---|---|
| 단위·계약 전체 | `cd ui/backend && go test ./internal/httpapi ./internal/machineauth ./internal/config ./internal/ldapclient -count=1 -v` | 네 패키지 `ok`, 최상위 테스트 `--- PASS` 526 · FAIL 0 · SKIP 0(머신 외 테스트 포함) |
| 경쟁 검사 | 같은 네 패키지 `-race -count=1` | 네 패키지 `ok` |
| 정적 | `go vet ./internal/...` | 종료 0 |
| 전체 모듈 | `go test ./... -count=1` | 나머지 패키지 `ok`; `cmd/server`·`web`은 이 작업 트리에 프런트 빌드(`web/dist`)가 없어 `pattern all:dist: no matching files found`로 **setup failed**(환경 문제, 코드 실패 아님; 이 감사에서 빌드하지 않음) |
| OpenAPI 집계 | `jq` (`ui/backend/internal/httpapi/openapi/openapi.json`) | 오퍼레이션 53, `security: []`(공개) 8, `machineBearer` 보유 8(전부 `get`: 비-GET 0), `securitySchemes` = `cookieAuth`·`machineBearer`; 보호 45 − 허용 8 = 거부 37 |
| 차트 | `scripts/test/test-chart-machine-auth.sh` | `PASS` 40줄, `FAIL`·기타 줄 없음 |
| 선택 재실행 | `TestMachine_FeatureOffIgnoresBearer`·`TestMachine_EveryProtectedOperationExercised`·`TestSelectAuth_Matrix`·`TestOpenAPIMachine*` 등 `-v` | 전부 `--- PASS` |
| CI(라이브) | `gh run list --workflow machine-keycloak-e2e.yml` | PR 마지막 헤드 `d41d338` 실행 **37555431534 success**; main 병합 커밋 `5c74f73` push 실행 **37557393281** → **success** |

### 요구사항 REQ-001–018

| REQ | 판정 | 증명 산출물(단위 → 라이브) |
|---|---|---|
| 001 | MET | `machineauth/verifier_test.go` `TestVerify_PositiveControl`·`_NegativeTable`(48 하위 케이스)·`_SignatureAndAlgorithmAttacks`·`_TimeBoundaries`, `review_test.go` `TestVerify_AccountAudienceNeverAccepted` → `test-machine-keycloak-live.py`(음성 40종 × 두 모드, bind 26→26), `test-machine-keycloak-settings-live.py` |
| 002 | MET | `httpapi/machine_test.go` `TestMachine_EveryProtectedOperationExercised`(45 전수: 8 도달·37 403·bind 0)·`_NewProtectedGetWithoutAllowlistIsDenied`·`_ScopeResolution` → keycloak-live(거부 37+HEAD+scope 부족+민감 DN, bind 29→29) |
| 003 | MET | `machine_contract_test.go` `TestOpenAPIDeniedOperationsNeverCarryMachineBearer`·`TestOpenAPINoNonGetCarriesMachineBearer`·`TestMachine_NonGetAlwaysDenied`, `jq` 8/37 |
| 004 | MET | `config/machine_test.go` `TestMachine_BindDNEquivalence`(변형 12종)·`_StartupFailures`·`_RootDNsAreSemicolonSeparated`·`_SSOServiceAccountCollision`, `TestMachineExec_BindFailureIs503AndNeverFallsBack`·`_RunsHandlersAsTheMachineIdentity` → `test-machine-acl-readonly-live.py`(세 구성 349 검사, 변이 11종, `api-credentials-e2e.yml`). `LDAP_REPLICATION_IDENTITY=prepare`와의 결합은 #277에서 정의·시험(복제 `{0}` + 머신 `{1}`–`{3}`, 증명 구성 (d), `test-machine-acl-with-identity.sh`) |
| 005 | MET | `ldapclient/secret_boundary_test.go` `TestAuditDTONeverEmitsReqModValues`·`TestEntryRedactedAttrsIsPinned`, `TestMachineGuard_EntryAndTreeAreBoundedToBaseDN` → keycloak-live(과권한 bind, 응답 17개에서 비밀 값 0건, accesslog `reqMod` 10건 시드) |
| 006 | MET | `TestSelectAuth_Matrix`·`TestMachine_DuplicateCookiesUnchanged`·`_AuthorizationShapes`·`_PublicAuthRoutesRejectAuthorization`·`_OriginGateStaysOutermost`·`_CORSNotExtended` → keycloak-live(쿠키+bearer 400, Origin 403, preflight, bind 0) |
| 007 | MET | `config` `TestMachine_InheritsSSOIssuer` → keycloak-live가 LDAP 모드와 SSO 모드를 모두 실행(71 검사) |
| 008 | MET | `machineauth/keyset_test.go` `TestKeySet_A…H`(정확한 조회 횟수)·`_F1_*`·`_F2_*`, `TestMachine_KeySourceOutageIs503WithRetryAfter`·`_StartupDiscoveryPolicy` → `test-machine-jwks-live.py`(D: 발급자 중단 상태 기동 → 32 s 뒤 재시작 없이 200) |
| 009 | MET(예외 D25) | `machine_audit_test.go` `TestMachineAudit_ExactlyOneLinePerAuthorizedRequest`·`_EarlyReturnsAndFields`·`_NoTokenMaterialInLogsOrResponses`·`_ServerLevelRejectionsAreNotAudited` → keycloak-live(8개 컨테이너 로그 323,801 B 스캔 0건, 허용·위조·scope 거부 각 1줄) |
| 010 | MET(replica별) | `machine_limiter_test.go`(`TestMachineIPThrottle_BoundaryN`·`_InclusiveWindowEdge`·`_ReleasedOnEveryExitPath`·`_TensOfThousandsOfIPsStayWithinDefaultCap`, `TestMachineOrdering_*`, `TestMachineClientBudget_*`), `machine_limiter_ttl_test.go`, `machine_limiter_panic_test.go` → `test-machine-execution-live.py`(소한도 컨테이너), keycloak-live(client 429·위조 XFF) |
| 011 | MET | `machineauth` `TestVerify_TimeBoundaries`, `config` `TestMachine_BoundaryAccepted` |
| 012 | MET | `machine_contract_test.go` 계약 테스트 5종 + `jq` 집계 |
| 013 | MET(제한: #284) | `TestMachine_FeatureOffIgnoresBearer`·`config` `TestMachine_DefaultOffParsesNothing`·`TestMachineLimits_AbsentWhenFeatureOff`·`TestMachineAudit_FeatureOffEmitsNothing`, `scripts/test/test-chart-machine-auth.sh`(40 PASS; 꺼짐 렌더가 origin/main과 바이트 동일은 T-016 기록) → 드릴 (c). 클러스터 설치는 실행하지 않음 |
| 014 | MET | `TestMachineAudit_NoTokenMaterialInLogsOrResponses`, 차트 `secretKeyRef`만(`ui-deployment.yaml`, 차트 테스트), 로그 스캔 0건 |
| 015 | MET | `TestDNWithinBase`·`TestMachineGuard_*`·`TestMachineMonitor_AccessLogOnlyWithAuditRead` → keycloak-live·execution-live(accesslog/config/Monitor DN 403·LDAP 연결 0) |
| 016 | MET | `TestKeySet_*`·`TestHTTPFetcher_Limits`·`config` `TestMachine_InsecureHTTPException` → jwks-live(A–E) |
| 017 | MET | `machine_boundary_test.go` `TestMachineCursorBinding`·`TestMachineCursor_Isolation` → keycloak-live(client 간·사람↔머신) |
| 018 | MET(제한: #280, #284) | `test-machine-revocation-drill.py`(18 검사: 비활성화 후 구토큰 통과, allowlist 제거 후 교체·옛 컨테이너 0·같은 토큰 401, 진행 중 요청 정상 종료, 기능 off), [machine-auth-operations.md](../../machine-auth-operations.md) |

### 수용 시나리오 AC-001–019

| AC | 판정 | 단위/계약 | 라이브(스크립트) · 비고 |
|---|---|---|---|
| 001 | MET | `TestMachineExec_RunsHandlersAsTheMachineIdentity`, `TestMachineAudit_ExactlyOneLinePerAuthorizedRequest` | keycloak-live: 허용 8개 200, 12 요청 = slapd accesslog 머신 DN bind 정확히 12·관리자 bind 0 |
| 002 | MET | `TestVerify_NegativeTable`(48), `_SignatureAndAlgorithmAttacks`, `TestMachine_VerificationFailuresAre401WithGenericBody` | keycloak-live 음성 40종·양성 대조, bind 26→26 |
| 003 | MET | `TestMachine_EveryProtectedOperationExercised`, `_NewProtectedGetWithoutAllowlistIsDenied` | 거부 배치 bind 29→29 |
| 004 | MET | `TestMachine_NonGetAlwaysDenied`, `TestOpenAPIDeniedOperationsNeverCarryMachineBearer` | 거부 37개는 `openapi.json`에서 도출해 전수 |
| 005 | MET | `TestAuditDTONeverEmitsReqModValues`, `TestMachineMonitor_AccessLogOnlyWithAuditRead` | 과권한 컨테이너 응답 17개, 비밀 값 0건 |
| 006 | MET | `TestSelectAuth_Matrix` 외 위 REQ-006 목록 | 혼용·Origin·preflight |
| 007 | MET | — | keycloak-live: LDAP 모드·SSO 모드 모두 |
| 008 | MET | `TestKeySet_A…H`, `_E_StaleBoundary` | jwks-live (D), keycloak-live JWKS 중단(캐시 kid 200·미지 kid 503+`Retry-After: 30`·복구) |
| 009 | MET | `config` 변형 테스트, `TestMachineExec_DeadlineBoundsBindAndSearch`·`_SlotIsTakenBeforeBind`·`_ClientCancelReleasesConnectionAndSlot`, `ldapclient` `TestBindHonoursContextDeadline`·`TestStartTLSHandshakeHonoursContextDeadline` | execution-live: 지연 프록시, 중단 50건 후 `cn=Monitor` 기준선 복귀; keycloak-live: 잘못된 비밀번호 503 |
| 010 | MET | `TestMachineAudit_*`(조기 반환 13행, `_RateRows`) | 라이브는 허용·검증 실패·scope 거부 3행만, 나머지 행은 단위(알려진 한계) |
| 011 | MET | `machine_limiter_test.go` 경계 표 전 행, `machine_limiter_exit_test.go` | execution-live·keycloak-live. 실제 프록시 뒤 XFF는 미실행(#284); 명시 CIDR 신뢰 오류는 #282로 수정 |
| 012 | MET(대체) | `TestVerify_TimeBoundaries` 경계 표 | 실제 만료는 기본 300 s가 아니라 3 s 수명 client + skew 0 컨테이너로 확인(문서화된 대체) |
| 013 | MET | `machine_contract_test.go`, `TestOpenAPIMachineBearerEqualsCodeAllowlist` | `jq`: 8/37/8/53 |
| 014 | MET | `TestMachine_FeatureOffIgnoresBearer`(401 `not logged in`), 꺼짐 전용 테스트 3종 | 드릴 (c). 기존 e2e 무변경 통과는 PR #281 헤드 `d41d338`에서 `E2E (kind)` 37555431568·`UI E2E (browser)` 37555431582·`UI fixture E2E (docker)` 37555431580·`API + credentials E2E (docker)` 37555431684·`CI` 37555431545 모두 success, main 병합 커밋에서는 `CI` 37557393337·`UI E2E (browser)` 37557393384·`API + credentials E2E (docker)` 37557393386 success(EVIDENCE §7.4) |
| 015 | MET(대체) | `TestDNWithinBase`, `TestMachineGuard_*` | accesslog/config/Monitor DN 403·LDAP 연결 0. "가드를 끈 빌드의 ACL 백스톱"은 머신 DN의 직접 ldapsearch 거부(ACL 스크립트)로 대체 |
| 016 | MET | `TestKeySet_A_RandomKidFlood`…`_G_Rotation`, `TestHTTPFetcher_Limits` | jwks-live: 위조 3,080건 → 조회 0, 무작위 kid 24,196건/65 s → 조회 3(상한 4) |
| 017 | MET | `TestMachineCursorBinding`, `TestMachineCursor_Isolation` | keycloak-live |
| 018 | MET | — | `test-machine-acl-readonly-live.py`: 세 구성 `349 checks passed, 0 failed`, 변이 11종 전부 탐지 |
| 019 | MET(docker replica) | — | `test-machine-revocation-drill.py` 18 검사. Helm/pod 교체는 아님(#284), 10 s 초과 요청 종료는 #280 |

### #214 판정

**수용 기준 충족; 이슈 #214는 닫을 수 있다**(닫기는 이 PR 병합 후 유지보수자의 별도 결정). 근거: 이슈 본문의 범위 세 항목 — (1) Keycloak 서비스 클라이언트 bearer 검증(iss/aud/exp/JWKS) (2) 서버측 오퍼레이션별 scope·읽기 전용 기본값·최소권한 LDAP bind 매핑 (3) 쿠키 흐름과의 계약 분리·`userPassword` 비노출 — 이 REQ-001–018 전부 MET로 단위와 실제 Keycloak 라이브에서 증명됐고, 릴리스 게이트(`release.yml`의 `release_critical`에 job `machine bearer auth (real Keycloak)`)가 연결돼 있다. PARTIAL·NOT MET인 REQ/AC는 없다.

**수용된 제한(각각 문서화됨)**

- **#277 / T-034 / D30** — 해결: 복제 신원 규칙 `{0}` + 머신 규칙 `{1}`–`{3}`, 두 설치 순서와 독립 롤백([machine-ldap-account.md](../../machine-ldap-account.md) 5.1·11·12절, 시험 `test-machine-acl-with-identity.sh`).
- **#280** — 정상 종료 대기가 10 s 고정이라 `MACHINE_REQUEST_TIMEOUT` > 10 s이면 교체 시 긴 요청이 끊긴다(기본값 10 s에서는 드릴이 통과).
- **#266** — 사람 세션 현재 비밀번호 시도 무제한(머신 경로와 무관한 기존 한계).
- **#284(신규)** — `ui.machineAuth`는 차트 렌더·kubeconform까지만 증명, 클러스터 설치·실제 ingress XFF·Helm replica 교체·다중 노드 ACL은 미실행.
- **#285(신규)** — 머신 쓰기 scope(비목표). **#286(신규)** — 즉시 폐기(introspection)·API key·mTLS(비목표). **#287(신규)** — 앱 내 API 문서 화면이 머신 호출 가능 표시를 안 함(표시 문제).
- subtree 단위 권한은 별도 패키지 [oidc-organization-authorization](../oidc-organization-authorization/CHANGE.md)의 몫이다.
- 구조적 한계: D25(핸들러 이전 서버 거절은 로그 없음, ingress 로그 필요), limiter는 replica별, `audit.read`·`server.settings.read`는 기본 꺼짐, 백오프 기저는 `MIN_REFRESH`(기본값에서만 30 s→5 m와 동일, EVIDENCE §5.3).
- **T-033**(OpenForge 공개 상태 게시)은 외부 조치로 열려 있다: 소유자는 유지보수자 dasomel, 전제는 "이 감사 병합 후".

### 이 감사가 확인하지 못한 것

- 라이브 스크립트 4개와 ACL 증명을 다시 돌리지 않았다(CI 실행 id와 EVIDENCE §4–§5 기록을 인용; 단위 시험 수치만 직접 재현).
- `go test ./...`의 `cmd/server`·`web`은 프런트 빌드 부재로 이 작업 트리에서 컴파일하지 못했다. `cmd/server/main.go`의 종료 코드는 이 감사에서 실행하지 않았다(#280은 `cmd/server/main.go:101`의 `10*time.Second`를 읽어 확인).
- 기존 `ui-e2e`·`e2e` 전체는 로컬에서 재실행하지 않았다. 대신 위 CI 실행 id를 인용했다. main 병합 커밋의 `E2E (kind)`·`UI fixture E2E (docker)`·`Keycloak LDAP federation E2E`·`SSSD E2E`는 감사 시점에 아직 pending이었고(`Upgrade and rollback E2E`는 진행 중) 그 결과는 주장하지 않는다.
- 문서의 curl·kubectl·helm 예시는 코드 읽기로만 대조했다(5b 기록 그대로).
