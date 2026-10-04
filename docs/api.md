# ldapium HTTP API

ldapium 웹 콘솔이 사용하는 `/api` JSON API를 스크립트와 AI 에이전트가 쓸 수 있도록 정리한 문서입니다.
인증 모델은 변경되지 않았습니다. **세션 쿠키만** 지원합니다.

- 기계 판독용 명세 (OpenAPI 3.1, 실행 중인 빌드와 항상 일치): `GET /api/v1/openapi.json`
- AI용 요약 인덱스: `GET /llms.txt`
- 서버/버전 탐색 (공개): `GET /api/v1/meta`
- 명세는 `ui/backend/internal/httpapi/openapi/openapi.json`에 있으며, 라우트와 어긋나면 `api_contract_test.go`가 실패합니다.

## 개요

| 항목 | 내용 |
|---|---|
| Base | 콘솔과 같은 origin, 경로 `/api` |
| 형식 | 요청/응답 모두 JSON (`Content-Type: application/json`) |
| 인증 | 쿠키 `ldapium_session` (HttpOnly, SameSite=Lax) |
| 권한 | LDAP 모드: 로그인한 DN의 ACL. SSO 모드: 서비스 계정의 ACL |

OpenAPI 문서의 표식: `security: []` = 공개, `x-admin: true` (+ `x-required-role`) = 관리자 DN 필요, 그 외 = 세션 필요.

## 인증 흐름

`GET /api/v1/meta`의 `authMode`를 먼저 확인합니다. `ldap`이면 스크립트 로그인이 가능하고, `sso`이면 브라우저 OIDC 로그인만 가능합니다.

```bash
BASE=http://localhost:8080

# 1. 로그인 (쿠키 저장). 실패가 반복되면 429 + Retry-After
curl -sS -c jar.txt -H 'Content-Type: application/json' \
  -d '{"identity":"cn=admin,dc=example,dc=org","password":"..."}' \
  "$BASE/api/login"

# 2. 쿠키로 호출
curl -sS -b jar.txt "$BASE/api/me"
curl -sS -b jar.txt "$BASE/api/users"

# 3. 로그아웃 (204)
curl -sS -b jar.txt -c jar.txt -X POST "$BASE/api/logout"
```

## 엔드포인트

공개: `GET /api/v1/meta`, `/api/v1/openapi.json`, `/api/auth/config`, `/api/health/ldap`, `POST /api/login`, `POST /api/logout`, `GET /api/sso/start`, `/api/sso/callback`. 나머지는 세션 필요.

| 그룹 | 엔드포인트 |
|---|---|
| Discovery | `GET /api/v1/meta`, `GET /api/v1/openapi.json`, `GET /api/auth/config`, `GET /api/health/ldap` |
| Auth | `POST /api/login`, `POST /api/logout`, `GET /api/me`, `GET /api/sso/start`, `GET /api/sso/callback` |
| Server | `GET /api/server-settings`, `GET /api/monitor`, `GET /api/audit/actions` |
| Directory | `GET /api/tree`, `GET /api/entry`, `POST /api/entry/move`, `GET /api/password-policies` |
| Users | `GET/POST/PUT/DELETE /api/users`, `POST /api/users/password`, `/lock`, `/unlock` |
| Groups | `GET/POST/PUT/DELETE /api/groups`, `POST/DELETE /api/groups/members` |
| Application profiles (`x-admin`) | `GET /api/v1/application-profile-types`, `GET /api/v1/applications`, `GET/PUT /api/v1/applications/integration-methods[/{method}]`, `GET/PUT/DELETE /api/v1/applications/{id}/integration-profile`, `GET .../keycloak-roles`, `GET .../roles`, `GET .../integration-status`, `POST .../integration-verify`, `POST .../keycloak-role-operations`, `GET .../configuration-export`, `POST .../mapping-preview` |
| Backups (`x-admin`) | `GET /api/v1/backups`, `PUT /api/v1/backups/policies`, `PUT /api/v1/backups/connections`, `DELETE /api/v1/backups/connections/{id}`, `POST /api/v1/backups/jobs/{kind}` |

프로필/백업 그룹은 설정된 관리자 DN만 호출할 수 있으며(403), 기능이 꺼져 있으면 404입니다.

## 오류 형식

두 가지 형태가 공존하며 둘 다 명세에 정의되어 있습니다. 클라이언트는 `error`를 먼저, 없으면 `message`를 읽으세요.

| 형태 | 사용처 |
|---|---|
| `{"error": "..."}` | 디렉터리/인증 핸들러(`respondErr`). 500은 `requestId` 포함, 상세 메시지는 서버 로그에만 기록 |
| `{"message": "..."}` | 입력 검증, 세션(401), 관리자 게이트, 프로필, 백업, Keycloak, 로그인 429 |

존재하지 않는 `/api` 경로는 404, 허용되지 않는 메서드는 405 (`Allow` 헤더 포함)이며 둘 다 `{"error": "..."}` 형태입니다.

## ETag / If-Match

프로필, 통합 방식, 백업 설정은 낙관적 동시성 제어를 사용합니다.

```bash
# 읽기: ETag 응답 헤더가 현재 revision
curl -si -b jar.txt "$BASE/api/v1/applications/grafana/integration-profile" | grep -i '^etag'
# ETag: "3"

# 쓰기: If-Match에 그 값을 그대로. 새로 만들 때는 "0"
curl -sS -b jar.txt -X PUT \
  -H 'Content-Type: application/json' -H "Origin: $BASE" -H 'If-Match: "3"' \
  -d @profile.json "$BASE/api/v1/applications/grafana/integration-profile"
```

- 쓰기 엔드포인트(프로필, 방식, 백업, Keycloak, 매핑 미리보기)는 `Origin`이 서버 자신의 origin과 같아야 하고(아니면 403) `Content-Type: application/json`이어야 합니다(아니면 415).
- `If-Match` 누락 428, revision 불일치 412, 형식 오류는 엔드포인트에 따라 400 또는 428.
- Keycloak 역할 작업은 정수 revision 대신 스냅샷의 따옴표 붙은 64자리 hex fingerprint(ETag)를 사용합니다.
- 응답 본문의 `revision`, `status`는 서버가 관리하므로 요청에 넣으면 거부됩니다.

## 제한

| 항목 | 값 |
|---|---|
| `GET /api/users`, `/api/groups` | 최대 5000건. 초과 시 `truncated: true` (커서 없음) |
| `GET /api/audit/actions` | `limit` 1-200 (기본 50), `before`에 이전 응답의 `nextBefore` |
| 로그인 | IP별 실패 횟수 제한, 초과 시 429 + `Retry-After` |
| 요청 본문 | 프로필 64KiB, 방식/연결 32KiB, 정책/역할 작업/미리보기 16KiB |
| 매핑 미리보기 | `claim_values` 최대 100개 |

## 상태 코드

| 코드 | 의미 |
|---|---|
| 200 / 201 / 202 / 204 | 성공 / 생성됨 / 비동기 시작됨(백업) / 본문 없음 |
| 303 | SSO 콜백 결과 리다이렉트 (성공 시 `/`, 실패 시 `/login?sso_error=`) |
| 400 / 415 / 422 | 잘못된 요청 / 잘못된 Content-Type / 검증 실패 |
| 401 / 403 | 세션 없음·만료 / 권한 없음(ACL, 관리자 DN, Origin) |
| 404 / 405 | 대상 없음·기능 비활성·알 수 없는 경로 / 허용되지 않는 메서드 |
| 409 / 412 / 428 | 충돌 / revision 불일치 / If-Match 필요 |
| 429 / 502 / 503 | 로그인 제한 / Keycloak 실패 / Keycloak 연결 비활성 |

## 안전 규칙

- `userPassword`는 어떤 응답에도 포함되지 않습니다(해시 포함).
- `POST /api/users/password`에서 `password`를 생략하면 서버가 생성한 `generatedPassword`를 한 번 반환합니다. 비밀로 취급하고 로그에 남기지 마세요.
- 삭제, 엔트리 이동, Keycloak 역할 작업, 백업 실행은 되돌릴 수 없습니다. 맹목적 재시도 금지.

## 아직 지원하지 않는 것

머신 토큰/서비스 주체, CORS, 페이지네이션 커서, `/metrics`, 백업 job ID는 지원하지 않습니다.
설계 방향은 [`docs/changes/api-integration/PLAN.md`](changes/api-integration/PLAN.md)를 참고하세요.
