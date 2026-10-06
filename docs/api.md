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
| Users | `GET/POST/PUT/PATCH/DELETE /api/users`, `POST /api/users/password`, `/lock`, `/unlock` |
| Groups | `GET/POST/PUT/PATCH/DELETE /api/groups`, `POST/DELETE /api/groups/members` |
| Application profiles (`x-admin`) | `GET /api/v1/application-profile-types`, `GET /api/v1/applications`, `GET/PUT /api/v1/applications/integration-methods[/{method}]`, `GET/PUT/DELETE /api/v1/applications/{id}/integration-profile`, `GET .../keycloak-roles`, `GET .../roles`, `GET .../integration-status`, `POST .../integration-verify`, `POST .../keycloak-role-operations`, `GET .../configuration-export`, `POST .../mapping-preview` |
| Backups (`x-admin`) | `GET /api/v1/backups`, `PUT /api/v1/backups/policies`, `PUT /api/v1/backups/connections`, `DELETE /api/v1/backups/connections/{id}`, `POST /api/v1/backups/jobs/{kind}`, `GET /api/v1/backups/jobs`, `GET /api/v1/backups/jobs/{id}`, `POST /api/v1/backups/jobs/{id}/cancel` |

프로필/백업 그룹은 설정된 관리자 DN만 호출할 수 있으며(403), 기능이 꺼져 있으면 404입니다.

## 오류 형식

모든 `/api` 오류(4xx/5xx, 알 수 없는 경로, 허용되지 않는 메서드, 패닉 포함)는 하나의 JSON 본문입니다.

```json
{
  "error": "profile changed; reload before saving",
  "message": "profile changed; reload before saving",
  "code": "revision_conflict",
  "requestId": "5nQe3kXyZpLwTqA0vB9cJmRdUsHf2GoE",
  "retryable": false
}
```

| 필드 | 의미 |
|---|---|
| `error` | 사람이 읽는 문구(주 필드). 4xx는 핸들러의 문구, 5xx는 `code`별 고정 문구이며 내부 오류 내용은 담지 않습니다 |
| `message` | `error`와 동일한 값의 사본. **deprecated alias**이며 `/api/v1`에서는 유지하되 새 클라이언트는 `error`를 읽으세요 |
| `code` | 안정적인 snake_case 코드. 아래 표의 닫힌 집합이며 이름은 바뀌지 않고 새 코드는 추가만 됩니다. 모르는 코드는 상태 코드로 처리하세요 |
| `requestId` | `X-Request-Id` 응답 헤더와 같은 값. 서버 로그에서 원인을 찾을 때 사용합니다 |
| `retryable` | 같은 요청을 그대로 다시 보내면 성공할 수 있는지 |

예외(봉투가 아닌 것): 성공·리다이렉트(`/api/sso/*`), `GET /api/health/ldap`의 프로브 본문 `{"reachable": bool}`(200/503), 본문이 없는 응답(OPTIONS 204, HEAD). 이들도 `X-Request-Id` 헤더는 가집니다.

`retryable`이 `true`인 429와 일시적 503에는 `Retry-After`(정수 초)가 항상 있고, 그 외 응답에는 없습니다. `412`/`428`은 다시 읽은 뒤 새 요청이 필요하므로 `false`, `500`은 일부만 적용됐을 수 있으므로 `false`입니다. `502 upstream_failed`는 GET/HEAD에서만 `true`입니다.

| `code` | 상태 | 발생 |
|---|---|---|
| `invalid_request` | 400 | 본문 파싱 실패, 필수 값 누락, 입력 검증, 표에 없는 4xx |
| `invalid_credentials` | 401 | 로그인/비밀번호 확인 실패 |
| `unauthenticated` | 401 | 세션 쿠키 없음 또는 서명 불일치 |
| `session_expired` | 401 | 세션 만료 |
| `forbidden` | 403 | 디렉터리 ACL 거부, Keycloak 경계 |
| `admin_required` | 403 | 프로필/백업 관리자 DN이 아님 |
| `origin_mismatch` | 403 | 쓰기 요청의 `Origin`이 서버 origin과 다름(프로필·백업·Keycloak 쓰기는 항상, 그 외 쓰기는 `Origin` 헤더가 있을 때) |
| `not_found` | 404 | 대상 없음, 알 수 없는 경로 |
| `feature_disabled` | 404 | 기능이 꺼져 있음(프로필, 백업, SSO, 비밀번호 로그인) |
| `method_not_allowed` | 405 | 허용되지 않는 메서드(`Allow` 헤더) |
| `conflict` | 409 | 디렉터리 상태와 충돌 |
| `already_exists` | 409 | 이미 있음 |
| `backup_busy` | 409 | 백업이 실행 중(`retryable: true`). `active_job_id`·`active_kind`가 실행 중인 job을 가리킨다(조회용이며 내 요청의 job이라는 증명은 아니다) |
| `job_not_found` | 404 | 형식이 맞지 않거나 보관에 없는 백업 job ID |
| `job_not_cancellable` | 409 | 실행 중이 아닌 job(이미 `cancelled`는 200 멱등) 또는 재기동 뒤 인수한 고아 워커 job |
| `persistence_unavailable` | 503 | 시작·취소 요청 기록을 쓸 수 없음: 워커를 시작하지 않았고 신호도 보내지 않았다(`retryable: true`, `Retry-After`) |
| `revision_conflict` | 412 | `If-Match` 불일치 |
| `partial_failure` | 500 | 사용자 생성 후 비밀번호 단계가 끝나지 않음(`retryable: false`). 오류 본문의 유일한 예외로 `state`와 `dn` 키가 더 있음(아래 "사용자 생성 실패 처리") |
| `unsupported_media_type` | 415 | `Content-Type`이 `application/json`이 아님 |
| `validation_failed` | 422 | 형식은 맞지만 검증 실패 |
| `idempotency_key_conflict` | 409 | 같은 `Idempotency-Key`의 같은 요청이 아직 처리 중(`retryable: true`) |
| `idempotency_key_reused` | 422 | 같은 키가 다른 요청(method·경로·쿼리·본문)에 쓰임 |
| `idempotency_outcome_unknown` | 409 | 쓰기 결과를 알 수 없음(연결 유실·패닉) 또는 기록의 지문 키가 더 이상 없음. 리소스를 읽어 확인(`retryable: false`) |
| `idempotency_capacity` | 503 | 멱등 기록 저장소가 가득 참: 새 키만 거부(`retryable: true`, `Retry-After`) |
| `idempotency_unsupported` | 422 | 이 서버에서 멱등 기능이 꺼져 있는데 키가 붙음 |
| `if_match_required` | 428 | `If-Match` 필요 |
| `login_rate_limited` | 429 | 로그인 실패 제한(`retryable: true`, `Retry-After`) |
| `internal` | 500 | 예상 못 한 실패(문구 고정, `requestId`로 로그 조회) |
| `upstream_failed` | 502 | Keycloak 작업 실패 |
| `keycloak_disabled` | 503 | Keycloak 관리자 연결 비활성(`retryable: false`) |
| `unavailable` | 503 | 일시적 의존성 장애(`retryable: true`, `Retry-After`) |

후속 변경(#214–#217)이 쓸 이름(`token_invalid`, `token_expired`, `scope_denied`, `cursor_invalid`, `size_limit_exceeded`, `idempotency_*` 외의 이름)은 예약되어 있으며, 처음 방출하는 변경이 이 표·OpenAPI `Error.code` enum·코드 골든 목록을 함께 갱신합니다. 새 오류 조건은 코드 한 줄을 추가하고, 5xx 문구는 고정 표에 추가합니다.

4xx 문구에는 DN·비밀이 없습니다. LDAP 서버가 돌려준 진단 문구는 해당 코드의 고정 문구(예: `invalid input`)로 대체되고 원문은 `requestId`와 함께 서버 로그에만 남습니다. 단 비밀번호 변경 화면이 사용자에게 보여 주는 알려진 비밀번호 정책 문구(ppolicy·ppm의 고정 문구, 예: `Password fails quality checking policy`)는 DN을 제거한 형태로 그대로 전달됩니다. 목록에 없는 새 문구는 검토 후 추가될 때까지 가려집니다.

존재하지 않는 `/api` 경로는 404, 허용되지 않는 메서드는 405 (`Allow` 헤더 포함)입니다.
HEAD는 GET 핸들러가 있는 모든 경로에서 본문 없이 GET과 동일하게 동작하며, OPTIONS는 등록된 `/api` 경로에서 204 No Content와 `Allow` 헤더를 반환합니다.

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

- **쓰기 Origin 게이트:** 로그인·로그아웃을 포함한 모든 상태 변경 요청(POST/PUT/PATCH/DELETE)은 `Origin` 헤더가 **있으면** 서버 자신의 origin(스킴·Host)과 같아야 하고, 아니면 핸들러 실행 전에 403 `origin_mismatch`입니다(`Origin: null`, 빈 값 포함). `Origin` 헤더가 없는 요청(curl, 스크립트, 서비스)은 영향이 없어 위 로그인 예시처럼 그대로 동작합니다. 이 게이트는 끌 수 없습니다. **영향:** `Origin`을 항상 보내는 비브라우저 HTTP 클라이언트는 그 값을 서버 origin으로 맞추거나 헤더를 빼야 합니다. 리버스 프록시/Ingress는 브라우저가 보낸 `Host`를 그대로 전달하고 TLS 종단 시 `X-Forwarded-Proto: https`를 붙여야 합니다(서버는 `Host`와 `X-Forwarded-Proto` 계열 헤더로 자기 origin을 계산하고, 비교 전에 호스트 대소문자·후행 점·기본 포트(:80/:443)·IPv6 표기를 정규화하며 `X-Forwarded-Host`는 쓰지 않습니다). `Host`를 재작성하면 정상 UI 쓰기도 403이 됩니다.
- 쓰기 엔드포인트(프로필, 방식, 백업, Keycloak, 매핑 미리보기)는 `Origin`이 서버 자신의 origin과 같아야 하고(아니면 403) `Content-Type: application/json`이어야 합니다(아니면 415).
- `If-Match` 누락 428, revision 불일치 412, 형식 오류는 엔드포인트에 따라 400 또는 428.
- Keycloak 역할 작업은 정수 revision 대신 스냅샷의 따옴표 붙은 64자리 hex fingerprint(ETag)를 사용합니다.
- 응답 본문의 `revision`, `status`는 서버가 관리하므로 요청에 넣으면 거부됩니다.

### 사용자·그룹·엔트리 이동의 조건부 쓰기 (opt-in)

사용자·그룹 목록 항목에는 `etag` 필드가, `GET /api/entry`에는 `ETag` 응답 헤더가 있습니다. 값은 항목의 `entryCSN`을 따옴표로 감싼 강한 ETag이며(예: `"20261006123456.123456Z#000000#001#000000"`), 정수 `revision`을 쓰는 프로필·백업과는 별개입니다. 읽을 수 없으면(ACL) 생략됩니다. 응답 본문의 `attributes`에는 들어가지 않습니다.

```bash
curl -si -b jar.txt "$BASE/api/entry?dn=uid=jdoe,ou=people,dc=example,dc=org" | grep -i '^etag'
# ETag: "20261006123456.123456Z#000000#001#000000"

curl -sS -b jar.txt -X PATCH -H 'Content-Type: application/merge-patch+json' \
  -H 'If-Match: "20261006123456.123456Z#000000#001#000000"' \
  -d '{"dn":"uid=jdoe,ou=people,dc=example,dc=org","mail":"new@example.org"}' "$BASE/api/users"
```

- `If-Match`는 선택입니다. 헤더가 없거나 `*`이면 예전과 같이 무조건 적용됩니다. 적용 대상: `PUT`/`PATCH`/`DELETE`(사용자·그룹), `POST /api/users/lock`·`/unlock`, `POST`/`DELETE /api/groups/members`(그룹의 ETag), `POST /api/entry/move`.
- 조건은 디렉터리가 쓰기 연산 안에서 직접 평가합니다(LDAP Assertion Control, RFC 4528, critical). 읽기-비교-쓰기 틈이 없어 같은 ETag로 동시에 쓰면 정확히 하나만 성공하고 나머지는 412입니다. 불일치는 412 `revision_conflict`이며 아무것도 쓰이지 않습니다.
- 약한 태그(`W/`), 태그 목록, 따옴표 없는 값, 형식 오류, 반복된 `If-Match`는 400입니다. `POST /api/users/password`는 `If-Match`를 지원하지 않으며(RFC 3062 확장 연산에 조건을 실을 수 없음) 보내면 400입니다.
- ETag는 디렉터리 내부 기록(비밀번호 정책의 실패한 바인드 기록, 선택적 lastbind)에도 바뀝니다. 이 경우 불필요한 412가 나올 수 있으며, 다시 읽고 재시도하면 됩니다. 그룹 구성원 변경은 구성원 사용자 항목의 ETag를 바꾸지 않습니다.
- **ETag의 보장 범위(한계):** ETag는 항목의 `entryCSN`이며, **그 항목에 직접 쓰인 속성**의 변경만 반영합니다. 디렉터리가 CSN 없이 바꾸는 값은 반영하지 않습니다: 사용자의 `memberOf`(memberof 오버레이), 그리고 refint가 삭제된 사용자를 그룹 `member`에서 지우는 변경. 따라서 refint 정리 뒤에도 낡은 태그의 그룹 `PUT`/`DELETE`가 통과할 수 있고, `GET /api/entry`는 그 경우 서로 다른 표현에 같은 ETag를 돌려줍니다. 원자적인 부분(조건 평가와 쓰기가 한 연산)은 영향받지 않으며, 직접 쓴 속성에 대한 보장만 유효합니다. `memberOf`·구성원 목록은 필요할 때 다시 읽으세요.
- **복제 한계:** 다중 provider 복제 환경에서는 조건이 쓰기를 받는 노드에서만 평가됩니다. 다른 노드에서 읽은 태그는 아직 반영되지 않아 정상 쓰기도 412가 될 수 있고, 같은 태그로 서로 다른 노드에 동시에 쓰면 둘 다 통과한 뒤 `entryCSN` 시각 기준 last-write-wins로 한쪽이 조용히 사라질 수 있습니다. 단일 쓰기 노드로 라우팅하세요.

### PUT과 PATCH

`PUT /api/users`는 본문에 없는 선택 필드(`givenName`, `mail`, `department`, `organization`, `organizationalUnit`)를 **삭제**합니다. `PUT /api/groups`는 생략한 `description`을 삭제합니다. 일부 필드만 바꾸려면 `PATCH`(JSON Merge Patch, `application/merge-patch+json` 또는 `application/json`)를 쓰세요. 키 없음 = 유지, 문자열 = 설정, `null` = 삭제입니다. 빈 문자열, `uid`, `password`, 알 수 없는 키, `cn`/`sn` 삭제, 바꿀 필드가 없는 본문은 400입니다.

### 사용자 생성 실패 처리

비밀번호가 있는 `POST /api/users`는 Add 후 비밀번호 설정 두 단계입니다. 비밀번호 단계 전에 새 항목이 이 요청이 만든 손대지 않은 항목임을 확인합니다(`entryUUID`·`entryCSN`·`creatorsName`·`modifiersName`·`createTimestamp`·`modifyTimestamp`, Add와 같은 세션 잠금 안에서 읽음). 비밀번호 단계가 실패하면 그 신원에 묶인 조건부 삭제로 항목을 지웁니다.

| 결과 | 응답 | 의미 |
|---|---|---|
| 되돌림 | 평범한 오류 봉투(정책 거부는 400 `invalid_request`, 권한은 403 `forbidden`, 그 외 500 `internal`), 문구가 `user not created`로 시작(500은 고정 문구) | 항목이 남지 않음. 다시 시도해도 안전. 디렉터리 진단은 허용 목록(예: ppolicy/ppm 정책 문구, DN 제거)만 노출 |
| 되돌릴 수 없음 | 500 `partial_failure` + `"state":"partial"`, `dn` | 검증된 삭제가 거부됨. 항목이 남아 있고 비밀번호가 적용됐는지는 알 수 없음. 항목을 조회한 뒤 `POST /api/users/password`로 설정하거나 `DELETE /api/users?dn=` |
| 확인 불가 | 500 `partial_failure` + `"state":"unknown"`, `dn` | 보상 삭제를 보냈으나 응답을 받지 못해 항목이 남았는지 알 수 없음. 먼저 항목이 있는지 조회 |
| 신원 변경 | 500 `partial_failure` + `"state":"identity_changed"`, `dn` | Add 직후 읽은 항목이 이 요청이 만든 손대지 않은 항목임을 증명하지 못함(다른 생성자·수정자, 생성 후 수정, 교체, 읽기 불가). **비밀번호를 설정하지 않았고 아무것도 삭제하지 않았습니다.** 그 항목을 신뢰하기 전에 확인 |

`partial_failure`는 오류 봉투 다섯 키 외에 `state`와 `dn`을 싣는 유일한 응답입니다(`dn`은 201이 돌려줬을 값). 본문 문구는 고정이며 `state`가 구분합니다.

**남는 경쟁(해결 불가):** 신원 확인과 비밀번호 설정(RFC 3062 확장 연산) 사이 수 밀리초는 닫을 수 없습니다. go-ldap v3.4.14의 `PasswordModifyRequest`는 제어를 실을 수 없어(`UserIdentity`/`OldPassword`/`NewPassword`만 있음) assertion을 붙일 수 없습니다. 그 사이 다른 관리자가 항목을 교체하면 그 항목에 비밀번호가 설정될 수 있습니다. 같은 바인드 DN의 다른 세션이 만든 수정은 `modifiersName`으로 구별되지 않습니다. 신원 읽기와 보상 삭제에는 컨텍스트·타임아웃이 없어 공유 연결을 그 시간만큼 점유하며(기존 공유 연결 한계, 컨텍스트 인식 검색 래퍼는 #215 D215-13 계획), 이 변경에서 새 메커니즘을 만들지 않았습니다.

## Idempotency-Key

응답이 유실된 뒤 재시도가 두 번 실행되지 않게 하는 선택 헤더입니다(change package `api-conditional-writes`, 결정 D216-6~D216-12).
적용 대상: `POST`/`PUT`/`PATCH`/`DELETE /api/users`, `POST /api/users/password`, `/api/users/lock`, `/api/users/unlock`, `/api/groups`(POST/PUT/PATCH/DELETE), `/api/groups/members`(POST/DELETE), `POST /api/entry/move`, `POST /api/v1/backups/jobs/{kind}`. 그 밖의 라우트와 `GET`/`HEAD`/`OPTIONS`에서는 무시됩니다.

```bash
curl -b jar -H "Idempotency-Key: $(uuidgen)" -H 'Content-Type: application/json' \
  -d '{"uid":"jdoe","cn":"J Doe","sn":"Doe"}' http://localhost:8080/api/users
```

- 키: 한 개, 16-128자, `[A-Za-z0-9._~:-]`(따옴표 문자열 허용). 형식 위반·중복 헤더는 400.
- 범위: (요청한 신원, 키). 다른 신원이 같은 키를 써도 독립이며 첫 신원의 결과·존재 여부는 드러나지 않습니다.
- 같은 키 + 같은 요청(method, 경로, 정렬된 쿼리, 정규화한 JSON 본문; `If-Match`는 제외)은 최초의 상태·본문·`Location`을 `Idempotent-Replayed: true`와 함께 재생하고 디렉터리에 다시 쓰지 않습니다. 재생은 `If-Match` 평가보다 먼저입니다. 같은 키 + 다른 요청은 422 `idempotency_key_reused`, 아직 처리 중이면 409 `idempotency_key_conflict`(`retryable`).
- 본문: 키가 붙은 요청의 본문은 정확히 하나의 JSON 값이어야 합니다. 뒤따르는 데이터, 잘못된 JSON, 중복(대소문자만 다른 것 포함) 필드명, DELETE의 본문, `application/json`이 아닌 Content-Type은 핸들러 실행 전에 400 `invalid_request`이며 키를 점유하지 않습니다. 키가 붙은 요청의 본문 상한은 64KiB이고 초과도 413이 아니라 400 `invalid_request`입니다(변경 문서 D216-7).
- 저장되는 결과: 2xx, `partial_failure`, `idempotency_outcome_unknown`(연결 유실·패닉으로 결과를 모를 때; 같은 키는 같은 응답을 재생하고 두 번째 실행은 없음). 쓰기에 도달하기 전에 거부된 요청(검증·인증·`If-Match` 412)과 디렉터리의 확정 오류 응답(404, 409, 403 등)만 저장하지 않으므로 같은 키로 다시 시도할 수 있습니다. 서버 오류가 디렉터리의 확정 응답인지 알 수 없으면(응답 유실 포함) 불확정으로 기록합니다. 요청 중 클라이언트가 끊겨도 쓰기는 끝까지 수행되고 결과가 기록됩니다. 처리 중 기록은 시간으로 풀리지 않습니다.
- 비밀: 기록에는 요청 본문·비밀번호·`generatedPassword`·요청자 DN이 없습니다(키·요청 지문은 HMAC 값뿐). `POST /api/users/password`는 명시적 `password`일 때만 키를 받고(재생 본문은 `{}`), 빈 `password`+키는 422 `validation_failed`.
- 저장소: 프로세스 메모리, 기본 TTL 24h(`UI_IDEMPOTENCY_TTL`, 1m-7d), 전체 10,000건·신원당 1,000건. 상한에 도달하면 **새 키만** 503 `idempotency_capacity`(`Retry-After`)로 거부하고 만료되지 않은 기록은 쫓아내지 않습니다.
- **한계:** 기록은 재시작·복제본 간에 유지되지 않습니다. 재시작 뒤 같은 키로 재시도하면 새 요청으로 실행되어(생성은 409 `already_exists`, 삭제는 404) 오늘의 동작이 됩니다. 중단된 요청이 디렉터리에 남긴 효과는 복구할 수 없습니다. 그래서 `UI_IDEMPOTENCY_ENABLED`(기본 `false`, 차트 `ui.idempotency.enabled`)가 켜져 있을 때만 키를 처리하고, 꺼져 있으면 키가 붙은 쓰기를 조용히 무시하지 않고 422 `idempotency_unsupported`로 거부합니다. 차트는 복제본이 1개일 때만 켭니다. 활성 여부는 `GET /api/server-settings`의 `idempotencyEnabled`.
- 백업 시작(`POST /api/v1/backups/jobs/{kind}`)은 메모리 스위치와 무관하게 키를 **영속 job 기록**에 둡니다(키 해시·지문·`key_id`만, API로는 나오지 않음). 같은 키 + 같은 kind는 같은 job의 `202` + `Location`을 재생하고(본문의 `status`는 그 시점의 현재 상태, 재시작 뒤에도 유효, 다른 키는 `backup_busy`가 우선), 다른 kind는 422 `idempotency_key_reused`입니다. 영속 지문 키 `UI_IDEMPOTENCY_KEY_FILE`이 없으면 키는 422 `idempotency_unsupported`로 거부됩니다(차트는 백업이 켜지면 백업 PVC의 `.idempotency/key`로 지정). 키 파일은 0600, 디렉터리 0700, 첫 기동에 한 번 생성되며 두 줄(`current`, `previous`)로 회전합니다. 기록의 `key_id`에 맞는 키가 없으면 409 `idempotency_outcome_unknown`입니다. job 기록은 job 보관(최대 200건·90일)을 따릅니다.

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
| 400 / 415 / 422 | 잘못된 요청(형식이 틀린 `If-Match`·`Idempotency-Key` 포함) / 잘못된 Content-Type / 검증 실패(`idempotency_key_reused`·`idempotency_unsupported` 포함) |
| 401 / 403 | 세션 없음·만료 / 권한 없음(ACL, 관리자 DN, Origin) |
| 404 / 405 | 대상 없음·기능 비활성·알 수 없는 경로 / 허용되지 않는 메서드 |
| 409 / 412 / 428 | 충돌(`idempotency_key_conflict`·`idempotency_outcome_unknown` 포함) / revision·ETag 불일치(`revision_conflict`) / If-Match 필요(프로필·백업) |
| 500 | 예상치 못한 실패, 또는 `partial_failure`(사용자 생성 후 비밀번호 단계 미완료) |
| 429 / 502 / 503 | 로그인 제한(`Retry-After`) / Keycloak 실패 / Keycloak 연결 비활성 |

## 안전 규칙

- `userPassword`는 어떤 응답에도 포함되지 않습니다(해시 포함).
- `POST /api/users/password`에서 `password`를 생략하면 서버가 생성한 `generatedPassword`를 한 번 반환합니다. 비밀로 취급하고 로그에 남기지 마세요.
- 삭제, 엔트리 이동, Keycloak 역할 작업, 백업 실행은 되돌릴 수 없습니다. 맹목적 재시도 금지.

## CORS (기본 꺼짐)

기본값에서는 어떤 응답에도 `Access-Control-*`·`Vary: Origin` 헤더가 붙지 않고, `OPTIONS`는 위 설명대로 204와 `Allow`만 반환합니다. 환경 변수 `CORS_ALLOWED_ORIGINS`(쉼표 구분, 정확한 `scheme://host[:port]`만; 브라우저가 생략하는 기본 포트 `:80`/`:443`은 정규화로 제거됨)를 설정하면 켜집니다. `*`, `null`, 경로·쿼리·프래그먼트·사용자 정보, 빈 항목, 빈·범위 밖(1–65535 아님) 포트는 기동을 거부합니다. 차트는 `ui.cors.allowedOrigins`입니다.

- **읽기 전용입니다.** 목록에 있는 Origin에만 `Access-Control-Allow-Origin: <그 Origin>`·`Access-Control-Allow-Credentials: true`·`Access-Control-Expose-Headers: X-Request-Id, Retry-After, ETag`가 `GET`/`HEAD` 응답(오류 응답 포함)에 붙습니다. 일치하지 않는 Origin, `null`, 쓰기 메서드(POST/PUT/PATCH/DELETE) 응답에는 `Access-Control-*`가 붙지 않습니다.
- `Vary: Origin`은 활성화되면 **모든** 응답(Origin이 없는 요청, 일치·불일치, `OPTIONS` 포함)에 붙습니다. 공유 캐시가 한 Origin의 응답을 다른 Origin에 재사용하지 않게 하기 위해서입니다.
- 프리플라이트(`OPTIONS` + `Access-Control-Request-Method`)는 목록의 Origin이 `GET`·`HEAD`·`OPTIONS`를 요청할 때만 핸들러 앞에서 204로 허용합니다(`Allow-Methods: GET, HEAD, OPTIONS`, `Allow-Headers: Content-Type, Accept`, `Max-Age: 600`). 쓰기 메서드의 프리플라이트는 `Access-Control-*` 없이 일반 `OPTIONS`(204 + `Allow`)로만 답하므로 브라우저가 차단합니다.
- 쿠키는 `SameSite=Lax` 그대로입니다. 다른 사이트(registrable domain이 다른 origin)의 fetch/XHR에는 세션 쿠키가 실리지 않으므로, 이 목록은 같은 사이트의 다른 origin(예: `console.example.com` → `ldapium.example.com`)에서 읽기를 허용하는 용도입니다. 머신 클라이언트는 `Origin`을 보내지 않아 CORS가 필요 없습니다.
- 이 목록은 **쓰기에 아무 영향도 주지 않습니다.** 위 **쓰기 Origin 게이트**는 목록과 무관하게 서버 자신의 origin만 통과시키므로, 목록의 Origin이 보낸 쓰기(프리플라이트 없는 단순 POST, `/api/logout` 포함)도 403 `origin_mismatch`입니다. 교차 출처 쓰기 UI는 지원하지 않습니다.

## /metrics (프로세스 지표)

UI 백엔드 프로세스의 Prometheus 지표(`ldapium_ui_*`: 요청 수·지연·진행 중 요청, API 오류 코드별 수, 로그인 실패 사유별 수, 디렉터리 호출 수·지연, 활성 세션 수, Go·프로세스 컬렉터)입니다. slapd 지표는 기존 `openldap_exporter` 사이드카(포트 9330)가 냅니다.

- **기본 꺼짐.** 환경 변수 `METRICS_ADDR`(`host:port`, 예: `127.0.0.1:9331`)를 설정한 때만 별도 리스너가 뜨고 `GET /metrics`만 응답합니다(그 밖의 경로 404). 지표 포트는 공개 UI 포트(8080, `LISTEN_ADDR`)와 달라야 하며 같으면 기동이 거부됩니다. 인증은 없으므로(Prometheus 관례) 네트워크 경계로 보호합니다. 차트는 `ui.metrics.*`로 별도 Service·NetworkPolicy(허용 피어 필수)를 만들고 ServiceMonitor/PodMonitor는 기본 꺼짐입니다.
- **공개 포트의 `/metrics`**는 항상 `application/json` 404 오류 봉투(`code: not_found`)입니다. SPA의 `index.html`이 아닙니다.
- 라벨은 닫힌 집합입니다: `route`는 등록된 라우트 패턴 또는 `unmatched`, `method`는 GET/POST/PUT/PATCH/DELETE 또는 `other`, `code`는 위 오류 코드 표, 로그인 실패 `reason`은 `invalid_credentials`·`rate_limited`·`malformed`·`upstream`. 사용자·uid·DN·IP·요청 경로 원문·쿼리·오류 문자열은 라벨에도 값에도 들어가지 않습니다.

## 아직 지원하지 않는 것

머신 토큰/서비스 주체, 페이지네이션 커서, 백업 job ID는 지원하지 않습니다.
설계 방향은 [`docs/changes/api-integration/PLAN.md`](changes/api-integration/PLAN.md)를 참고하세요.
