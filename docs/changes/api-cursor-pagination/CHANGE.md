# Change: `GET /api/users`·`/api/groups` 서버측 커서 페이지네이션

- Change class: `B` (API 계약 추가, 백엔드) + `C` (opt-in 이미지·차트 설정 `LDAP_PAGED_TOTAL_LIMIT`, runtime/contract 변경 — **별도 커밋**, D215-14). 인증·스키마·ACL·자격 증명 경계는 건드리지 않는다.
- Owner: 미지정
- Related issue: [#215](https://github.com/dasomel/ldapium/issues/215) (출처 [api-integration PLAN P1](../api-integration/PLAN.md)). 연계: #218 오류 봉투([api-error-envelope](../api-error-envelope/CHANGE.md)), #214 머신 인증([machine-principal-auth](../machine-principal-auth/CHANGE.md))
- Status: `Accepted 2026-10-06 — maintainer instruction to process #215 (open questions resolved as recorded below); implementation requires T-001 and the image change in its own commit`
- Accepted by / date: 유지보수자 지시, 2026-10-06 (미해결 질문 Q1·Q2는 아래 Review record에 결정으로 기록)
- 작성일: 2026-10-06 (기준 커밋 `60dae0d`, 1차 검토 반영 개정)

> 설계 문서다. 코드·OpenAPI·이미지·차트는 변경하지 않았다. "검증 필요"는 T-002 라이브 스파이크에서
> 실제 이미지로 확인하기 전까지 사실로 취급하지 않는다.

## Problem

`GET /api/users`·`/api/groups`는 최대 5000건 + `truncated` 플래그만 제공하므로 그 이상은 HTTP로 조회할 수 없다. 외부 시스템·AI 에이전트(#214)는 전체 순회가 필요하다. `/api/audit/actions`만 `limit`/`before`로 페이징된다.

현재 구조(근거):

| 사실 | 위치 |
|---|---|
| 핸들러는 인자 없이 `ListUsers/ListGroups(ctx, cfg.BaseDN)` 호출, 응답 `{users\|groups, truncated}` | `ui/backend/internal/httpapi/user_handlers.go:12-18`, `group_handlers.go:12-18`, `dto.go:5-16` |
| RFC 2696 paged results(페이지 500)로 읽다 5000에서 자르고 `truncated=true` | `ui/backend/internal/ldapclient/search.go:10,19,31-61` |
| 검색은 `c.conn.Search(req)` — 컨텍스트·타임아웃 없는 동기 호출, 뮤텍스는 스캔 전체 동안 점유 | `search.go:43`, `users.go:39-40`, `groups.go:32-33` |
| 연결 생성 시 요청 타임아웃 미설정 | `ldapclient/dial.go:124-157`(`newConn`) |
| 순서는 slapd 반환 순서, 필터 고정 | `users.go:42`, `groups.go:35` |
| `sizeLimitExceeded`는 `mapErr`에 매핑이 없어 일반 500으로 떨어진다 | `ldapclient/errors.go:15-55` |
| 핸들러는 `UserSearchBase`가 아니라 `cfg.BaseDN` 전체를 검색(본 변경은 유지) | `user_handlers.go:13`, `dto.go:42` |
| OpenAPI·문서가 "커서 없음"을 명시 | `openapi.json:970,1532,4908-4926,4952-4970`, `docs/api.md:95`, `llms.txt:36` |
| 비관리자 `olcSizeLimit` 기본 10000, `olcLimits` 없음, rootDN 면제 | `image/entrypoint.sh:157-173`, `image/ldifs/01-cn-config.ldif:74`, `image/README.md:89` |

### 핵심 제약

1. **요청마다 bind하지 않는다.** 로그인 때 한 번 bind한 `*ldap.Conn` 하나를 세션이 보관하고(`dial.go:35-64`, `session/store.go:14-25`), 뮤텍스로 직렬화한다(`real_client.go:11-20`). 자격 증명은 저장하지 않는다(`store.go:16-18`) → 사용자 신원으로 두 번째 연결을 열 수 없다.
2. RFC 2696 쿠키는 연결에 묶인 서버 상태라 HTTP 요청 사이에 보관할 수 없다 → 커서는 서버 상태 없이 위치를 재구성해야 한다.
3. **서버 크기 제한은 paged search의 총합에 적용된다**(`size.prtotal`을 완화하지 않는 한 hard limit이 총합 기준, [OpenLDAP limits](https://openldap.org/doc/admin26/limits.html); T-002에서 이미지로 확인). 기본값(10000)에서 비관리자는 10000건을 넘는 스캔을 할 수 없다(D215-14).
4. 오래 걸리는 검색을 취소하려면 컨텍스트 인지 래퍼가 필요하다(D215-13). go-ldap v3.4.14의 `Search`는 블로킹이다.

### 이전 패키지와의 관계

[groups-pagination](../groups-pagination/CHANGE.md)(2026-10-02)이 이미 다룬 것: GroupsPage UI의 **클라이언트측** 페이지 이동(10/20/50/100, 첫/이전/다음/마지막, 검색·크기 변경 시 1쪽, 모바일, 브라우저 회귀). 그 패키지는 "UI paging은 가져온 엔트리에만 작동, 서버 truncation은 한계로 남음"을 명시했고 백엔드는 범위 밖이었다. 남은 것(= 본 패키지): 서버측 커서, 정렬·필터 범위, 동시 변경 의미, 5000 초과 순회, 서버 크기 제한 처리, OpenAPI/문서, 대규모 라이브 검증. UsersPage의 클라이언트 페이징(`UsersPage.tsx:65-67`)도 같은 한계를 가진다.

## Intent

기존 호출자 응답은 **바이트 단위로 불변**으로 두고, `limit`/`cursor`를 보내는 호출자가 (제한이 허용하는 신원에서) 10000건 이상을 누락·중복 없이 순회하게 한다. 제한에 걸리면 조용히 잘라내지 않고 명시적 오류로 알린다. 커서는 stateless, 키는 고정 전순서, 동시 변경 보장은 스냅샷이 아닌 증명 가능한 최소 보장이다. 지연·뮤텍스 점유는 청크 단위로 유한하게 묶는다.

## Scope

- In scope: `GET /api/users`·`/api/groups` 커서 모드; 커서·키 순수 함수; 컨텍스트 인지 청크 검색 래퍼; 페이지 조회·조립; 도메인 오류 `size limit`; opt-in `LDAP_PAGED_TOTAL_LIMIT`(이미지 + 차트 `ldap.limits.pagedTotal`, 별도 커밋); OpenAPI·`docs/api.md`·`llms.txt`; 단위·라이브·동시 변경·계약 테스트; 성능 측정.
- Affected: `ui/backend/internal/{httpapi,ldapclient,domain}`, `openapi/{openapi.json,llms.txt}`, `docs/api.md`, `image/{entrypoint.sh,ldifs/01-cn-config.ldif,README.md}`, `charts/ldapium/{values.yaml,templates/statefulset.yaml,README*.md}`, `scripts/`, CI 1개.

## Non-goals

- UI 변경(D215-11, 후속 이슈). 트리·`/api/groups/members` 멤버 목록 페이징.
- 임의 정렬·내림차순·임의 LDAP 필터, `total` 제공, 스냅샷 일관성.
- 기본 설정의 동작 변경(`LDAP_SIZE_LIMIT` 기본값, 기본 ACL). 새 설정은 opt-in이며 기본 동작 불변.
- #218 오류 봉투 정의, #214 머신 인증·rate limit 구현(참조만). GET 목록은 `If-Match`·`Idempotency-Key`를 요구하지 않는다.
- 레거시 `ListUsers/ListGroups`·`searchAllPaged` 수정(뮤텍스 장기 점유 등은 그대로 — 별도 이슈).

## Requirements

- `REQ-001` — 파라미터 없는 `GET /api/users`·`/api/groups`는 현재와 동일한 본문·순서·5000 상한·`truncated` 의미를 유지한다. 새 필드 없음.
- `REQ-002` — `limit`·`cursor`·`q`·`sort` 중 하나라도 있으면 커서 모드이며, 고정 전순서 `(정렬 키, DN)`의 엄격 증가 순으로 최대 `limit`건을 반환한다.
- `REQ-003` — 커서는 stateless·불투명·버전 포함 토큰이다. 변조, 타 로그인 세션(재로그인 포함)·타 리소스·타 `q`에서의 재사용은 거부한다.
- `REQ-004` — 제한이 허용하는 신원(rootDN 또는 `paged total`이 완화된 신원)으로 10000건 이상을 커서만으로 순회하면 변경이 없는 동안 누락·중복이 0이다.
- `REQ-005` — 동시 추가/삭제/이름 변경과 **두 단계 사이** 변경 하의 보장을 정확히 문서화하고 테스트로 고정한다.
- `REQ-006` — 필터는 `q` 하나(고정 속성, 길이 상한, 이스케이프)뿐이고, `sort`는 기본 키 외 값을 거부한다.
- `REQ-007` — `userPassword`는 어떤 페이지 응답에도 없다(기존 denylist 불변).
- `REQ-008` — 지연·점유를 유한하게 묶는다: `limit` 상한, 스캔 상한, 요청 deadline(컨텍스트 전파), 청크 단위 뮤텍스 해제, 세션당 동시 스캔 1.
- `REQ-009` — 잘못된 `limit`/`cursor`/`q`/`sort`는 400, 응답은 #218 봉투(`error`·`message`·`code`·`requestId`·`retryable`)를 따른다.
- `REQ-010` — OpenAPI(파라미터·응답·오류), `docs/api.md`, `llms.txt`를 갱신하고 드리프트 테스트가 고정한다.
- `REQ-011` — ACL로 숨겨진 엔트리는 해당 신원의 순회에서 제외되고, 커서는 로그인 세션(`Session.ID`)에 묶여 위치 정보가 세션 간에 재사용되지 않는다.
- `REQ-012` — 성능 예산을 정의하고 10k·50k에서 측정 증거를 남긴다. 미달 시 탈출구(D215-9).
- `REQ-013` — 서버 크기 제한에 걸리면 부분 결과·조용한 절단 없이 명시적 오류(`size_limit_exceeded`, retryable=false, 해결책 명시)를 반환한다.
- `REQ-014` — paged total 제한은 opt-in 이미지/차트 설정으로 완화할 수 있고, 기본값은 현 동작과 같다.
- `REQ-015` — 두 단계(키 선택 → 전체 속성 조회) 사이에 엔트리가 바뀌어도 방출 튜플은 항상 엄격 증가하고, 커서는 항상 전진하며 빈 페이지로 멈추지 않는다.

## Acceptance scenarios

### `AC-001` — 무파라미터 호환

- Covers: `REQ-001`
- Given 5001건 이상 사용자·그룹이 있는 디렉터리와 변경 전 응답 기록(T-004)
- When 파라미터 없이 `GET /api/users`·`/api/groups` 호출
- Then 키 집합이 `{users|groups, truncated}`뿐이고 `truncated=true`, 길이 5000, 순서가 기준선과 같다. 기존 단위·UI 테스트가 수정 없이 통과한다.

### `AC-002` — 제한이 허용되는 신원의 10000+ 무손실 순회

- Covers: `REQ-002`, `REQ-004`, `REQ-011`
- Given 12000 사용자·12000 그룹(대소문자 혼합·uid 없음·uid 중복·비ASCII 포함)과, (i) rootDN(관리자) 로그인 또는 (ii) `LDAP_PAGED_TOTAL_LIMIT=unlimited`로 기동한 이미지의 일반 사용자 로그인
- When `limit=200`으로 `hasMore=false`까지 `nextCursor`만 따라 순회
- Then 반환 DN 집합 == 해당 신원의 `ldapsearch` 기준 집합, 중복 0, 페이지 내·페이지 간 `(키, DN)` 엄격 증가, 마지막 페이지에 `nextCursor` 없음. (ii)에서 ACL이 일부를 숨기면 보이는 부분집합만 같은 규칙으로 순회한다.

### `AC-003` — 페이지 사이 동시 변경 의미

- Covers: `REQ-005`
- Given 순회 중 **페이지 사이**에 (a) 커서 앞쪽 키로 추가, (b) 뒤쪽 키로 추가, (c) 미방문 엔트리 삭제, (d) 이미 반환된 엔트리 삭제, (e) 미방문 엔트리를 앞쪽 키로 이름 변경, (f) 방문 엔트리를 뒤쪽 키로 이름 변경
- When 순회를 끝까지 진행
- Then 순회 내내 불변인 엔트리는 정확히 1회, (a)는 0회, (b)는 1회, (c)는 0회, (d)는 1회(이미 반환됨), (e)는 0회, (f)는 2회. 그 외 중복 없음. 이 표가 OpenAPI 설명과 같다.

### `AC-004` — 커서 변조·오용 거부

- Covers: `REQ-003`, `REQ-009`, `REQ-011`
- Given 유효 커서
- When 한 바이트 변조 / 잘림 / 알 수 없는 버전 / users 커서를 groups에 / 다른 `q` / **같은 DN으로 재로그인한 새 세션** / 다른 사용자 세션 / `SESSION_SECRET` 교체 / 1024바이트 초과 / 비 base64
- Then 전부 400 `cursor_invalid`(원인 구분 없는 일반 메시지, retryable=false), LDAP 조회 없음.

### `AC-005` — 파라미터 검증·필터 범위

- Covers: `REQ-006`, `REQ-009`
- Given `limit=0|201|abc`, `q`가 65자 이상·제어문자·`*()\`·NUL 포함, `sort=mail`
- When 호출
- Then `limit`·`sort`·`q` 위반은 422 `validation_failed`(#218 표의 기존 코드; 어느 파라미터인지는 `message`에 필드명만 적고 값은 되풀이하지 않는다). `q`의 특수문자는 리터럴로 이스케이프되어 필터 구조를 바꾸지 않는다(구성 필터 문자열 고정 + 퍼즈). `sort=uid`(users)·`sort=cn`(groups)은 허용.

### `AC-006` — `userPassword` 비노출

- Covers: `REQ-007`
- Given `userPassword`를 가진 사용자(과권한 bind 포함)
- When 모든 페이지 조회
- Then 응답 어디에도 `userPassword`(대소문자·`;binary` 포함)가 없다.

### `AC-007` — 유한 지연·뮤텍스 (즉시 중단은 보장하지 않는다)

- Covers: `REQ-008`
- Given 느린 LDAP(예: 사이에 지연 주입한 프록시 또는 큰 스캔)와, 같은 세션에서 병렬로 호출하는 다른 요청, 스캔 상한을 낮춘 주입 값, 취소된 요청 컨텍스트
- When 커서 모드 요청과 병렬 요청을 보냄
- Then (i) 커서 요청은 `listRequestTimeout`(기본 30 s) 안에 종료한다(초과 시 503 `scan_timeout`); (ii) 같은 세션의 다른 요청은 뮤텍스를 **청크 하나**(≤ `chunkTimeout` 5 s) 이상 기다리지 않는다; (iii) 상한 초과는 422 `scan_limit_exceeded`; (iv) 같은 세션의 두 번째 동시 커서 요청은 첫 요청이 끝나거나 자기 deadline까지 대기하고 초과 시 503 `unavailable`. 서버측 즉시 중단은 보장하지 않는다(D215-13).

### `AC-008` — OpenAPI·문서 드리프트

- Covers: `REQ-010`
- Given 변경된 `openapi.json`
- When `go test ./...`(ui/backend)
- Then 계약 테스트 통과, 새 파라미터·`nextCursor`·`hasMore`·400/422/503 응답이 스키마에 있고 "커서 없음" 문구가 모두 제거된다(`docs/api.md`, `llms.txt` 포함). 오류 코드 목록이 #218 골든 목록과 일치한다.

### `AC-009` — 성능 예산

- Covers: `REQ-012`
- Given 10k·50k 엔트리 로컬 단일 노드, `limit=50`·`200`
- When 라이브 스크립트로 페이지 지연 측정
- Then D215-9 예산을 만족하거나 미달 시 증거와 함께 탈출구가 채택된다. 명령·환경 기록.

### `AC-010` — (조건부·후속) UI 커서 채택 시 이전/다음

- Covers: `REQ-002`
- Given UI가 후속 이슈에서 커서 모드를 채택
- When 모킹 API로 다음/이전(이전은 클라이언트 커서 스택)
- Then 경계·빈 페이지·오류 복구가 동작한다. 본 패키지는 UI를 바꾸지 않으므로(D215-11) 후속 이슈에서 실행한다.

### `AC-011` — 기본 설정의 일반 사용자: 명시적 크기 제한 오류

- Covers: `REQ-013`
- Given 기본 설정(`LDAP_SIZE_LIMIT`=10000, `LDAP_PAGED_TOTAL_LIMIT` 미설정), 12000 엔트리, 일반 사용자 로그인
- When 파라미터 없는 `GET /api/users`(레거시)와 커서 모드 `GET /api/users?limit=50`
- Then 레거시는 5000건 + `truncated:true`로 불변. 커서 모드는 부분 페이지 없이 422 `size_limit_exceeded`(retryable=false, 메시지에 `q`로 좁히기·관리자 신원·`LDAP_PAGED_TOTAL_LIMIT` 안내). `q`로 후보를 10000건 이하로 좁히면 같은 신원으로 성공한다. 500·빈 성공 응답으로 떨어지지 않는다.

### `AC-012` — opt-in 이미지·차트 설정

- Covers: `REQ-014`
- Given `LDAP_PAGED_TOTAL_LIMIT` 미설정 / `50000` / `unlimited` / `abc`
- When 이미지 부트스트랩과 `helm template`
- Then 미설정이면 `cn=config`에 `olcLimits` 없음(기존과 동일), 값 설정 시 `olcLimits: {0}users size.prtotal=<값>`, `abc`는 기동 거부(`LDAP_SIZE_LIMIT`와 같은 검증), 차트는 `ldap.limits.pagedTotal` 미설정 시 env를 렌더하지 않는다. 설정은 새 데이터 볼륨에서만 적용(bootstrap-only)이며 기존 볼륨 절차가 문서화된다.

### `AC-013` — 두 단계 사이 변경

- Covers: `REQ-005`, `REQ-015`
- Given phase 1(키 선택)과 phase 2(`entryUUID` 조회) **사이**에 선택된 엔트리를 (a) 삭제, (b) 이름 변경(DN 변경), (c) 정렬 키 속성 수정, (d) 키 외 속성만 수정, (e) ACL로 숨김, (f) 모든 선택 엔트리를 삭제
- When 페이지를 조립
- Then (a)(b)(c)(e)는 이번 페이지에서 제외(변경 후 새 튜플이 현재 커서 뒤라면 이후 페이지에서 정확히 1회 나타남), (d)는 새 속성으로 방출, 방출된 튜플은 모두 직전 커서보다 크고 서로 엄격 증가, (f)는 빈 `items`이지만 `hasMore=true`면 `nextCursor`가 phase 1 선택의 마지막 튜플로 **전진**한다.

## Architecture and decisions

- Relevant ADR/design links: [api-integration PLAN P1](../api-integration/PLAN.md), [groups-pagination](../groups-pagination/CHANGE.md), [api-error-envelope](../api-error-envelope/CHANGE.md), 선례 `audit/actions`(`audit_actions_handlers.go:15-37`, `ldapclient/audit_client.go:17-92`).
- ADR threshold result: `not required` — 신규 의존성·자격 증명 경계·스키마 변경 없음. 이미지 opt-in 설정은 `image/README.md`가 정본. 커서 형식(D215-1)과 순회 의미(D215-5)는 `docs/api.md`가 정본.

### 대안 평가

| | A. 키셋(정렬 키 기준 "이후 N건") | B. RFC 2696 쿠키를 서명 커서로 포장 | C. VLV/서버 정렬(`sssvlv`) |
|---|---|---|---|
| 서버 상태 | 없음 | 연결·slapd 상태(그 연결에서만 유효) | 요청당 서버 정렬 집합(`olcSssVlvMax` 기본 10 동시) |
| 요청 간 생존 | 무관 | 세션 연결 점유, 만료·재시작·replica 이동 시 소멸 | 무관 |
| 동시 추가/삭제 | 정의된 보장(D215-5) | slapd 내부 순서 의존, 보장 불명 | 오프셋 기반이라 이동·중복 |
| 비용/페이지 | 전체 스캔 O(N), 메모리 O(limit) | O(limit) | 서버 정렬 O(N log N) |
| 요구 | 없음 | 없음 | 메인 DB `sssvlv`(**기본 꺼짐**: `image/README.md:121`, `values.yaml:183-185`; accesslog DB에만 상시: `entrypoint.sh:932-937`) |

서버측 키 범위 필터 `(uid>last)`는 사용할 수 없다: `uid`·`cn`은 RFC 4519 정의상 ORDERING 규칙이 없고(검증 필요, T-002), 인덱스도 `uid eq`, `cn pres,eq,sub`뿐이다(`01-cn-config.ldif:79-80`). audit도 같은 이유로 커서 행을 클라이언트에서 거른다(`ldapclient/audit.go:403-416`).
**추천: A (키셋 + 백엔드 경계 선택).** 서버 상태·연결 점유가 없고 동시 변경 의미를 증명할 수 있다. 비용은 페이지당 O(N) 스캔(D215-9).

### 결정 기록

- `D215-1` 커서 형식(개정: 세션 결속). `v1.<b64url(payload)>.<b64url(mac)>`, payload = `{v:1, r:"users"|"groups", k:<키>, d:<DN>, q:<정규화 q>, s:<세션 결속값>}`. `mac = HMAC-SHA256(K, "v1."+b64url(payload))`, `K = HMAC-SHA256(SessionSecret, "ldapium/list-cursor/v1")`(쿠키 서명과 키 용도 분리, `session/cookie.go:24-31`), 상수시간 비교. **`s = b64url(HMAC-SHA256(K, "sid:"+Session.ID))[:16바이트]`** — 세션 ID 원문이 커서(로그·URL에 남을 수 있음)에 들어가지 않는다. 같은 DN의 **새 로그인은 새 `Session.ID`**이므로 이전 커서는 무효(재로그인 시 순회를 처음부터 다시 시작; 테스트 AC-004). 이전 안(세션 DN 결속)은 기각: 재로그인·다른 탭 세션 간 재사용이 가능했다.
  - 이유: 커서에는 비밀이 없다(응답으로 받은 키·DN). HMAC은 기밀이 아니라 **무결성·결속**: 변조가 조용히 위치를 건너뛰지 않고 400이 되며, 세션·리소스·필터에 묶여 ACL 범위가 다른 호출자에게 재사용되지 않는다. 암호화는 하지 않는다.
  - 비용: `SESSION_SECRET` 교체·세션 만료·백엔드 재시작 시 커서 무효(세션도 무효라 이미 동일). 세션이 프로세스 메모리이므로 replica 친화도는 기존과 같다.
  - **#214 연계**: 머신 요청이 요청별 임시 `Session`을 쓰면(machine-principal-auth T-013) `Session.ID`가 요청마다 달라 커서가 이어지지 않는다. 그 패키지 구현 시 `s`를 **안정적 주체 키**(머신은 client id)로 대체해야 한다 — 결속값 도출을 순수 함수 한 곳(`cursorBinding(sess)`)에 두고 T-003에서 확인한다.
  - 탈출구: 버전 `v` 증가, 결속값 함수 교체.
- `D215-2` 요청 파라미터. `limit`(1–200, 커서 모드 기본 50; 상한은 audit와 동일 `audit_actions_handlers.go:19`), `cursor`, `q`(≤64자, UTF-8, 제어문자 불가), `sort`(생략 또는 기본 키와 같은 값만). 커서 모드 트리거 = `limit`·`cursor`·`q`·`sort` 중 하나라도 존재. 알 수 없는 `sort`가 조용히 무시되면 호출자가 다른 정렬을 가정하므로 명시 거부. 200은 phase 2 응답 크기(그룹 `member`가 큼)와 크기 제한 여유용. 탈출구: 상수 한 곳.
- `D215-3` 응답(가산적, camelCase). 커서 모드: `{users|groups:[…], truncated:false, hasMore:bool, nextCursor?:string}`. `truncated`는 스키마 required이므로 유지하되 커서 모드에서는 항상 `false`; 이어짐은 `hasMore`. `nextCursor`는 `hasMore=true`일 때만. 이름은 audit의 `nextBefore`/`hasMore`(`dto.go:22-26`) 관례, 파라미터가 `before`가 아닌 이유는 audit의 `before`가 평문 `reqStart:세션` 마커(`audit.go:299-307`)이기 때문. **무파라미터 호출자는 현재와 동일한 `{users|groups, truncated}`, 같은 순서·상한**(REQ-001). 이유: 5000 상한을 정렬 순서로 바꾸면 모든 호출이 O(N)+정렬이 되고 기존 소비자의 순서 가정이 깨진다.
- `D215-4` 전순서 키. users = `(lower(min(uid 값들)), lower(DN))`, groups = `(lower(min(cn 값들)), lower(DN))`. UTF-8 바이트 사전식(로케일 콜레이션 아님). `uid` 없는 사용자의 키는 `""`(맨 앞), 동률은 DN. DN은 엔트리당 유일 → 전순서. `uid`는 MAY·다중 값 가능·유일 보장이 `unique` 오버레이에 의존하므로 DN 타이브레이크 필수. 탈출구: 키 함수 교체 시 커서 버전 증가.
- `D215-5` 동시 변경 의미(증명, 개정).
  - 불변식: 각 페이지는 직전 커서 `(k₀,d₀)`보다 **엄격히 큰** 튜플 중 최소 `limit`개 후보이고, 다음 커서는 phase 1에서 **선택된** 마지막 튜플이다. 페이지가 덮는 구간 `(k₀,d₀]~(k₁,d₁]`은 서로 겹치지 않는다.
  - 보장 1(무손실·무중복): 순회 내내 존재하고 `(키, DN)`이 불변인 엔트리는 정확히 1회 반환된다(중복은 서로 다른 두 튜플에서만 가능하고, 한 엔트리가 두 구간에 들려면 튜플이 변해야 함; 누락은 해당 구간 스캔이 못 봐야 생기나 순회 내내 존재하면 모든 스캔에서 보임 — paged 스캔 중 미변경 엔트리 누락 없음은 검증 필요, T-002).
  - 보장 2: 현재 커서 **뒤**에 추가된 엔트리는 반환될 수 있고, 커서 **앞**(키 ≤ 커서)에 추가된 엔트리는 이번 순회에서 반환되지 않는다.
  - 보장 3: 삭제는 자기 구간 스캔 전이면 미반환, 이미 반환된 뒤면 한 번 반환된 상태로 남는다.
  - 비보장: 키·DN 변경은 0회 또는 2회를 일으킬 수 있다(앞→뒤 2회, 뒤→앞 0회). 스냅샷 일관성은 제공하지 않는다(탈출구 D215-9 세션 스냅샷).
  - 페이지가 `limit`보다 짧아도 `hasMore=true`일 수 있다(두 단계 사이 변경, D215-6). 호출자는 길이가 아니라 `hasMore`/`nextCursor`로만 계속 여부를 판단한다.
- `D215-6` 조회 방식과 두 단계 일관성 규칙(개정).
  - phase 1: 세션 연결로 RFC 2696 paged search를 **청크 단위**로(D215-13) 수행. 요청 속성은 키 속성(users `uid`, groups `cn`)과 `entryUUID`뿐. 커서보다 큰 튜플 중 최소 `limit+1`개를 힙으로 유지(메모리 O(limit)). `limit+1`번째는 `hasMore` 판정용(audit 선례 `audit.go:403-416`). 선택 결과 = phase 1 튜플 `t1(i)=(k1,d1)`과 `entryUUID`의 목록 `S`.
  - phase 2: `S`를 `(|(entryUUID=…)…)` 청크(≤100, `entryUUID eq` 인덱스 `01-cn-config.ldif:77`)로 전체 속성(`userAttrs`/`groupAttrs`, `users.go:17-20`, `groups.go:13`) 조회. 결과마다 키·DN으로 `t2`를 **다시 계산**한다.
  - **정렬과 커서는 오직 phase 1 튜플 기준**이다. 규칙(`assemblePage(S, fetched)` 순수 함수):
    1. `t2 == t1`(DN과 키 모두 동일): 방출. 비키 속성이 바뀌었으면 phase 2의 **최신 값**으로 방출(키·위치는 phase 1).
    2. phase 2에 없음(삭제 또는 ACL로 숨김): 제외.
    3. `t2 != t1`(이름 변경·키 변경): **이번 페이지에서 제외**(삭제처럼 취급). 새 튜플이 현재 커서 뒤면 이후 페이지의 스캔에서 정확히 1회 나타나고, 앞이면 이번 순회에서 나타나지 않는다. 따라서 방출된 모든 튜플은 `(k₀,d₀]` 이후·페이지 구간 안이며 엄격 증가한다(`REQ-015`).
    4. 방출 순서는 항상 phase 1 순서.
    5. `nextCursor` = **선택된 마지막 phase 1 튜플**(방출 여부와 무관). 선택된 전부가 제외돼 `items`가 비어도 `hasMore=true`이면 커서가 전진하므로 호출자는 반드시 진행한다. phase 1이 0건이면 `hasMore=false`, `nextCursor` 없음.
  - 이유: `member`·`memberOf`가 큰 엔트리를 전량 스캔하지 않기 위해. 비용: 요청당 LDAP 호출 ≈ ⌈N/500⌉ + ⌈limit/100⌉. 탈출구: 작은 디렉터리용 단일 단계는 후속.
- `D215-7` 필터 범위·주입 방어. 필터는 `q` 하나: users = `(&(objectClass=inetOrgPerson)(|(uid=*Q*)(cn=*Q*)(mail=*Q*)(displayName=*Q*)))`, groups = `(&(objectClass=groupOfNames)(|(cn=*Q*)(description=*Q*)))`. `Q = ldap.EscapeFilter(q)`(선례 `audit_client.go:36`), 속성 목록은 코드 상수, 속성 지정 파라미터 없음. 정규화된 `q`가 커서에 들어가 호출 간 변경을 막는다. 서버 크기 제한은 서버가 **반환하는** 엔트리 수를 세므로 `q`로 후보를 좁히면 제한 아래로 들어올 수 있다(D215-14의 해결책 중 하나). UI의 7개 필드 클라이언트 검색(`UsersPage.tsx:57-63`)과 같지 않다.
- `D215-8` 상한과 5000 상한의 관계. 커서 모드는 `maxListResults`(5000, `search.go:19`)를 적용하지 않는다(레거시 전용). 요청당 스캔 상한 `maxScanEntries`=100000(상수): 초과 시 422 `scan_limit_exceeded`(`q` 사용 안내). 서버 크기 제한은 D215-14, 지연은 D215-13. (개정: 이전의 "스캔 상한이 크기 제한 문제를 해결"한다는 서술을 삭제 — 상한은 메모리·지연 방지용이고 서버 제한과 무관하다.)
- `D215-9` 비용·탈출구. 제안 예산(미측정, AC-009): `limit=50`에서 페이지 p95 ≤ 1 s @10k, ≤ 3 s @50k(로컬 단일 노드); 10k 전체 순회(`limit=200`, 50페이지) ≤ 60 s. 전체 순회 총비용 O(N²/limit)를 문서에 명시. 미달 시 탈출구: (a) 세션별 키 스냅샷 캐시(키+UUID만, TTL·상한 포함, O(1) 페이지·진짜 스냅샷 의미; 서버 상태·메모리 DoS 관리 필요) — 별도 결정으로 승격; (b) `sssvlv` 메인 DB(opt-in, 비추천). **Q1 결정(유지보수자): 페이지당 O(N)을 문서화된 한계로 수용하되, (a)는 D215-13 청크 설계 이후에만 기록된 탈출구로 둔다.**
- `D215-10` 오류와 #218 봉투. 모든 오류는 #218 봉투 `{error, message, code, requestId, retryable}`(`error`와 `message`는 동일 문구). 코드는 아래 "Error codes introduced". #218이 먼저 병합되지 않았으면 현행 `{error}`로 출고하고 코드 값은 봉투 PR이 채운다. 커서 만료 개념은 없다(stateless) — 세션 만료는 기존 401 `session_expired`, 재로그인·변조는 `cursor_invalid`.
- `D215-11` 프런트엔드. **Q2 결정: UI는 클라이언트측 페이징을 유지하고 서버 커서는 API 소비자용**이다. UsersPage는 총건수·마지막 페이지·7필드 검색에 의존(`UsersPage.tsx:57-67`), `GroupPagination.tsx:5-12`는 `total`로 페이지 수 계산, `MembersDialog.tsx:95`는 후보 전체가 필요. UI 전환은 별도 후속 이슈(AC-010). 사용되지 않는 클라이언트 함수도 추가하지 않는다.
- `D215-12` `userPassword`. 요청 속성은 고정 목록이며 `userPassword`가 없고 매핑도 읽지 않는다(`users.go:54-80`; DIT 브라우저 denylist `tree.go:88-104`는 별개). 커서 모드가 새 속성을 요청하지 않는다. AC-006.
- `D215-13` 청크 스캔·취소·뮤텍스(신규; 지연/점유 한정).
  - 문제: `search.go:43`은 `c.conn.Search`(go-ldap v3.4.14 `search.go:567`, 컨텍스트 없음, 응답 대기 블로킹)이고 연결에 요청 타임아웃이 없다(`dial.go:124-157`). 현재 `ListUsers`는 스캔 내내 뮤텍스를 쥐므로(`users.go:39-40`) 느린 LDAP이 같은 세션의 모든 요청(UI는 병렬 호출)을 굶긴다. 같은 구조를 커서 모드에 쓰면 AC-007이 불가능하다.
  - 설계: (1) `ldapclient`에 컨텍스트 인지 `searchChunk(ctx, req)` — `conn.SearchAsync(chunkCtx, req, buf)`(go-ldap `search.go:631`, 컨텍스트 취소 시 수신 중단·`Err()`는 nil)로 한 번의 paged 요청(≤`searchPageSize`=500, `search.go:10`)을 읽고, `chunkCtx = WithTimeout(ctx, chunkTimeout=5s)`; 종료 후 **`ctx.Err()`를 반드시 확인**한다(취소가 오류로 보고되지 않으므로). `req.TimeLimit`=`ceil(chunkTimeout)`을 함께 보내 서버도 스스로 멈춘다. (2) 뮤텍스(`c.mu`)는 **청크마다** 잡고 풀어, 같은 세션의 다른 요청은 최대 청크 하나를 기다린다. (3) 세션당 동시 스캔 1개를 위한 `scanMu`(클라이언트 필드): 두 번째 커서 요청은 자기 컨텍스트까지 대기하고 초과 시 503 `unavailable`+`Retry-After` — 한 연결에서 paged search 두 개의 동시 진행이 안전한지 불명(검증 필요, T-002). (4) 핸들러가 `context.WithTimeout(r.Context(), listRequestTimeout=30s)`를 만들어 `ldapclient`까지 전달; 청크 사이에 deadline·취소를 확인; 초과 시 503 `scan_timeout`(retryable=false, 메시지에 `q`·재시도 안내).
  - 블로킹 읽기와 `SetTimeout`: `Conn.SetTimeout`(`conn.go:356`)은 요청별 타이머로 해당 메시지 채널만 닫고 연결은 유지하지만(`conn.go:582-618`) **연결 전역 설정**이라 같은 세션의 모든 오퍼레이션에 영향을 주므로 주 수단으로 쓰지 않는다. 별도 단기 연결은 자격 증명이 없어 불가(위 제약 1). 소켓 `SetDeadline`은 go-ldap이 연결을 공유 멀티플렉싱하므로 다른 요청까지 끊어 쓰지 않는다.
  - 취소의 실제 효과: v3.4.14에는 Abandon API가 없다(go-ldap `ldap.go:31`의 상수만 존재). 취소된 청크는 서버가 `TimeLimit`이나 완료까지 계속 보낼 수 있고, 이미 종료된 메시지 ID의 늦은 패킷은 `conn.go:610`에서 `setError`만 기록한다. 이것이 공유 연결을 오염시키는지는 **검증 필요(T-002)**; 오염되면 폴백은 타임아웃 시 세션 연결을 닫고 재로그인(401)시키는 것이다.
  - **AC-007이 현실적으로 보장하는 것(즉시 중단이 아님)**: 요청 총 시간 ≤ `listRequestTimeout` + 진행 중 청크 잔여(≤5 s 상한), 다른 요청의 대기 ≤ 청크 1개, 스캔 상한·취소 시 새 청크를 시작하지 않음. 이미 서버로 나간 청크의 서버측 즉시 중단은 보장하지 않는다.
  - 비용: 청크 사이 뮤텍스 재획득 오버헤드, 구현 복잡도. 탈출구: 청크 크기·타임아웃은 상수, 문제 시 D215-9(a).
- `D215-14` 서버 크기 제한과 opt-in 설정(신규; 이전 `D215-8` 제한 서술을 대체).
  - 사실(`entrypoint.sh:157-173`, `01-cn-config.ldif:74`): 비관리자 `olcSizeLimit`=10000, `olcLimits` 없음, rootDN 면제. paged search의 hard limit은 **총합**에 적용된다(`size.prtotal` 완화 전까지; T-002가 실제 이미지에서 확인).
  - (a) rootDN(관리자 로그인) 또는 제한이 완화된 신원은 설계대로 순회한다. SSO 모드의 서비스 계정이 rootDN인지는 배포별(검증 필요).
  - (b) opt-in 설정 추가(**Class C, 별도 커밋**): 이미지 env `LDAP_PAGED_TOTAL_LIMIT`(숫자 또는 `unlimited`, 미설정=현재 동작) → `LDAP_SIZE_LIMIT`와 같은 검증(`entrypoint.sh:169-173`) 후 `01-cn-config.ldif`의 `olcSizeLimit` 다음(74행)에 `olcLimits: {0}users size.prtotal=<값>`(인증된 모든 DN; anonymous 제외) 렌더(미설정이면 줄 자체 없음, 렌더 위치는 `__LDAP_SIZE_LIMIT__` 치환 `entrypoint.sh:1005` 인근의 placeholder 방식). 차트 `ldap.limits.pagedTotal`(기본 비움) → `statefulset.yaml`의 env 목록(`LDAP_SSSVLV_MAIN_ENABLED` 항목 `:135-136` 선례)에서 값이 있을 때만 렌더. 현재 차트는 `LDAP_SIZE_LIMIT`도 배선하지 않으므로(차트 grep 결과 없음) 새 값만 추가한다. bootstrap-only(`image/README.md:89,234-243`): 기존 볼륨은 `ldapmodify`로 `olcDatabase={1}mdb,cn=config`에 `olcLimits`를 추가하는 절차를 README에 문서화(검증 필요: soft/hard가 `olcSizeLimit` 기본을 유지하는지 — T-002). 변경 파일: `image/entrypoint.sh`, `image/ldifs/01-cn-config.ldif`, `image/README.md`, `charts/ldapium/{values.yaml,templates/statefulset.yaml,README.md,README-ko.md}`. 테스트: 엔트리포인트 렌더(미설정/값/`unlimited`/잘못된 값; `scripts/test/test-bootstrap-seed.sh` 선례), `helm template`·`scripts/verify-chart-schema.sh`, 라이브 `ldapsearch -E pr=500/noprompt`, `ldapium:e2e` 재빌드(AGENTS.md).
  - 위험·비용: 값을 올리면 인증된 모든 사용자가 paged 검색으로 디렉터리 전체를 열거할 수 있다(비 paged 단일 질의의 `olcSizeLimit`는 그대로, ACL은 계속 적용, `entrypoint.sh:161-163`의 "마지막 방어선" 논리 약화). 그래서 기본값은 불변이고 운영자가 명시적으로 켠다.
  - (c) 기본 설정에서 제한에 걸리면 **절대 조용히 자르지 않는다**: `sizeLimitExceeded`(`ldap.LDAPResultSizeLimitExceeded`, 선례 `audit_client.go:61`, `tree.go:83`)를 새 도메인 오류 `domain.ErrSizeLimitExceeded`로 매핑(`errors.go:15-55`에 case 추가; 현재는 500으로 떨어짐)하고 핸들러가 422 `size_limit_exceeded`(retryable=false)로 응답. 메시지는 해결책을 명시한다: "directory size limit reached; narrow with `q`, use an identity exempt from the limit, or ask the operator to set LDAP_PAGED_TOTAL_LIMIT (ldap.limits.pagedTotal)". 부분 페이지는 반환하지 않는다.
  - (d) AC-002(허용되는 신원)와 AC-011(기본 일반 사용자: 명시적 오류)로 분리. 키셋 스캔은 매 페이지 전체 후보를 읽으므로 기본 설정에서 후보 >10000이면 **첫 페이지부터** 오류다(`q`로 좁히면 성공).
  - T-002는 이제 설계를 막는 게이트가 아니라 위 `size.prtotal` 의미를 실제 이미지에서 **확인**하는 작업이다.

### Error codes introduced

#218 코드 표(`docs/changes/api-error-envelope/CHANGE.md`, 닫힌 집합)와 **같은 이름**을 쓴다: `cursor_invalid`, `size_limit_exceeded`, 그리고 기존 `validation_failed`. 새 코드를 만들지 않는다. 봉투 예시:

```json
{
  "error": "invalid cursor",
  "message": "invalid cursor",
  "code": "cursor_invalid",
  "requestId": "5nQe3kXyZpLwTqA0vB9cJmRdUsHf2GoE",
  "retryable": false
}
```

```json
{
  "error": "directory size limit reached; narrow with q, use an identity exempt from the limit, or ask the operator to set LDAP_PAGED_TOTAL_LIMIT",
  "message": "directory size limit reached; narrow with q, use an identity exempt from the limit, or ask the operator to set LDAP_PAGED_TOTAL_LIMIT",
  "code": "size_limit_exceeded",
  "requestId": "Hj2kL9mNpQrStUvWxYz0AbCdEfGh1iJk",
  "retryable": false
}
```

| code | 상태 | retryable | 생산자 |
|---|---|---|---|
| `cursor_invalid` | 400 | false | 변조·잘림·버전·리소스/`q`/세션 불일치·재로그인·`SESSION_SECRET` 교체·길이 초과 (원인 구분 없음. stateless라 만료 개념이 없어 `cursor_expired`는 쓰지 않는다) |
| `validation_failed` | 422 | false | `limit` 범위·형식, `q` 길이·인코딩·제어문자, 기본 키 외 `sort` (필드명만 메시지에, 값은 되풀이하지 않음; #218 기존 코드) |
| `size_limit_exceeded` | 422 | false | 서버 크기 제한(D215-14) |
| `scan_limit_exceeded` | 422 | false | `maxScanEntries` 초과(D215-8) |
| `scan_timeout` | 503 | false | `listRequestTimeout` 초과(D215-13) |
| `unavailable` (#218 예약 코드 사용) | 503 | true | 세션당 동시 스캔 대기 초과, `Retry-After` |

### 연계

- #218: 위 목록을 코드 표에 추가하는 한 줄 PR 요건(D218-14 방식). 봉투가 먼저 병합되면 본 패키지는 `apiErr(status, code, msg)`를 사용, 아니면 후속에서 채움.
- #214: 머신 principal은 `directory.users.read`/`groups.read`로 이 엔드포인트를 쓴다. 커서 결속값(D215-1) 재확인 필요. rate limit은 #214 REQ-010 담당.

## Change impact

| Area | Impact / evidence needed |
|---|---|
| Source / API / command | `GET /api/users`·`/api/groups`에 선택 파라미터·응답 필드. `domain.ErrSizeLimitExceeded` 추가. 신규 엔드포인트 없음. 무파라미터 불변(AC-001) |
| Dependencies / lockfiles | N/A — 표준 라이브러리와 기존 `go-ldap`(`SearchAsync`는 현재 버전 v3.4.14에 존재, `ui/backend/go.mod:7`) |
| Runtime / toolchain | **이미지**: `LDAP_PAGED_TOTAL_LIMIT`(opt-in, 기본 불변, bootstrap-only), **차트**: `ldap.limits.pagedTotal`. 요청당 LDAP 호출·청크 증가는 AC-009로 측정 |
| CI / CD | 라이브 순회·크기 제한 스크립트를 워크플로에 연결(대규모 적재가 길면 `workflow_dispatch`/야간 분리 — T-023) |
| Release / packaging | 이미지 태그 변경이 필요한 opt-in 설정이므로 릴리스 노트에 이미지·차트·API 각 1줄. 별도 커밋 |
| Generated output | `openapi.json`·`llms.txt` 갱신, 차트 README EN/KO |
| Security / supply chain | 커서 HMAC·세션 결속, `q` 이스케이프, 스캔·`limit`·deadline 상한, `userPassword` 비노출, paged total 완화의 열거 위험(D215-14 위험) |
| Offline / air-gap | N/A — 외부 의존 없음 |
| Documentation / operations | `docs/api.md:95-96`, `llms.txt:36-37,45`, `openapi.json` 설명·`x-ai-hints`(`openapi.json:5884-5893`), `image/README.md`(env 표·bootstrap-only 절), 차트 README, 운영자용 기존 볼륨 절차 |
| Portfolio / downstream repositories | #214(결속값)·#218(코드 표) 연계. 다운스트림 SDK 없음(T-003 확인) |

## Verification plan

| Acceptance ID | Verification method | Environment | Expected evidence |
|---|---|---|---|
| `AC-001` | 변경 전 응답 기록 대비 고정 비교 + 기존 테스트 무수정 통과 | 유닛(핸들러 fake) + 라이브 5001+ | 키 집합·길이·순서 일치 |
| `AC-002` | `scripts/test/test-api-cursor-pagination-local.py`(신규, `test-api-edge-codes-local.py` 선례): `scripts/bench-load.sh --count 12000`(`bench-generate-ldif.py`는 `ou=people` 사용자만 생성 — 그룹·엣지 생성기는 T-014); (i) 관리자 로그인, (ii) `LDAP_PAGED_TOTAL_LIMIT=unlimited` 이미지 + 일반 사용자 | 라이브: slapd+UI 컨테이너(`ldapium:e2e` 재빌드) | 집합 동등·중복 0·엄격 증가 |
| `AC-003` | 같은 스크립트의 **페이지 사이** 결정적 변경 (a)–(f) 기대표 단언 | 라이브 | 기대표 대비 실측 |
| `AC-004` | 순수 단위: 왕복·1바이트 변조·잘림·버전·리소스·`q`·세션 결속(**재로그인 = 새 `Session.ID`**)·비밀 교체·길이 + 핸들러 400. 라이브: 같은 사용자 재로그인 후 이전 커서 거부 | 유닛 + 라이브 | `go test`, 라이브 로그 |
| `AC-005` | 단위: 검증 표, 필터 문자열 고정 비교, `EscapeFilter` 퍼즈(`escaping_fuzz_test.go` 패턴) | 유닛 | `go test` + 시드 |
| `AC-006` | 단위: `userPassword` 픽스처 매핑 + 라이브 과권한 bind 응답 grep | 유닛 + 라이브 | 본문에 없음 |
| `AC-007` | 단위: 주입 가능한 검색 함수로 `chunkTimeout`·`listRequestTimeout`·취소·스캔 상한·`scanMu` 대기를 시계 주입으로 검증(LDAP 배선 자체는 AGENTS.md 관례상 단위 테스트 없음). 라이브: LDAP 앞에 지연 주입(예: `tc`/프록시 또는 큰 스캔)해 같은 세션 병렬 요청의 대기 시간을 측정하고 **즉시 중단이 아닌** 위 보장만 단언; 취소된 청크 뒤 같은 연결이 정상인지 확인 | 유닛 + 라이브 | 시간 측정 표 |
| `AC-008` | 기존 드리프트·계약 테스트(`api_contract_test.go:39,84`) 확장 + `llms.txt` 서빙 테스트(`api_docs_test.go:102`) + 오류 코드 목록 골든 | 유닛 | `go test`, "no cursor" grep 0건 |
| `AC-009` | 라이브 스크립트 페이지별 p50/p95/p99·전체 순회 시간, 10k·50k(`bench-load.sh`), 레거시 목록 지연 비교 | 라이브(로컬 단일 노드, 환경 기록) | 측정 표(`research/` 관례) |
| `AC-010` | (후속) Playwright 모킹 e2e(`e2e/groups-pagination.spec.ts` 선례) | 브라우저 | 후속 이슈 증거 |
| `AC-011` | 라이브: 기본 설정 이미지 + 12000건 + 일반 사용자: 레거시 5000/`truncated`, 커서 모드 422 `size_limit_exceeded`, `q`로 좁힌 요청 성공, 부분 결과 없음. 단위: `sizeLimitExceeded`→도메인 오류→422 매핑 | 유닛 + 라이브 | 응답 본문·상태 |
| `AC-012` | 엔트리포인트 렌더 테스트(미설정/값/`unlimited`/`abc`), `helm template` 기본·설정 렌더, `scripts/verify-chart-schema.sh` 프로필 추가, 라이브 `slapcat`/`ldapsearch`로 `olcLimits` 확인, 기존 볼륨 `ldapmodify` 절차 1회 시연 | 이미지 빌드 + Helm | 렌더 출력, `cn=config` 덤프 |
| `AC-013` | 단위: `assemblePage` 표 테스트((a)–(f), 순서·엄격 증가·커서 전진·빈 페이지). 라이브: `ldapclient` 테스트 이음새(비프로덕션 훅 `betweenPhases func()`, 기본 nil)로 phase 1과 2 사이에 실제 삭제·modrdn·속성 수정·ACL 변경을 가해 같은 단언 | 유닛 + 라이브 | `go test`(라이브 태그), 실측 표 |

순수 단위(AC-004·005·013 표, 키 비교, 힙)와 라이브/런타임 증거(AC-002·003·007·009·011·012·013 라이브)를 구분한다. LDAP 배선은 AGENTS.md "Testing philosophy"에 따라 모킹 프레임워크 없이 순수 헬퍼 + 라이브로 검증한다.

### Traceability matrix

| Requirement | Acceptance | Decision | Tasks | Evidence |
|---|---|---|---|---|
| `REQ-001` | `AC-001` | D215-3 | T-004, T-012, T-020, T-021 | 호환 비교 로그 |
| `REQ-002` | `AC-002` | D215-2, D215-4, D215-6 | T-010, T-011, T-012, T-014, T-020, T-021 | 순회 집합 동등 |
| `REQ-003` | `AC-004` | D215-1 | T-010, T-020, T-021 | 커서·재로그인 테스트 |
| `REQ-004` | `AC-002` | D215-6, D215-14 | T-002, T-011, T-014, T-015, T-021 | 12000건 순회(관리자·완화 신원) |
| `REQ-005` | `AC-003`, `AC-013` | D215-5, D215-6 | T-010, T-011, T-014, T-020, T-021 | 기대표, 두 단계 사이 변경 |
| `REQ-006` | `AC-005` | D215-2, D215-7 | T-010, T-020 | 검증 표·퍼즈 |
| `REQ-007` | `AC-006` | D215-12 | T-010, T-020, T-021 | 응답 grep |
| `REQ-008` | `AC-007` | D215-8, D215-13 | T-016, T-011, T-012, T-020, T-021 | 시간 측정, 취소 테스트 |
| `REQ-009` | `AC-004`, `AC-005` | D215-10 | T-010, T-012, T-020 | 400 응답 |
| `REQ-010` | `AC-008` | D215-3, D215-10 | T-013, T-030 | 계약 테스트·문서 diff |
| `REQ-011` | `AC-002`, `AC-004` | D215-1 | T-010, T-021 | 재로그인 거부, ACL 부분집합 |
| `REQ-012` | `AC-009` | D215-9 | T-014, T-022 | 측정 표 |
| `REQ-013` | `AC-011` | D215-14 | T-016, T-011, T-012, T-020, T-021 | 422 응답, 부분 결과 없음 |
| `REQ-014` | `AC-012` | D215-14 | T-015, T-020 | 렌더·`cn=config` 증거 |
| `REQ-015` | `AC-013` | D215-6 | T-010, T-011, T-020, T-021 | `assemblePage` 표·라이브 |

## Rollout, rollback and recovery

- Rollout sequence: T-001 확인 → T-002 스파이크로 `size.prtotal`·취소·인터리브 사실 확인 → **이미지·차트 opt-in 설정(T-015)을 자체 커밋으로 먼저** → 순수 헬퍼 → 청크 검색 래퍼 → 페이지 조회·조립 → 핸들러 → OpenAPI·문서 → 라이브 검증. 무파라미터 경로가 불변이므로 중간 상태도 안전하다.
- Rollback trigger and procedure: 무파라미터 호환 깨짐, 성능 예산 미달로 운영 영향, 뮤텍스 점유·공유 연결 오염 관측. 절차: PR 되돌리기. 이미지 설정은 미설정 시 기존과 동일하므로 되돌려도 기본 배포는 영향 없다. 운영자가 설정을 켠 경우 값을 비우고 볼륨에서 `olcLimits`를 `ldapmodify`로 삭제(문서화).
- Data/configuration recovery: 백엔드 변경은 읽기 전용이라 N/A. 이미지 설정은 `cn=config`의 `olcLimits` 한 항목이며 삭제 절차를 문서화.
- Compatibility or migration obligations: 기존 클라이언트·UI 무변경. 새 필드는 선택(`truncated` required 유지). 커서 형식 `v1` 고정. 새 이미지 env는 선택·기본 불변.

## Evidence and durable synchronization

- Evidence location/format: 라이브 스크립트 출력·측정 표를 PR 본문 + `research/` 관례로 보존, 실패·기각 시도 포함(AGENTS.md "Research evidence").
- Tests or checks that become durable regression controls: `cursor_test.go`, `assemblePage` 표 테스트, 청크 래퍼 시간 주입 테스트, 핸들러 검증 표, OpenAPI 스키마·오류 코드 골든, `test-api-cursor-pagination-local.py`, 엔트리포인트 렌더 테스트, 차트 렌더 프로필.
- Documentation to update: `docs/api.md`, `openapi.json`, `llms.txt`, `image/README.md`, 차트 README(EN/KO), 이 패키지 상태.
- ADR/evidence/portfolio records to update: ADR 불필요(위). `api-integration/PLAN.md`는 읽기 전용 — 수정하지 않고 #215에 완료 범위를 코멘트. UI 커서 모드가 남으므로 "Related to #215 (not closing yet)" + 후속 이슈 분리.

## Review record

- Accepted scope/requirements: 2026-10-06 유지보수자 지시로 수용(위 Status).
- Material changes after acceptance and re-review: 1차 독립 검토 반영 개정 — (1) 서버 크기 제한을 결정 가능한 사실로 처리하고 opt-in 이미지 설정·명시 오류·AC 분리(D215-14, REQ-013/014, AC-011/012); (2) 청크 스캔·컨텍스트 인지 검색·뮤텍스 해제·유한 지연(D215-13, REQ-008, AC-007); (3) 두 단계 일관성 규칙(D215-6, REQ-015, AC-013); (4) 커서를 `Session.ID`에 결속(D215-1, REQ-011, AC-004). 오류 코드 표 추가.
- Resolved questions:
  - Q1(페이지당 O(N)): 문서화된 한계로 수용. 세션 스냅샷 캐시(D215-9a)는 D215-13 청크 설계 이후에만 쓰는 기록된 탈출구.
  - Q2(UI): 클라이언트측 페이징 유지, 서버 커서는 API 소비자용, UI 전환은 별도 후속 이슈(D215-11, AC-010).
- Open questions or blockers: 없음(결정 대기 항목 없음). 구현 착수 조건: T-001과 T-015(이미지 변경, 별도 커밋).
- 검증하지 못한 사실(T-002 또는 AC에서 확인): `size.prtotal`의 총합 의미와 `olcLimits: users size.prtotal=` 구문·soft/hard 유지; `uid`/`cn` ORDERING 규칙 부재; 한 연결에서 paged search 도중 다른 오퍼레이션·두 번째 paged search 허용 여부; 취소된 `SearchAsync` 청크 뒤 공유 연결 상태(`conn.go:610`); paged 스캔 중 미변경 엔트리 누락 없음; `entryUUID` OR 필터 성능; SSO 서비스 계정의 rootDN 여부; 성능 예산 수치(제안값).
