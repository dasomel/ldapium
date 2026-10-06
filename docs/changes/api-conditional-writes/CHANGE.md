# Change: 코어 사용자·그룹 쓰기의 조건부 쓰기(ETag/If-Match)와 멱등성(Idempotency-Key) 규약

- Change class: `B` — 외부 API 계약에 가산적 변경(헤더·필드·`PATCH`), 디렉터리 쓰기 의미(보상 삭제, assertion control) 추가. 인증·인가 경계는 바뀌지 않는다. 승격 조건(`D`): 멱등 기록을 PVC에 영속화하거나, `If-Match`를 기본 필수로 바꾸는 `UI_REQUIRE_IF_MATCH`(D216-3의 이연 항목)를 도입하는 변경.
- Owner: 미지정 — 구현 착수 전 지정
- Related issue: [#216](https://github.com/dasomel/ldapium/issues/216) — 출처 [api-integration PLAN P1](../api-integration/PLAN.md). 이 패키지가 #216의 세 수용 기준을 모두 닫는다(umbrella 아님). 후속 참조: #217(백업 job, D217-9가 이 규약을 요구), #218(오류 봉투), #215(목록).
- Status: `Accepted 2026-10-06 — maintainer instruction to process #216 (open questions resolved as recorded below)`
- Accepted by / date: 유지보수자 지시(#216 처리) / 2026-10-06 — 열린 질문은 Review record에 해소 결정으로 기록(유지보수자 결정 사항 없음)
- 작성일: 2026-10-06

> 설계 문서다. 코드·OpenAPI·차트·UI는 변경하지 않았고 아래 동작은 구현·런타임 검증되지 않았다.
> 현황 서술은 2026-10-06 `main`(60dae0d, #230 병합 포함) 소스를 다시 열어 확인했다. 확인하지 못한 항목은 “미검증”으로 표시하고 Review record에 모았다. Docker·라이브 디렉터리는 사용하지 않았다.
> 경로 표기: 접두 없는 `*.go`는 `ui/backend/internal/httpapi/`, `ldapclient/…`는 `ui/backend/internal/ldapclient/`, `ui/frontend/…`는 저장소 루트 기준.
> 오류 본문은 **#218 봉투**(`{error, message, code, requestId, retryable}`, `error`==`message`)를 따르며 여기서 재정의하지 않는다. 이 패키지가 추가하는 코드·선택 키는 “Error codes introduced”에 모았다.

## Problem

코어 `/api/users`·`/api/groups` 쓰기에는 동시성 제어도 재시도 안전성도 없다. 프로필·백업 쓰기는 `ETag`+`If-Match`를 쓴다(`app_profile_handlers.go:60,66-73`, `backup_handlers.go:54-58`).

| 관찰 | 근거 |
|---|---|
| 코어 쓰기 핸들러는 `If-Match`·`ETag`를 전혀 읽지 않는다. 마지막 쓰기가 이긴다 | `user_handlers.go:20-182`, `group_handlers.go:20-101` |
| 사용자 생성은 Add 후 비밀번호 Password Modify 두 단계다. 두 번째가 실패하면 항목은 남고 `dn`은 버려진다 | `ldapclient/users.go:120-133`(실패 시 `return dn, fmt.Errorf("user created but setting password failed: %w", err)`), 핸들러가 `dn`을 성공 때만 사용 `user_handlers.go:37-51` |
| 그 오류의 사용자 가시 결과가 일관되지 않다: sentinel로 감싸지면(`errors.Is` 통과) 400/403 + “user created but…” 문구, 그렇지 않으면 500 + 고정 `internal error`(원문은 로그만). 어느 쪽이든 재시도는 409 `already_exists` | `errors.go:28-47`, `ldapclient/errors.go:15-55` |
| 사용자 `PUT`은 생략한 필드를 지운다: `cn`·`sn`은 Replace, 나머지 5개(`givenName`·`mail`·`departmentNumber`·`o`·`ou`)는 빈 값이면 값 없는 Replace(삭제) | `ldapclient/users.go:151-158`, `replaceOrClear` `:179-185`. 그룹 `description`도 동일 `groups.go:101-103` |
| 응답 유실 후 재시도의 결과가 오퍼레이션마다 다르다: 생성 409, 삭제 404, 멤버 추가 409(`AttributeOrValueExists`→`ErrConflict`), 멤버 제거 404(`NoSuchAttribute`→`ErrNotFound`), 잠금·해제·`PUT`은 조용히 재적용 | `ldapclient/errors.go:66-77`, `users.go:245-305`. 재적용은 위험하다: 잠금 응답 유실 → 다른 관리자가 해제 → 재시도가 다시 잠근다 |
| 비밀번호 재시도: 지정 비밀번호는 ppolicy 이력(`pwdInHistory`) 때문에 두 번째가 거부될 수 있고, 생성형(빈 `password`)은 재시도할 때마다 새 비밀번호가 만들어진다 | `user_handlers.go:93-139`(생성형 응답 `generatedPassword`) |
| `GET /api/entry`는 `*`만 요청해 운영 속성(`entryCSN` 등)이 응답에 없고, 목록은 지정 속성만 요청한다 | `ldapclient/tree.go:113-119`, `users.go:13-20`(주석: 운영 속성은 `*`로 안 나오므로 명시 필요), `groups.go:13` |
| 프런트 편집 다이얼로그는 목록 항목의 전체 필드를 `PUT`으로 보낸다. 그룹 멤버 저장은 같은 그룹에 **병렬** 요청을 보낸다 | `ui/frontend/src/pages/UsersPage.tsx:78-86`, `GroupsPage.tsx:86-95`, `GroupsPage.tsx:111-114`(`Promise.all`) |

## Intent

(1) 클라이언트가 읽은 상태를 기준으로 쓰기를 조건화(`If-Match`)하고, 낡은 쓰기는 디렉터리에서 **원자적으로** 거부한다. (2) 응답 유실 뒤 같은 `Idempotency-Key` 재시도는 같은 결과를 돌려주고 두 번 실행하지 않는다. (3) 사용자 생성의 부분 성공을 보상하거나 명시적 `partial` 상태로 보고한다. (4) #217이 요구한 공용 멱등 규약(D217-9)을 한 곳에 고정한다. 모든 요구는 **옵트인·가산**이다: 새 헤더 없이 보낸 쓰기는 오늘의 의미를 유지하고 `GET`은 어떤 헤더도 요구하지 않는다.

## Scope

- In scope: 활성 스위치(env·차트 값·`idempotencyEnabled` 설정 노출)와 영속 지문 키, 사용자·그룹·엔트리 이동 쓰기 11개 오퍼레이션의 `If-Match`/`Idempotency-Key`(D216-11 표), 목록 항목 `etag` 필드와 `GET /api/entry`의 `ETag` 헤더, assertion control 기반 원자성, 부분 갱신 `PATCH`(사용자·그룹), 사용자 생성 보상·`partial` 상태, 멱등 기록(메모리, TTL·상한), #217 채택 계약, 오류 코드·선택 키, OpenAPI·`llms.txt`·`docs/api.md`·드리프트 테스트, 프런트 If-Match/키 전송과 412 처리, 라이브 검증.
- Affected users/systems: API 소비자·AI 에이전트(헤더 선택 사용), 브라우저 UI, `ui/backend`(`httpapi`, `ldapclient`), 디렉터리(Modify/Delete/ModifyDN에 critical 제어 추가, 생성 실패 시 Delete), #215·#217·#218 구현자.

## Non-goals

- 비밀번호 변경(RFC 3062 확장 연산)의 `If-Match` — 제어 부착을 go-ldap이 지원하지 않고 slapd 동작이 미검증이다(D216-2). 요청 시 400으로 거부한다.
- `If-Match` 기본 필수화, `If-None-Match`, 조건부 `GET`(304), 일괄 멤버 연산, Post-Read(RFC 4527)로 쓰기 응답에 새 `ETag` 반환.
- 영속(PVC/LDAP) 멱등 기록, 다중 복제본 간 공유 기록(D216-9). 프로필·정책·Keycloak 쓰기의 멱등 키(이미 `If-Match`로 재시도 안전).
- 다중 provider 복제 간 선형화(`If-Match`가 보장하지 않는 것은 D216-1에 명시).
- 코어 CRUD의 인가 모델 변경(ACL이 계속 유일한 인가 수단).

## Requirements

- `REQ-001` — 호환: `If-Match`·`Idempotency-Key` 없는 요청은 현재와 같은 상태 코드·부작용을 낸다(사용자 `PUT` 생략 필드 삭제 포함). `GET`·`HEAD`·`OPTIONS`는 두 헤더를 요구·검증하지 않는다. 이 패키지가 필수로 만드는 오퍼레이션은 없다(D216-3).
- `REQ-002` — 리비전 노출: 사용자·그룹 목록 항목에 `etag`(따옴표 포함 강한 ETag), `GET /api/entry`에 `ETag` 헤더. 값은 디렉터리의 `entryCSN`에서 오며 읽을 수 없으면 생략한다. 비밀·DN을 담지 않는다.
- `REQ-003` — 조건부 쓰기: 사용자 `PUT`/`PATCH`/`DELETE`, 잠금/해제, 그룹 `PUT`/`PATCH`/`DELETE`, 멤버 추가/제거, 엔트리 이동은 `If-Match`가 있으면 현재 `entryCSN`과 일치할 때만 적용된다. 불일치는 412 `revision_conflict`이고 쓰기가 일어나지 않는다. 형식 오류·미지원 오퍼레이션은 400.
- `REQ-004` — 원자성·fail-closed: 조건 평가는 쓰기와 같은 LDAP 연산 안에서(assertion control, critical) 이뤄진다. 서버가 제어를 지원하지 않으면 조건 없는 쓰기로 떨어지지 않고 실패한다.
- `REQ-005` — 부분 갱신: 사용자·그룹 `PATCH`(JSON Merge Patch 의미)가 있고 생략 필드는 보존된다. `PUT`은 불변이며 OpenAPI·문서에 생략 필드 삭제 위험이 명시된다.
- `REQ-006` — 생성 원자성: 비밀번호 단계 실패 시 이 요청이 만든 항목만 삭제한다. 항목 신원(`entryUUID`+`entryCSN`)을 Add 직후 읽어 `creatorsName`이 바인드 DN과 같을 때만 신원을 인정하고, 보상 Delete는 `(&(entryUUID=…)(entryCSN=…))` assertion에 묶인다. 불일치·읽기 실패·삭제 실패는 삭제하지 않고 명시적 `partial` 상태(코드·재시도 힌트·복구 경로)를 반환한다. 보상이 보장하는 것은 이 둘 중 하나뿐이다: 신원이 묶인 삭제, 또는 `partial` 응답.
- `REQ-007` — 멱등 규약: `Idempotency-Key` 형식·범위(주체 결속)·요청 지문·처리 중 충돌·재생(`Idempotent-Replayed: true`)·TTL(기본 24h)·저장 상한이 정의된다. 같은 키 재시도는 한 번만 실행된다. 처리 중 기록은 **시간으로 만료하지 않는다**(LDAP 연산의 결과를 관측할 때까지 유지). 상한에 도달하면 **새 키를 거부**하고(503 `idempotency_capacity`) 만료되지 않은 완료 기록을 쫓아내지 않는다.
- `REQ-008` — 비밀: 비밀번호·생성 비밀번호는 기록에도 재생 본문에도 없다. 지문은 비밀을 평문으로 저장하지 않는다. 서버 생성 비밀번호 요청은 멱등 키와 함께 쓸 수 없다.
- `REQ-009` — 결과 저장 규칙·평가 순서: 2xx와 불확정·부분 결과(`partial_failure`, `idempotency_outcome_unknown`)를 TTL 동안 저장해 같은 키 재시도가 그대로 재생한다. 그 외 4xx·5xx는 저장하지 않는다. 클라이언트가 끊겨도 연산은 끝까지 수행되고 결과가 기록된다. 결과를 판정할 수 없으면(연결 유실) `outcome_unknown`으로 기록하고 409 `idempotency_outcome_unknown`으로 응답한다. 재생은 `If-Match` 평가보다 먼저이며 `If-Match`는 지문에 포함하지 않는다.
- `REQ-010` — 공용 계약: #217의 `POST /api/v1/backups/jobs/{kind}`가 202+`Location` 재생, 키 충돌, TTL, 인가 결합, 정책 리비전 결합을 이 규약으로 채택할 수 있다. 정책 ETag를 job 상태 리비전으로 쓰지 않는다.
- `REQ-011` — 오류: 모든 새 오류는 #218 봉투·코드 표를 쓰고, 새 코드·선택 키는 “Error codes introduced”에 나열한다. 기존 `if_match_required`(428)·`revision_conflict`(412)를 재사용한다.
- `REQ-012` — 문서·계약: OpenAPI(헤더 파라미터·`etag`·`PATCH`·응답 헤더)·`llms.txt`·`docs/api.md`가 동기화되고 드리프트·계약 테스트가 모든 보호 라우트의 412/400/409/422/503을 덮는다. `PATCH` 추가로 깨지는 정확 `Allow`·메서드 단언 테스트는 라우트 변경과 같은 작업에서 갱신한다.
- `REQ-013` — 프런트: 편집·삭제 다이얼로그는 `etag`가 있으면 `If-Match`를, 생성·편집·삭제는 시도별 `Idempotency-Key`를 보낸다. 412는 재조회 안내로 처리한다. 구 서버·구 UI 조합이 계속 동작한다. 병렬 멤버 연산에는 `If-Match`를 보내지 않는다.
- `REQ-014` — 검증: 실제 slapd에서 assertion control 지원, 비루트 바인드의 `entryCSN` 가독, 응답 유실 재시도, stale 거부, 보상 경로, 동시 중복 생성이 확인된다. 복제 한계는 문서화하고 저렴하게 가능하면 시험한다.
- `REQ-015` — 한계 공개: 멱등 기록이 재시작·복제본 간에 유지되지 않음, `If-Match`의 복제 한계, 단일 복제본 전제를 문서와 차트 README에 명시한다.
- `REQ-016` — 배포 전제: 메모리 멱등 기록은 UI 프로세스가 하나일 때만 유효하다. 명시적 활성 스위치(env `UI_IDEMPOTENCY_ENABLED`, 차트 `ui.idempotency.enabled`)가 켜져 있을 때만 `Idempotency-Key`를 처리하고, 꺼져 있으면 키가 붙은 보호 라우트 요청을 조용히 무시하지 않고 422 `idempotency_unsupported`로 거부한다. 차트는 복제본 1개이고 롤링 중첩이 불가능한 전략일 때만 활성으로 렌더한다. 재시작은 기록을 지우고 중단된 요청의 LDAP 효과는 복구할 수 없음을 문서화한다.
- `REQ-017` — 지문 키: 지문 HMAC 키는 배포 단위로 영속되는 비밀이다(0600 개인 파일, 한 번 생성, `SESSION_SECRET` 저장소와 같은 규칙). #217의 영속 job 기록은 지문과 `key_id`만 저장하고 키는 저장하지 않으며, 재시작 뒤에도 같은 요청을 알아본다. #216 메모리 저장소는 같은 키에서 파생할 수 있으나 영속을 요구하지 않는다.

## Acceptance scenarios

### `AC-001` — 헤더 없는 요청은 오늘과 같다

- Covers: `REQ-001`, `REQ-005`
- Given 기존 클라이언트(헤더 없음), 일부 필드가 채워진 사용자
- When `PUT /api/users`에서 `givenName`·`mail`·`department`를 생략하고, 그룹·잠금·이동·삭제도 헤더 없이 호출
- Then 상태 코드·부작용이 변경 전 기준선과 같다(생략 필드는 삭제됨). 기존 테스트는 **두 곳을 제외하고** 무수정 통과한다: `PATCH /api/users`를 “잘못된 메서드”로 쓰는 `ui/backend/internal/httpapi/api_docs_test.go:197`(정확한 `Allow` 집합 단언)와 `scripts/test/test-api-edge-codes-local.py:152`(`PATCH`→405 기대)는 `PATCH` 라우트 추가와 같은 작업(T-012)에서 다른 잘못된 메서드·새 `Allow` 집합으로 갱신한다.

### `AC-002` — `etag` 노출

- Covers: `REQ-002`
- Given 사용자·그룹이 있는 디렉터리
- When 목록과 `GET /api/entry?dn=`을 호출
- Then 각 항목에 `etag`(`"<entryCSN>"`)가 있고 `GET /api/entry`는 같은 값을 `ETag` 헤더로 준다. 응답 어디에도 `userPassword`가 없다. 비루트 일반 바인드에서도 `entryCSN`이 읽히거나, 못 읽으면 필드·헤더가 생략되고 다른 필드는 불변이다.

### `AC-003` — stale `If-Match`는 412이고 쓰기가 없다

- Covers: `REQ-003`, `REQ-004`, `REQ-011`
- Given 클라이언트 A가 `etag`를 읽은 뒤 B가 같은 항목을 수정
- When A가 낡은 `If-Match`로 각 보호 라우트(사용자 PUT/PATCH/DELETE/lock/unlock, 그룹 PUT/PATCH/DELETE, 멤버 추가/제거, 이동)를 호출
- Then 모두 412 `revision_conflict`(`retryable:false`) 봉투이고 디렉터리 변경이 없다(`entryCSN` 불변).

### `AC-004` — 일치하면 원자적으로 적용, 경쟁에서 정확히 하나만 성공

- Covers: `REQ-003`, `REQ-004`
- Given 같은 `etag`를 가진 클라이언트 둘
- When 동시에 같은 `If-Match`로 `PUT`
- Then 정확히 하나가 204, 나머지는 412. assertion 없는 읽기-비교-쓰기 창이 없다(코드 경로에 읽기 선검사 없음).

### `AC-005` — 잘못된·미지원 `If-Match`

- Covers: `REQ-003`, `REQ-004`
- When `If-Match`가 CSN 형식이 아님/목록/`W/` 약한 태그, `POST /api/users/password`에 `If-Match`
- Then 400 `invalid_request`(쓰기 없음). `If-Match: *`은 “항목이 존재할 것”으로 허용(조건 없는 쓰기와 동일 결과). 서버가 assertion을 거부(`unavailableCriticalExtension`)하면 500 `internal`이고 쓰기 없음.

### `AC-006` — `PATCH`는 생략 필드를 보존한다

- Covers: `REQ-005`
- When `PATCH /api/users` `{"dn":…,"mail":"x"}`, `{"dn":…,"givenName":null}`, `{"dn":…,"givenName":""}`, `{"dn":…,"uid":"y"}`, `{"dn":…}`
- Then 각각 `mail`만 변경 / `givenName`만 삭제 / 400 / 400(`uid`·`password` 불변·금지) / 400(필드 없음). 나머지 속성은 전후 동일.

### `AC-007` — 생성 실패 시 보상

- Covers: `REQ-006`
- Given 비밀번호 정책(ppm)이 거부할 비밀번호
- When `POST /api/users`(uid 신규, 비밀번호 약함)
- Then 4xx 봉투(`state:"rolled_back"`), 디렉터리에 `uid` 항목이 없다. 같은 uid로 올바른 비밀번호 재시도는 201.

### `AC-008` — 보상 불가 시 명시적 `partial`

- Covers: `REQ-006`, `REQ-011`
- Given 비밀번호 단계 실패 후 (a) 보상 Delete가 거부(ACL) (b) Add 직후 읽은 신원과 현재 항목이 다름(다른 관리자가 그 사이 삭제 후 같은 DN으로 재생성, 또는 수정) (c) `creatorsName`이 바인드 DN과 다르거나 읽을 수 없어 신원 불인정
- When `POST /api/users`
- Then 500 `partial_failure`(`retryable:false`, `state:"partial"`, `dn`, 복구 경로 문구)이고 같은 `Idempotency-Key` 재시도는 같은 `partial_failure`를 재생한다(다른 키·키 없음은 409 `already_exists`). 항목은 남는다. 비밀번호 단계는 응답이 유실됐을 뿐 **적용되었을 수 있으므로** 비밀번호 유무·바인드 가능 여부를 보장하지 않는다. 다른 생성자가 지우고 다시 만든 항목은 `entryUUID`가 달라 삭제되지 않는다.

### `AC-009` — 응답 유실 재시도가 중복·파괴 효과를 만들지 않는다

- Covers: `REQ-007`, `REQ-009`
- Given 서버가 요청을 처리했으나 클라이언트가 응답을 받지 못함
- When 같은 `Idempotency-Key`·같은 본문으로 재전송(생성, 삭제, 멤버 추가, 잠금 뒤 다른 관리자 해제 후 잠금 재시도)
- Then 원래 상태·본문·`Location`과 `Idempotent-Replayed: true`가 오고 디렉터리 변경은 한 번뿐이다(사용자 1명, 잠금 재적용 없음).

### `AC-010` — 키 오용·경쟁

- Covers: `REQ-007`
- When (a) 같은 키·다른 본문/대상 (b) 다른 주체가 같은 키 (c) 같은 키 동시 두 요청 (d) 키 형식 위반·헤더 중복
- Then (a) 422 `idempotency_key_reused` (b) 독립 새 요청이며 첫 주체의 결과·존재 여부가 드러나지 않음 (c) 하나는 실행, 다른 하나는 409 `idempotency_key_conflict`(`retryable:true`, 첫 요청이 끝난 뒤에는 재생) (d) 400. 동시 중복 생성(다른 키)은 하나만 201, 나머지 409 `already_exists`.

### `AC-011` — 비밀은 저장·재생되지 않는다

- Covers: `REQ-008`
- When 지정 비밀번호와 키로 `POST /api/users/password`, 빈 `password`+키, 기록 덤프/로그 검사
- Then 지정 비밀번호 요청은 재생 시 비밀이 없는 본문(`{}`)이고, 빈 `password`+키는 422 `validation_failed`로 거부된다. 기록·로그·메트릭에 비밀번호·`generatedPassword`·요청 본문이 없다. 지문은 HMAC 값뿐이다.

### `AC-012` — 재생이 조건보다 먼저, 실패는 저장하지 않는다

- Covers: `REQ-009`
- When (a) `If-Match` v1 + 키로 `PUT` 성공 후 같은 요청 재전송(이제 v1은 낡음) (b) 첫 시도가 412/400 또는 일반 5xx였다가 같은 키로 재시도 (c) 첫 시도가 `partial_failure`였다가 같은 키로 재시도
- Then (a) 412가 아니라 원래 204 재생 (b) 그 기록은 저장되지 않았으므로 재실행된다(새 `If-Match`로 성공 가능) (c) 같은 `partial_failure` 재생. 키 없는 `If-Match` 재시도는 412(안전하되 시끄러움).

### `AC-013` — TTL·상한

- Covers: `REQ-007`
- When 시계 주입으로 24h 경과, 전역 상한(10,000)·주체당 상한(1,000)에 도달, 모든 기록이 `in_flight`
- Then 만료 기록만 제거되고 그 키는 새 요청 취급이다. 상한 도달 시 **새 키는 503 `idempotency_capacity`(`retryable:true`, `Retry-After`)로 거부**되고 미만료 완료 기록은 제거되지 않아 기존 키의 재생·충돌 응답은 계속 나간다. 모두 `in_flight`여도 같은 규칙(새 키 거부, 기존 `in_flight`는 시간 만료 없이 유지). 보호 라우트의 응답 본문은 ≤4KiB 고정 테스트로 보장한다.

### `AC-014` — #217 채택 계약

- Covers: `REQ-010`
- Then D216-12의 계약(같은 키→같은 job의 202+`Location`, 다른 kind/요청→422, 키는 요청 관리자 지문에 결속, 정책 리비전 불일치는 원 응답 재생, 정책 ETag를 job 리비전으로 쓰지 않음)이 #217 T-031의 입력으로 충분히 구체적이다: 계약 테스트 표가 이 문서에 있고 #217에서 그대로 쓸 수 있다.

### `AC-015` — `GET`은 헤더를 요구하지 않는다

- Covers: `REQ-001`
- When `GET`·`HEAD`·`OPTIONS`(목록·단건·#215 커서 모드 포함)를 두 헤더 없이/있이 호출
- Then 헤더가 있어도 무시되고 응답은 동일하다. `OPTIONS`는 #230대로 204+`Allow`.

### `AC-016` — 오류 봉투와 코드 표

- Covers: `REQ-011`
- Then 모든 새 오류 응답이 봉투(`error`==`message`, `code`, `requestId`, `retryable`)이고 코드·상태·`retryable`이 “Error codes introduced”와 같다. #218 골든 목록에 흡수된다.

### `AC-017` — 문서·계약 동기화

- Covers: `REQ-012`, `REQ-015`
- Then `openapi.json`·`llms.txt`·`docs/api.md`·차트 README가 새 헤더·필드·`PATCH`·한계를 설명하고, `TestOpenAPIMatchesRegisteredRoutes`·`TestOpenAPIOperationsAreComplete`(`api_contract_test.go:39,84`)와 신규 표 주도 계약 테스트(보호 라우트 × {412, 428 해당 없음, 400, 409, 422})가 통과한다.

### `AC-018` — UI

- Covers: `REQ-013`
- When 사용자 편집 중 다른 곳에서 변경 후 저장, 네트워크 오류 뒤 같은 다이얼로그에서 재제출, 그룹 멤버 일괄 저장, 신구 서버·UI 조합
- Then 412는 “다른 곳에서 변경됨, 새로 고침” 안내와 재조회, 재제출은 같은 키로 한 번만 반영, 멤버 일괄 저장은 412 없이 성공, `etag` 없는 서버·헤더 없는 UI 조합이 동작한다. `@fixture` e2e 무수정 통과.

### `AC-019` — 라이브 검증과 한계 증거

- Covers: `REQ-014`, `REQ-015`
- Then T-002·T-021의 라이브 결과(제어 지원, `entryCSN` 가독, 복제 시험 또는 “미시험” 명시)가 EVIDENCE에 기록되고 이 문서의 “검증하지 못한 사실”이 갱신된다.

### `AC-020` — 활성 스위치와 비활성 거부

- Covers: `REQ-016`
- Given (a) `UI_IDEMPOTENCY_ENABLED=false` (b) `true`
- When 매트릭스의 쓰기 라우트에 `Idempotency-Key`를 붙여 호출, `GET`에 붙여 호출, 차트를 `helm template`으로 렌더
- Then (a) 쓰기는 422 `idempotency_unsupported`(쓰기 없음), `GET`은 무시, `If-Match`·`PATCH`는 정상 (b) 정상 처리. 렌더: 기본값은 env `false`·전략 변경 없음, `ui.idempotency.enabled=true`+복제본 1은 env `true`+`Recreate`, 복제본 2는 env `false`, 프로필·백업과 함께 켜도 `Recreate`가 한 번만 렌더된다. `GET /api/server-settings`의 `idempotencyEnabled`가 스위치와 일치한다.

### `AC-021` — 결과 관측 전에는 키를 놓지 않는다

- Covers: `REQ-007`, `REQ-009`
- When (a) 클라이언트가 요청 중 연결을 끊음 (b) 같은 키의 두 번째 요청이 첫 요청 처리 중 도착 (c) LDAP 연결이 쓰기 연산 도중 끊겨 결과를 모름 (d) 핸들러 패닉
- Then (a) 연산은 끝까지 수행되고 결과가 기록되어 같은 키 재시도는 원래 결과를 재생 (b) 두 번째는 409 `idempotency_key_conflict`이고 연산은 한 번만 수행 (c)(d) 기록은 `outcome_unknown`이며 409 `idempotency_outcome_unknown`(`retryable:false`)과 재생된다. 어느 경우에도 시간 경과로 키가 풀려 두 번째 실행이 일어나지 않는다.

### `AC-022` — 보상은 신원에 묶인다(삭제 후 재생성 경쟁)

- Covers: `REQ-006`
- Given 비밀번호 단계 실패 직전에 다른 관리자가 같은 DN의 항목을 삭제하고 새로 만듦(또는 `creatorsName`이 바인드 DN과 다름, 신원 읽기 실패)
- When 보상 단계가 실행
- Then assertion `(&(entryUUID=<원래>)(entryCSN=<c0>))`가 실패해(결과 122) 새 항목은 삭제되지 않고 응답은 `partial_failure`다. 신원 불인정·읽기 실패도 삭제 없이 `partial_failure`다. 결정 로직의 순수 함수 단위 테스트와, 삭제·재생성된 DN에 옛 `entryUUID` assertion Delete가 122로 실패함을 보이는 라이브 프리미티브 테스트로 증명한다.

### `AC-023` — 영속 지문 키와 재시작

- Covers: `REQ-017`
- When (a) 같은 영속 키로 UI를 재시작한 뒤 #217식 영속 기록과 같은 요청을 비교 (b) 키 파일을 회전(`current`+`previous`) (c) 기록의 `key_id`에 맞는 키가 없음
- Then (a) 재시작 전과 같은 지문으로 같은 요청을 알아본다(기록에는 지문·`key_id`만 있고 키 문자열이 어떤 기록·로그에도 없다) (b) 이전 `key_id` 기록도 검증된다 (c) 재생도 `idempotency_key_reused`도 아닌 409 `idempotency_outcome_unknown`이다. 키 파일은 0600·소유자 검사를 통과해야 하고 아니면 기동이 거부된다.

## Architecture and decisions

- Relevant ADR/design links: [api-error-envelope](../api-error-envelope/CHANGE.md)(D218-3 코드 표, D218-5 `retryable`, D218-12 CORS, D218-14 규약, D218-15 메시지, D218-16 Origin 게이트), [backup-job-ids](../backup-job-ids/CHANGE.md)(D217-9), [api-cursor-pagination](../api-cursor-pagination/CHANGE.md)(GET 무헤더), [api-integration PLAN](../api-integration/PLAN.md), [AGENTS.md](../../../AGENTS.md)(`userPassword` 비노출, LDAP 와이어 코드 단위 테스트 없음).
- ADR threshold result: `required` — 공용 멱등 규약(#217이 의존)과 외부 계약(`etag`·헤더·`PATCH`)·디렉터리 쓰기 의미는 되돌리기 어렵다. 수용 시 ADR 한 건으로 D216-1·2·5·6~9를 승격한다.
- Alternatives and important trade-offs: 각 결정의 “대안” 열.

### 결정 기록 (ID는 이 패키지 한정이라 `D216-` 접두)

| ID | 결정 | 이유 | 비용 | 탈출구 |
|---|---|---|---|---|
| D216-1 | **리비전 = `entryCSN` 강한 ETag.** 값은 `"20261006123456.123456Z#000000#001#000000"`(따옴표 포함, CSN 형식 `^\d{14}\.\d{6}Z#[0-9A-F]{6}#[0-9A-F]{3}#[0-9A-F]{6}$`). 획득: 사용자·그룹 목록 항목의 새 선택 필드 `etag`(속성 목록에 `entryCSN` 추가: `users.go:17-20`, `groups.go:13`, #215 두 단계 조회 포함), `GET /api/entry?dn=`의 `ETag` 헤더(요청 속성에 `entryCSN` 명시: `tree.go:117`, 응답 `attributes`에는 넣지 않고 헤더로만). 읽을 수 없으면(ACL) 생략. 쓰기 응답에는 새 `ETag`를 **싣지 않는다**(재조회 필요). 이 필드는 프로필의 정수 `revision`(`app_profile_handlers.go:60`)과 구별해 `etag`로 부른다 | `entryCSN`은 모든 항목이 가진 복제 대상 속성(`olcDbIndex: entryCSN eq`, `image/ldifs/01-cn-config.ldif:77-78`)이고 `CSNMatch` 등가 비교가 가능해 assertion 필터에 그대로 쓰인다. 각 수정마다 새 값이라 강한 검증자 요건을 충족. 읽기-비교 없이 쓰기 한 번으로 조건을 평가 | **가짜 충돌**: 사용자 항목을 건드리는 부수 쓰기도 CSN을 올린다 — lastbind의 `pwdLastSuccess`(`image/README.md:219-226`, 기본 꺼짐), ppolicy 실패 바인드 기록(`pwdFailureTime`; 미검증), `memberof` 오버레이의 `memberOf` 갱신(CSN 변경 여부 미검증). 결과는 불필요한 412와 재조회일 뿐 유실이 아니다. 쓰기 응답에 새 태그 없음 → 연속 편집은 재조회. 필드 1개 +≈45B/항목 | 대안: ① `modifyTimestamp` 기각(1초 해상도, 같은 초 두 쓰기 구분 불가) ② `entryUUID` 기각(편집으로 안 변함) ③ 속성 해시 기각(서버가 해시를 원문으로 되돌릴 수 없어 assertion 필터를 만들려면 읽기 선행이 필요하고 읽기-쓰기 창이 생김). 가짜 충돌이 문제면 Post-Read(RFC 4527)와 속성 해시를 후속 변경으로 검토 |
| D216-1a | **`If-Match`가 보장하는 것/않는 것.** 보장: 쓰기를 받는 slapd 노드에서 그 항목의 현재 `entryCSN`이 클라이언트가 본 값과 같을 때만 적용(노드 로컬 원자적). 비보장: ① 복제 provider 간 선형화 — 노드 A에서 읽은 태그가 노드 B에서는 아직 옛 CSN이면 정상 쓰기도 412(안전한 실패), 반대로 같은 태그로 두 노드에 동시 쓰기가 각각 통과하면 둘 다 성공하고 이후 `entryCSN` 시각 last-write-wins로 한쪽이 **조용히 사라진다**(AGENTS.md “Multi-provider” 항목, `image/entrypoint.sh:494`). ② 읽기 이후 다른 속성의 변경 구분(전체 항목 단위 태그) ③ 이동·삭제된 항목의 태그 재사용(삭제는 404) | 복제 위에서 조건부 쓰기는 낙관적 보호이지 합의가 아님을 호출자가 알아야 한다 | 복제 환경에서는 쓰기 노드가 고정되지 않으면 잔여 유실 위험이 남는다(문서화) | 단일 쓰기 노드 라우팅은 운영 권고로 문서화. 영구 해법은 이 변경 범위 밖 |
| D216-2 | **원자성 = RFC 4528 assertion control(`1.3.6.1.1.12`), critical, 필터 `(entryCSN=<태그>)`.** Modify(`PUT`·`PATCH`·lock·unlock·멤버 추가/제거), Delete(사용자·그룹), ModifyDN(이동)에 부착. go-ldap v3.4.14에는 이 제어 타입이 없지만 `Control` 인터페이스(`control.go:207-214`)와 `ldap.CompileFilter`(`filter.go:77`)가 있어 `Encode()`에서 컴파일된 필터를 값으로 넣는 로컬 구현 하나로 충분하다(`NewModifyRequest`/`NewDelRequest`는 `controls` 인자, ModifyDN은 `NewModifyDNWithControlsRequest` `moddn.go:41-53`). `ControlString`은 값을 문자열로 넣어 부적합. 헤더 값은 위 CSN 정규식을 통과해야만 필터에 들어간다(원문 연결 금지). 결과 매핑: `assertionFailed(122)`(`error.go:82`) → 412 `revision_conflict`; `unavailableCriticalExtension(12)` → 500 `internal`(로그에 원문, 쓰기 없음); 항목 없음 → 기존 404. 필터 평가는 호출자 바인드의 `entryCSN` 접근을 요구하므로 못 읽는 바인드는 항상 412(애초에 태그를 못 얻는다). **읽기-비교-쓰기 폴백은 두지 않는다**(조용한 창 방지). 비밀번호 확장 연산은 제어 부착 수단이 없어 `If-Match` 미지원(400) | 한 왕복으로 조건 평가와 쓰기가 같은 연산에서 일어난다. critical이라 미지원 서버는 조건 없는 쓰기가 아니라 오류를 낸다 | 로컬 제어 타입 약 30줄과 라이브 확인 필요. **slapd 빌드의 assertion 지원은 이 문서 작성 중 라이브 확인하지 못했다(미검증, T-002 선행 필수)** | T-002에서 미지원으로 판명되면 D216-2를 “노드 로컬 읽기-비교-쓰기 + 문서화된 경쟁 창”으로 개정하고 재검토 |
| D216-3 | **`If-Match`는 옵트인. 이 패키지가 필수로 만드는 오퍼레이션은 없다.** `UI_REQUIRE_IF_MATCH`(엄격 모드) 같은 필수화 플래그는 **이름만 예약하고 구현하지 않는다**. 도입 기준: UI가 전 편집에 `If-Match`를 보낸 릴리스가 지나고, 소비자 가이드가 갱신된 뒤. 후보: 사용자·그룹 `PUT`/`DELETE`, 이동. 프로필·백업의 428(필수)은 그대로 | 요구 5번: 기존 클라이언트가 계속 동작해야 한다. 사용자 `PUT`의 필드 삭제 위험은 필수화가 아니라 `PATCH`(D216-4)로 해소한다. 삭제·잠금은 재시도해도 파괴적 중복이 없다(404/재적용은 키로 해소, D216-8) | 헤더를 안 보내는 클라이언트는 여전히 마지막 쓰기 승 | 필수화는 별도 변경(Class D 승격) |
| D216-4 | **`PUT` 유지 + 안전한 `PATCH` 추가.** `PATCH /api/users`, `PATCH /api/groups`(본문에 `dn`, 현행 `PUT`과 같은 위치). 의미는 JSON Merge Patch(RFC 7396): 키 없음=보존, 문자열=설정, `null`=삭제, `""`=400(모호성 제거). `cn`·`sn`은 `null`/`""` 금지(필수). `uid`·`password`·알 수 없는 키는 400(`DisallowUnknownFields`), 변경 필드 없음은 400. 구현은 키별 Replace만 담은 한 번의 Modify(`replaceOrClear` 재사용). 허용 Content-Type: `application/merge-patch+json`·`application/json`. `PUT` 의미는 불변이며 OpenAPI 설명에 “본문에 없는 `givenName`·`mail`·`department`·`organization`·`organizationalUnit`(그룹은 `description`)은 삭제된다”를 명시 | 외부 소비자가 필드 일부만 바꾸려다 데이터를 지우는 사고의 구조적 해법. `PUT`을 바꾸면 구 클라이언트가 깨진다 | 새 메서드·핸들러 2개, 존재 여부(`null` vs 없음) 구분용 디코드 | `PATCH` 미도입 시 `fields` 마스크 대안(기각: 새 개념, Merge Patch가 표준) |
| D216-5 | **사용자 생성 보상(신원 결속).** 순서: ① Add(비밀번호 없이) ② 비밀번호가 있으면 **Add 직후** 항목의 `entryUUID`·`entryCSN`·`creatorsName`을 명시 요청해 읽는다(`u`,`c0`) ③ `creatorsName`이 바인드 DN(`ldapclient`의 `c.dn`)과 같을 때만 신원을 인정한다(아니면 보상 비활성) ④ Password Modify ⑤ 실패 시 **재읽기 없이** `(&(entryUUID=u)(entryCSN=c0))` assertion Delete(D216-2의 제어). 삭제 성공 → 비밀번호 단계의 오류 상태·코드 + `state:"rolled_back"`(“user not created”, 재시도 안전). 삭제 실패·`assertionFailed`(다른 관리자가 그 사이 삭제 후 재생성하면 `entryUUID`가 달라지고, 수정하거나 비밀번호가 실제로 적용됐으면 `entryCSN`이 달라진다)·신원 읽기 실패·신원 불인정·권한 없음 → **삭제하지 않고** 500 `partial_failure`(`retryable:false`) + `state:"partial"` + `dn`(성공 시 201이 줬을 같은 값) + 고정 문구(복구: 항목을 조회해 상태를 확인한 뒤 `POST /api/users/password`로 설정하거나 `DELETE /api/users?dn=`). 비밀번호 없는 생성은 단일 Add라 보상 대상 없음. 로그: `user_create_rolled_back|user_create_partial request_id=… uid_fp=…`. **보장은 둘 중 하나뿐**: 신원이 묶인 삭제 또는 `partial` 응답 — `partial` 항목에 비밀번호가 없다거나 바인드할 수 없다는 보장은 하지 않는다(응답 유실 뒤 비밀번호 변경이 적용됐을 수 있다). **RFC 4527 Post-Read(`1.3.6.1.1.13.2`)는 쓸 수 없다**: go-ldap v3.4.14 `Conn.Add`는 오류만 돌려주고 응답 제어를 버린다(`add.go:70-100`; `ModifyWithResult`만 제어를 돌려줌 `modify.go:148-155`), 요청 전송·응답 읽기는 비공개(`doRequest`/`readPacket`)라 직접 조립할 수 없고, `DecodeControl`(`control.go:553`)도 이 OID를 모른다. 그래서 Add 직후 DN 기준 검색이 기본 경로다(요청된 제어는 보내지 않는다). 잔여 경쟁: 같은 바인드 DN을 쓰는 다른 세션이 Add와 검색 사이에 지우고 재생성하면 신원이 새 항목으로 잡힌다 — 같은 관리자 DN의 동시 같은 uid 생성은 운영상 드물고 `creatorsName` 확인이 다른 생성자는 걸러낸다. 단일 Add에 `userPassword`를 넣는 방식은 이 이미지에서 `olcPPolicyHashCleartext: TRUE`(`01-cn-config.ldif:127`)라 원자적일 수 있으나 해싱을 보장하지 않는 외부 디렉터리에서 평문이 저장될 위험이 있어 기본으로 채택하지 않는다(`users.go:82-85` 의도 유지; **Q2 해소: 후속**, 해싱·정책 검증 뒤) | 삭제가 이 요청이 만든 바로 그 항목(UUID)의 직후 상태(CSN)에만 묶여 남의 항목을 지우지 않는다. `dn` 노출은 성공 값과 같아 D218-15와 충돌하지 않는 한 건의 예외(#218 표에 기록) | 비밀번호 있는 생성에 읽기 한 번 추가, `creatorsName`·`entryUUID` 접근이 필요(미검증이면 보상은 항상 `partial`로 수렴) | go-ldap이 Add 응답 제어를 노출하거나 포크하면 Post-Read로 교체해 위 경쟁 창을 닫는다. 생성 모드를 “Add에 비밀번호 포함”으로 바꾸는 설정(후속) |
| D216-6 | **멱등 규약 헤더.** 요청 헤더 `Idempotency-Key`(IETF idempotency-key 초안과 호환하도록 맨 토큰 또는 따옴표 문자열 허용). 값: 1개만, 길이 16–128, 문자 `[A-Za-z0-9._~:-]`, 위반·중복 헤더·빈 값은 400 `invalid_request`. 적용 오퍼레이션만 문서화(D216-11); 매트릭스에 없는 라우트와 `GET`/`HEAD`/`OPTIONS`에서는 무시한다. **기능이 꺼져 있으면(D216-9a) 적용 오퍼레이션에서 키가 붙은 요청은 422 `idempotency_unsupported`(`retryable:false`)로 거부한다.** 재생 응답 헤더 `Idempotent-Replayed: true`(최초 응답에는 없음) | UUID 등 충분한 엔트로피를 요구해 충돌·추측을 줄인다. 키를 받고 조용히 무시하면 호출자가 보호받는다고 오해한다 | 소비자가 키를 생성·보관, 비활성 배포에서는 키를 못 쓴다 | 길이·문자 완화는 가산 |
| D216-7 | **범위·지문.** 범위 = (**주체**, 키). 주체 = 세션의 `sess.DN`(SSO 모드에서 `Bound`는 서비스 계정이지만 `DN`은 사용자 신원: `session/store.go:20-26`)이며 기록 키에는 DN 원문이 아니라 `SHA-256(DN‖0x00‖키)`만 쓴다. **다른 주체의 같은 키는 독립 새 키**라 존재 여부가 새지 않는다. 지문 = `HMAC-SHA256(fk, method‖0x00‖경로 템플릿+쿼리(정렬)‖0x00‖정규화 본문)`; 정규화는 JSON 파싱 후 키 정렬 재직렬화. `If-Match`·`Origin`·쿠키는 지문에 넣지 않는다. 본문 상한 64KiB(초과 400). **키 `fk`는 배포 단위 영속 비밀에서 파생한다**(D216-9b). 비밀번호는 HMAC 입력에는 들어가지만 저장되는 것은 32B HMAC와 `key_id`뿐이라 기록 유출로 사전 대입이 불가능하다 | 범위를 (주체, 키)로 두고 method·대상을 지문에 넣어 같은 키의 다른 오퍼레이션 재사용을 422로 잡는다(요청이 말한 “주체+method+path” 범위를 포함하는 더 엄격한 형태) | 본문 버퍼링·재직렬화 CPU(상한 64KiB) | 지문에 헤더 추가는 가산 |
| D216-8 | **상태기계·재생.** 기록 상태 `in_flight` → `completed`. 새 키: `in_flight` 삽입 후 실행. 같은 키+같은 지문이 `in_flight` → 409 `idempotency_key_conflict`(`retryable:true`). 같은 키+다른 지문 → 422 `idempotency_key_reused`. `completed` → **원래 상태·본문·`Location`을 재생**하고 `Idempotent-Replayed: true`. **`in_flight`는 시간·연결 종료·패닉으로 지우지 않는다.** 연산은 요청 컨텍스트가 취소돼도(클라이언트 끊김) 끝까지 수행되고(`context.WithoutCancel`로 분리; `ldapclient`는 컨텍스트를 호출 시작에서만 확인 `users.go:36`) 프로세스가 LDAP 연산의 결과를 관측한 뒤에만 `completed`로 바뀐다. 결과를 판정할 수 없으면 — 쓰기 연산이 요청 전송 후 네트워크 계열 오류(`ldap.ErrorNetwork`=200, `error.go:86`)로 끝나거나 핸들러가 패닉 — `outcome_unknown`으로 **기록**하고 409 `idempotency_outcome_unknown`(`retryable:false`, “리소스를 읽어 상태를 확인한 뒤 재시도”)으로 응답하며, 같은 키 재시도는 같은 응답을 재생한다. **저장하는 결과**(TTL 동안): 2xx, `partial_failure`, `idempotency_outcome_unknown`. 그 외 4xx·일반 5xx는 기록을 삭제해 같은 키로 재시도할 수 있다(5xx 일반은 재생하지 않음). 저장 내용: 상태 코드, 허용 응답 헤더(`Location`), 본문 ≤4KiB, 생성·만료 시각, 지문 HMAC·`key_id`. **저장하지 않는 것**: 요청 본문, 비밀번호, `generatedPassword`, 쿠키, 원 DN 주체. 서버 생성 비밀번호 요청(빈 `password`)은 키와 함께 오면 422 `validation_failed` | 키가 한 번 점유되면 결과가 관측될 때까지 두 번째 실행이 불가능하다(시간 만료는 중복 실행을 허용했다). 부분·불확정 결과를 같은 키로 다시 내보내 409 `already_exists`로 오인하지 않게 한다 | LDAP 호출이 멈추면(`dial.go`에 연산 타임아웃 없음, 미검증) 그 키는 재시작까지 `in_flight`로 남아 같은 키 요청은 409 `idempotency_key_conflict`가 된다(안전하나 소비자는 새 키 불가피). 재생되는 `partial_failure`는 관리자가 그 뒤 복구해도 원래 결과를 말한다(응답 문구가 조회를 안내) | 판정 불가 연산에 서버측 타임아웃을 도입하면 `outcome_unknown`으로 수렴(후속) |
| D216-9 | **저장소 = 프로세스 메모리(TTL·상한), 기본 TTL 24h, 명시 활성 스위치 필요(D216-9a).** `UI_IDEMPOTENCY_TTL`(기본 24h, 상한 7d), 전체 10,000건·주체당 1,000건(`in_flight`와 `completed` 합산). **상한에 도달하면 새 키를 거부한다: 503 `idempotency_capacity`(`retryable:true`, `Retry-After` 5s).** **만료되지 않은 기록은 어떤 이유로도 쫓아내지 않는다**(제거 대상은 만료 기록뿐, 삽입 시 지연 정리+주기 청소). 모든 기록이 `in_flight`여도 같은 규칙이다. 기존 키의 재생·충돌 응답은 상한과 무관하게 나간다. 저장소 비교는 이 표 아래 | 재생 보증이 곧 계약이므로 용량 때문에 보증을 깨지 않는다 | 포화되면 새 키가 거절된다(공격 시 주체당 상한이 한 주체의 전체 점유를 막는다; 정상 사용은 24h 동안 1,000건 미만을 가정) | 상한은 env로 조정(가산), 영속 저장소는 후속 |

| 저장소 | 비용 | 재시작 생존 | 다중 복제본 정확성 | 판정 |
|---|---|---|---|---|
| 프로세스 메모리 | 최소, 새 볼륨·스키마 없음. 세션 저장소(`session/store.go`)와 같은 수명 | 없음 | 복제본마다 별도(정확하지 않음) | **채택** |
| PVC 파일(프로필·백업식) | 코어 CRUD에 PVC를 강제(현재 `ui.enabled`만으로 동작) | 있음 | 단일 기록자 전제 | 기각(Class D, 후속) |
| LDAP 항목에 표지(Add와 함께) | 스키마·ACL·복제(LWW) 부담, 항목 오염, 생성에만 적용·삭제는 흔적 없음 | 있음 | 복제 지연에 의존 | 기각 |
| LDAP 전용 서브트리 | 새 컨테이너·스키마·가지치기, 복제 충돌 | 있음 | 지연 의존 | 기각 |

**배포 전제(정정).** 차트에서 UI `replicas`는 값이고(`ui-deployment.yaml:59` `{{ .Values.ui.replicaCount }}`, 기본 1 `values.yaml:536`), `Recreate` 전략과 복제본 1개 강제는 **프로필·백업이 켜졌을 때만** 적용된다(복제본 `fail`은 `:4`(백업)·`:12`(프로필), 조건부 `strategy: Recreate`는 `:60-63`). 그 외에는 기본 롤링 업데이트라 갱신 중 두 프로세스가 겹칠 수 있고 복제본을 2 이상으로 둘 수도 있다. 따라서 **메모리 저장소는 UI 프로세스가 하나일 때만 유효하다**(D216-9a). 유효한 단일 프로세스에서도 재시작은 기록을 지우므로 중단된 요청의 LDAP 효과는 복구할 수 없다. 기록이 없을 때의 구조적 안전망: 코어 CRUD는 DN이 자연 키라 중복 생성은 불가(두 번째 Add는 409), 삭제·이동은 404, 지정 비밀번호는 이력 거부가 최악이고, 재적용되는 연산(잠금/해제 순서 역전)만 남는다(REQ-015). 비동기 자원(#217)은 영속이 필요하므로 D216-12가 자원 기록에 키를 둔다.

| ID | 결정 | 이유 | 비용 | 탈출구 |
|---|---|---|---|---|
| D216-9a | **활성 스위치.** env `UI_IDEMPOTENCY_ENABLED`(기본 `false`)와 차트 값 `ui.idempotency.enabled`(기본 `false`, 옵트인). 차트는 `ui.idempotency.enabled=true`이면 `strategy: Recreate`를 렌더하고(조건을 `or applicationProfiles.enabled backups.enabled idempotency.enabled`로 확장: 현재 조건은 `ui-deployment.yaml:60-63`), 컨테이너 env `UI_IDEMPOTENCY_ENABLED`는 **`replicaCount == 1`이고 전략이 Recreate일 때만** `true`, 아니면 `false`로 렌더하며(복제본 ≥2이면 `NOTES.txt`에 경고) 프로필·백업 `fail` 규칙은 그대로다. 서버는 활성 여부를 인증된 `GET /api/server-settings`에 `idempotencyEnabled`(bool, `dto.go:31-50`의 `serverSettingsResponse`에 가산)로 노출하고 UI는 이 값이 참일 때만 키를 보낸다. 꺼져 있을 때 적용 오퍼레이션의 키 요청은 422 `idempotency_unsupported`. `If-Match`·`PATCH`·보상은 이 스위치와 무관하게 동작한다 | 기본 롤링 업데이트에서 두 프로세스가 겹치면 같은 키가 둘 다 실행될 수 있어 메모리 기록이 보증을 못 준다 | 옵트인이라 기본 설치에서는 키가 쓰이지 않는다(UI는 설정 확인 후 생략). Recreate는 갱신 시 짧은 단절 | 영속 저장소를 도입하면 스위치 조건을 완화(별도 변경) |
| D216-9b | **지문 키(`fk`)는 배포 단위 영속 비밀.** `SESSION_SECRET`과 같은 규칙(`config/secrets.go`의 `loadOrGenerateSecret`: 0700 디렉터리, 0600 일반 파일, 소유자 확인, 원자적 공개, 재시작마다 재생성하지 않음)으로 관리하는 `idempotency-key` 파일을 쓴다. 경로 env `UI_IDEMPOTENCY_KEY_FILE`(절대 경로, 선택): #217 배포(백업 PVC)에서는 차트가 **백업 job 저장소와 같은 PVC의 개인 디렉터리**로 지정해 job 기록과 수명을 맞춘다. 미설정이면 #216 메모리 저장소는 프로세스별 임의 키를 쓴다(영속 불필요: 기록도 같이 사라짐). 사용 키 = `HMAC(마스터, "ldapium/idempotency/v1")`, `key_id` = 사용 키 SHA-256의 앞 8 hex. **영속 기록(#217 job)에는 지문과 `key_id`만 저장하고 키는 어디에도 저장·로그하지 않는다.** 회전: 파일에 `current`·`previous` 두 키를 두면 기록의 `key_id`로 해당 키를 골라 검증하고 새 기록은 `current`로 쓴다. 기록의 `key_id`에 맞는 키가 없으면 지문을 검증할 수 없으므로 **재생도 재사용 오류도 내지 않고** 409 `idempotency_outcome_unknown`으로 응답한다(리소스를 읽어 확인) | 재시작 뒤에도 영속 기록(#217)이 같은 요청을 알아봐야 한다. 키를 기록에 두면 유출 시 사전 대입이 가능하다 | 키 파일 관리·회전 절차 추가. 키 분실 시 기존 기록은 재생 불가(오류가 아니라 불확정 응답) | 키 파생 라벨 변경은 `v2`로 가산 |
| D216-10 | **요청 처리 순서.** 세션(`middleware.go:28-50`) → 라우트 게이트(관리자 DN 등) → Origin 게이트(D218-16) → `Idempotency-Key` 조회·삽입(재생이면 여기서 응답 종료) → `If-Match` 형식 검증 → 핸들러(필요 시 assertion 부착) → 2xx면 기록 완료. 재생은 현재 인증·라우트 인가를 통과한 요청에만 나간다(권한이 회수된 주체는 재생도 못 받는다). 둘 다 있을 때 `If-Match`는 최초 실행에만 평가되고 재생에서는 평가하지 않는다 | 자기 쓰기가 CSN을 올리므로 재생 전에 `If-Match`를 보면 정상 재시도가 412가 된다(AC-012) | 인증 후 재생이라 만료된 세션은 재생 불가(재로그인 후 같은 주체면 가능) | — |
| D216-11 | **보호 매트릭스**(아래). 코어 쓰기 11개 + `PATCH` 2개 모두 `Idempotency-Key` 지원, `If-Match`는 항목을 바꾸는 오퍼레이션만(생성·비밀번호 제외) | 매트릭스에 없는 경우를 조용히 무시하지 않고 문서화·400으로 닫는다 | — | — |
| D216-12 | **#217 채택 계약**(D217-9가 요구한 항목): ① 같은 키+같은 요청(`kind`)은 **같은 job**의 `202`+`Location`(+`job_id`·`kind`)을 재생한다. 응답 본문의 `status`는 재생 시점의 job 현재 상태를 반영한다(`Location`이 권위) ② 같은 키+다른 `kind`/요청 → 422 `idempotency_key_reused` ③ **인가 결합**: 키는 요청한 백업 관리자 주체(`fingerprintIdentity` 16hex, `audit_log.go:108-118`와 같은 규칙)에 결속, 다른 주체는 독립 ④ **TTL·저장**: 메모리 규약의 24h·메모리 저장소가 아니라 job 기록이 영속이므로 키 해시·**지문·`key_id`(D216-9b)**를 job 기록의 가산 필드로 저장하고 보관은 기록 보관(최대 200건·90일, D217-14)을 따른다. 조회는 영속 기록이 먼저이고 재시작 뒤에도 유효하다. 지문 키는 job 저장소와 같은 PVC의 영속 비밀(D216-9b)이며 기록에는 키가 없다 ⑤ **정책 리비전 결합**: job 기록의 `policy_revision`(D217-2)은 불변이며 재생은 정책이 그 뒤 바뀌어도 원래 job을 돌려준다(오류 아님). 정책 ETag 사전조건 `If-Match`가 후에 도입돼도 재생이 먼저 평가된다 ⑥ **정책 ETag를 job 상태 리비전으로 재사용하지 않는다** ⑦ 활성 job이 있을 때 다른 키 요청은 #217의 409 `backup_busy`가 우선 ⑧ job이 끝난 뒤 키 없는 재시도는 새 실행. ⑨ 백업이 켜진 배포는 이미 복제본 1·`Recreate`를 강제하므로(`ui-deployment.yaml:4,60-63`) 단일 프로세스이고 job 키는 영속 기록 기반이다. 따라서 이 라우트의 키 허용 여부는 메모리 스위치(D216-9a)가 아니라 `ui.backups.enabled`를 따른다(#217 T-031이 결정을 확정). #217의 T-031이 이 계약으로 구현 | #217은 단일 활성·비파괴라 중복 실행은 구조적으로 막히지만 응답 유실·종료 후 재시도·재시작 뒤 재시도는 영속 키가 필요하다 | job 기록 스키마 가산(#217 T-031) | 키 없는 호출은 현행 |
| D216-13 | **HEAD/OPTIONS·CORS 상호작용(한 줄).** `OPTIONS`는 #230대로 204+`Allow`이며 두 헤더와 무관하고, `If-Match`·`Idempotency-Key`는 쓰기 요청 헤더이므로 #218의 CORS 허용 요청 헤더(`Content-Type`·`Accept`, 쓰기 메서드 프리플라이트 거부: D218-12)에 **추가하지 않는다**; 교차 출처 쓰기는 허용되지 않으므로 `ETag`만 노출 목록(D218-12 이미 포함)에서 읽기용으로 쓰이고 `Idempotent-Replayed`는 노출하지 않는다 | CORS가 켜져도 쓰기 보호를 약화하지 않는다(REQ-012 of #218) | — | CORS가 쓰기를 허용하게 되면(별도 변경) 허용·노출 목록에 가산 |
| D216-14 | **프런트.** `api.ts`의 `request`(`api.ts:29-51`)에 선택 헤더 인자를 허용한다. 편집·삭제(사용자·그룹)는 항목의 `etag`가 있을 때만 `If-Match`를, 서버 설정 `idempotencyEnabled`가 참일 때만 시도별 `Idempotency-Key`(`crypto.randomUUID()`, 성공·취소 전까지 같은 다이얼로그 제출에서 재사용)를 보낸다. 잠금·해제는 키만. **그룹 멤버 일괄 저장(`Promise.all`, `GroupsPage.tsx:111-114`)은 `If-Match`를 보내지 않는다**(자기 쓰기끼리 CSN을 올려 병렬 요청이 서로 412가 되므로); 키는 연산별로 보낸다. 412는 `revision_conflict` 코드로 감지해 안내 토스트(i18n ko/en)와 `load()` 재조회, 422 `idempotency_unsupported`는 설정 캐시를 무효화하고 키 없이 한 번 재시도한다. 사용자 편집은 `PUT`을 유지(전체 필드 전송 UI)하되 `PATCH` 전환은 후속 선택 | 구 서버 응답에 `etag`·`idempotencyEnabled`가 없으면 헤더를 보내지 않으므로 신 UI+구 서버가 동작, 구 UI+신 서버는 헤더가 없어 동작 | 병렬 멤버 저장은 보호 없음(후속: 일괄 멤버 연산) | — |
| D216-15 | **문서·계약.** `openapi.json`에 각 보호 오퍼레이션의 `Idempotency-Key`·`If-Match` 헤더 파라미터, 응답 `412`/`422`/`409`(키)/`400`, `ETag`·`Idempotent-Replayed` 응답 헤더, `UserItem`·`GroupItem`의 `etag`, `PATCH` 2개, `PUT` 위험 문구, `partial_failure` 응답 예시; `x-ai-hints`·`llms.txt`·`docs/api.md`(ETag 절 `:71-88`에 코어 CRUD 추가, 상태 코드 표 `:100-110`) 갱신. 드리프트 테스트(`api_contract_test.go:39,84`)에 `PATCH` 라우트가 자동 포함되며, 신규 표 주도 계약 테스트가 매트릭스의 모든 행에 대해 412/400/409/422 봉투를 검증 | 외부 소비자·에이전트는 스펙으로 동작한다 | 스펙 증가 | — |

**D216-11 보호 매트릭스** (`Idem`=`Idempotency-Key`, `IfM`=`If-Match`)

| 오퍼레이션 | `Idem` | `IfM`(대상 항목) | 재시도 결과(키 없을 때) | 원자성 수단 |
|---|---|---|---|---|
| `POST /api/users` 생성 | 예 | — (생성) | 409 `already_exists` | 단일 Add + 보상(D216-5) |
| `PUT /api/users` | 예 | 사용자 | 재적용(안전, 최종값 동일) | Modify+assertion |
| `PATCH /api/users` (신규) | 예 | 사용자 | 재적용 | Modify+assertion |
| `DELETE /api/users?dn=` | 예 | 사용자 | 404 | Delete+assertion |
| `POST /api/users/password` | 예(지정 비밀번호만) | **미지원(400)** | 이력 거부 가능 | 확장 연산(제어 불가) |
| `POST /api/users/lock`, `/unlock` | 예 | 사용자 | 재적용(순서 역전 위험) | Modify+assertion |
| `POST /api/groups` 생성 | 예 | — | 409 `already_exists` | 단일 Add |
| `PUT`·`PATCH /api/groups` | 예 | 그룹 | 재적용 | Modify+assertion |
| `DELETE /api/groups?dn=` | 예 | 그룹 | 404 | Delete+assertion |
| `POST /api/groups/members` | 예 | 그룹 | 409 `conflict`(이미 구성원) | Modify+assertion |
| `DELETE /api/groups/members` | 예 | 그룹 | 404 `not_found`(이미 아님) | Modify+assertion |
| `POST /api/entry/move` | 예 | 이동 대상 항목 | 404(구 DN 없음) | ModifyDN+assertion |
| `POST /api/v1/backups/jobs/{kind}` | 예(#217, D216-12) | — (정책 ETag는 job 리비전 아님) | 새 job 또는 409 `backup_busy` | #217 단일 활성 |
| 그 외 쓰기(프로필·방식·백업 정책/연결·Keycloak·로그인·로그아웃) | 미적용(무시) | 기존 규칙 유지 | 기존 | 기존 |

### Error codes introduced

#218 D218-3 표가 흡수할 목록(이름은 append-only 계약, 상태·`retryable`은 D218-5 규칙을 따른다).

| code | 상태 | retryable | 발생 |
|---|---|---|---|
| `idempotency_key_conflict` | 409 | true | 같은 키·같은 요청이 처리 중(#218 예약 이름 그대로) |
| `idempotency_key_reused` | 422 | false | 같은 키에 다른 요청(method·대상·본문)(#218 예약 이름 그대로) |
| `partial_failure` | 500 | false | 사용자 생성에서 비밀번호 단계 실패 후 보상 불가(D216-5). 부분 적용 가능성이므로 D218-5의 500 규칙(false)과 일치 |
| `idempotency_outcome_unknown` | 409 | false | 쓰기 결과를 판정할 수 없음(연결 유실·패닉)이거나 영속 기록의 `key_id`에 맞는 키가 없어 지문을 검증할 수 없음. 리소스를 읽어 확인한 뒤 재시도. 같은 키는 같은 응답을 재생 |
| `idempotency_capacity` | 503 | true | 멱등 기록 상한(전역 10,000·주체당 1,000)에 도달해 새 키를 받을 수 없음. `Retry-After` 필수(D218-5의 일시적 503 규칙). 미만료 기록은 제거하지 않음 |
| `idempotency_unsupported` | 422 | false | 멱등 기능이 꺼진 배포(`UI_IDEMPOTENCY_ENABLED=false`)에서 적용 오퍼레이션에 키가 붙음. 조용히 무시하지 않음(D216-9a) |

재사용(새 코드 아님): `if_match_required`(428)·`revision_conflict`(412)(코어 CRUD의 412는 `If-Match` 불일치; **428은 이 패키지가 발생시키지 않는다**, 필수화가 없으므로), `invalid_request`(400: 키·`If-Match` 형식, 미지원 `If-Match`, `PATCH` 검증), `validation_failed`(422: 생성형 비밀번호+키), `already_exists`·`not_found`·`conflict`.

#218 `idempotency_*` 패밀리는 `idempotency_key_conflict`·`idempotency_key_reused`·`idempotency_outcome_unknown`·`idempotency_capacity`·`idempotency_unsupported` 다섯 이름으로 확정하며 추가 이름을 만들지 않는다(닫힌 집합, D218-3·D218-14). `partial_failure`는 `idempotency_*` 패밀리가 아니다. 위 네 코드의 행은 #218 `docs/changes/api-error-envelope/CHANGE.md` D218-3 표에도 함께 추가했다. 오류 봉투 **선택 키 도입**(D218-1이 허용): `state`(`"rolled_back"` | `"partial"`, 사용자 생성 오류에만), `dn`(`partial_failure`에만, 성공 시 201의 `dn`과 같은 값이라 D218-15의 DN 비노출 규칙에 대한 명시적 예외 한 건). 두 키는 #218 OpenAPI `Error` 컴포넌트에 optional로 추가한다. `error`==`message`·`requestId`·`retryable` 봉투는 그대로다.

## Change impact

| Area | Impact / evidence needed |
|---|---|
| Source / API / command | `httpapi`: 멱등 미들웨어·`If-Match` 파서·`PATCH` 핸들러 2개·응답 `etag`; `ldapclient`: assertion 제어 타입, `Modify`/`Del`/`ModifyDN` 경로에 선택 제어 인자, `entryCSN` 속성 추가, 생성 보상. `Client` 인터페이스 메서드 시그니처 변경(조건 태그 인자) → 가짜 구현체 갱신. 외부 API 가산 변경이라 설계 변경(AGENTS.md): 이 패키지가 검토 대상 |
| Dependencies / lockfiles | N/A — 표준 라이브러리(`crypto/hmac`, `crypto/sha256`, `crypto/rand`)와 이미 있는 go-ldap v3.4.14만 사용. 신규 의존성 없음 |
| Runtime / toolchain | env `UI_IDEMPOTENCY_ENABLED`(기본 false)·`UI_IDEMPOTENCY_TTL`·`UI_IDEMPOTENCY_KEY_FILE`(선택). 메모리 사용 상한 약 10,000건×≤5KiB. UI 프로세스 1개 전제. slapd는 assertion control 지원 필요(미검증, T-002) |
| CI / CD | 라이브 시나리오 `scripts/test/test-api-conditional-writes-local.py`(신규) 워크플로 한 줄, 차트 렌더 단언 `scripts/test/test-chart-idempotency-render.sh`(신규)를 `ci.yml`의 `verify-chart-schema.sh` 단계(`ci.yml:370`) 옆에 연결 |
| Release / packaging | 차트 변경: `ui.idempotency.enabled`(기본 false), 조건부 `Recreate` 확장, `NOTES.txt` 경고, 키 파일 경로 전달. 이미지 변경 없음. 릴리스 노트: 새 헤더·`PATCH`·`etag`, `PUT` 위험, 활성 스위치 |
| Generated output | `openapi.json`·`llms.txt`·`docs/api.md`; 프런트 타입(`types.ts`의 `etag?`) |
| Security / supply chain | 주체 결속 키(타 주체 키로 정보 노출 없음), 비밀 비저장·HMAC 지문, critical assertion으로 조건 우회 방지, 보상 삭제는 조건부(남의 변경 보존), CSN 정규식 검증으로 필터 주입 차단. `userPassword`는 어느 응답·기록에도 없음(`entryRedactedAttrs`, `tree.go:99-101` 유지) |
| Offline / air-gap | N/A — 외부 호출 없음 |
| Documentation / operations | `docs/api.md`, `ui/README.md`, `charts/ldapium/README.md`(단일 복제본 전제·기록 휘발·복제 한계), 운영 가이드(412 급증 시 lastbind·ppolicy 부수 쓰기 점검, `partial_failure` 복구 절차) |
| Portfolio / downstream repositories | #217(T-031이 D216-12 사용), #218(코드 3개·선택 키 2개 흡수), #215(목록 속성에 `entryCSN` 포함, GET 무헤더). 외부 API 소비자 |

## Verification plan

LDAP 와이어 코드는 AGENTS.md 원칙에 따라 단위 테스트하지 않고 순수 헬퍼만 단위 테스트한다(목킹 프레임워크 금지). 와이어 동작은 실제 slapd에서 확인한다.

| Acceptance ID | Verification method | Environment | Expected evidence |
|---|---|---|---|
| `AC-001` | 변경 전 기준선 캡처 후 통과 확인(PUT 생략 필드 삭제 포함). `api_docs_test.go:197`·`test-api-edge-codes-local.py:152`는 T-012에서 갱신하고 갱신 전후 차이를 기록 | `go test ./...`(ui/backend), UI `@fixture` e2e, `test-api-edge-codes-local.py` | 기준선·재실행 로그, 두 단언의 diff |
| `AC-002` | 단위: 항목→DTO `etag` 매핑(`ldap.NewEntry` 픽스처), `userPassword` 비노출; 라이브: 루트·일반 바인드로 `entryCSN` 가독 | `go test`; `ldapium:e2e` | 매핑 표, 두 바인드의 응답 |
| `AC-003` | 계약 표 주도 테스트(보호 라우트 × stale 태그, 가짜 클라이언트가 `assertionFailed` 반환) + 라이브(B가 수정 후 A 쓰기, `entryCSN` 불변 확인) | `go test`; `ldapium:e2e` | 라우트별 412 봉투, 변경 없음 |
| `AC-004` | 라이브: 같은 태그 동시 두 `PUT`(스레드 N회 반복) | `ldapium:e2e` | 매 회 정확히 1×204 + 1×412 |
| `AC-005` | 단위: 헤더 파서 표(형식·목록·`W/`·`*`·빈 값), CSN 정규식 퍼즈(필터 주입 시도); 라이브: assertion 지원 확인·미지원 시 거동 | `go test`(퍼즈 포함); `ldapium:e2e` | 파서 표, 지원 확인 출력 |
| `AC-006` | 단위: Merge Patch 디코드 표(없음/null/""/미지원 키/빈); 라이브: 전후 속성 비교 | `go test`; `ldapium:e2e` | 표, 전후 LDIF |
| `AC-007` | 라이브: ppm이 거부하는 비밀번호로 생성 → 항목 부재 확인 → 올바른 비밀번호로 재생성 | `ldapium:e2e`(ppm 활성) | `ldapsearch` 부재, 두 번째 201 |
| `AC-008` | 라이브: 보상 Delete 거부(생성자에게 삭제 ACL 없음)·신원 불인정(`creatorsName` 불일치)·Add와 보상 사이 항목 수정; 보상 결정은 순수 함수 단위; 같은 키 재시도 재생 | `go test`; `ldapium:e2e` | `partial_failure` 본문, 남은 항목 속성, 재생 응답 |
| `AC-009` | 라이브: 요청 전송 후 응답 폐기(소켓 종료)·같은 키 재전송 — 생성·삭제·멤버·잠금/해제 시나리오 | `ldapium:e2e`(UI 컨테이너) | 사용자 1명, 재생 헤더, 잠금 재적용 없음 |
| `AC-010` | 단위: 상태기계(삽입·충돌·재사용·타 주체)·키 검증 표; 라이브: 동시 같은 키 두 요청, 동시 다른 키 생성 | `go test`; `ldapium:e2e` | 코드별 응답, 사용자 1명 |
| `AC-011` | 단위: 지문 HMAC(비밀번호 차이→불일치, 저장 구조체에 비밀 필드 없음 리플렉션 검사), 로그 비누출; 라이브: 기록 비누출은 로그 grep | `go test`; `ldapium:e2e` | 구조체 검사, 로그 grep 0건 |
| `AC-012` | 단위: 파이프라인 순서(재생이 `If-Match`보다 먼저), 일반 4xx/5xx 기록 삭제·`partial`·`outcome_unknown` 저장; 라이브: 성공 `PUT` 재전송, `partial_failure` 재생 | `go test`; `ldapium:e2e` | 204 재생, 키 재사용 성공, partial 재생 |
| `AC-013` | 단위: 시계 주입 TTL, 상한(전역·주체당) 도달 시 새 키 503·미만료 기록 유지·모두 `in_flight`일 때, 보호 라우트 응답 본문 ≤4KiB 고정 테스트 | `go test` | 표 주도 결과 |
| `AC-014` | 문서·계약 테스트 표(#217 T-031 입력) 검토; #217 구현 시 같은 표를 통과 | 문서 리뷰 | 표, #217 PR 링크 |
| `AC-015` | 계약: 두 헤더를 붙인 `GET`/`HEAD`/`OPTIONS` 응답 불변 | `go test`(`api_docs_test.go:246` 선례) | 동일 응답 |
| `AC-016` | 봉투·코드 골든 목록 테스트, OpenAPI `Error` 컴포넌트 선택 키 | `go test` | 골든 일치 |
| `AC-017` | `TestOpenAPIMatchesRegisteredRoutes`·`TestOpenAPIOperationsAreComplete`(`api_contract_test.go:39,84`) + 신규 헤더 파라미터 존재 검사 | `go test` | 통과 로그 |
| `AC-018` | 프런트 단위/컴포넌트(키 재사용, `etag` 없음 시 헤더 생략) + Playwright e2e(다른 곳 변경 후 저장→안내, 멤버 일괄 저장) | `ui/frontend` 테스트, `ui-e2e.yml` | 테스트 로그, 스크린샷 |
| `AC-019` | EVIDENCE.md 작성(T-022); 복제 시험은 2노드 환경이 있을 때만(`scripts/test/test-wiped-node-resync.sh` 형식), 없으면 “미시험” 기록 | `ldapium:e2e`, 선택 2노드 | 결과 또는 미시험 명시 |
| `AC-020` | 단위: 비활성 시 422·`GET` 무시·`server-settings.idempotencyEnabled`; 차트: `helm template` 단언 4건(기본/활성+1/활성+2/프로필·백업 병용) | `go test`; `scripts/test/test-chart-idempotency-render.sh` | 렌더 출력의 env·strategy 값 |
| `AC-021` | 단위: 상태기계(`in_flight`는 시간으로 안 풀림), 연결 끊김 시 연산 완료 기록(컨텍스트 분리), 쓰기 중 네트워크 오류→`outcome_unknown`, 패닉→`outcome_unknown`; 라이브: 요청 중 소켓 종료 후 재시도, 동시 같은 키 | `go test`; `ldapium:e2e` | 코드별 응답, 사용자 1명 |
| `AC-022` | 단위: 보상 결정 순수 함수(신원 일치/UUID 불일치/CSN 불일치/`creatorsName` 불일치/읽기 실패); 라이브 프리미티브: 삭제·재생성한 DN에 옛 `entryUUID` assertion Delete→122, 동시 삭제·재생성 스트레스(확률적) | `go test`; `ldapium:e2e` | 122 결과, 새 항목 생존 |
| `AC-023` | 단위: 키 파일 0600·소유자 검사, 회전(`current`/`previous`)·`key_id` 선택·키 없음→불확정, 기록·로그에 키 문자열 없음; 라이브(#217 구현 시): 재시작 뒤 같은 요청 인식 | `go test`; `ldapium:e2e` | 검증 표, 로그 grep 0건 |

단위/정적(`go test`, `go vet`, OpenAPI 드리프트)과 런타임(라이브 slapd) 증거를 구분해 기록한다.

## Rollout, rollback and recovery

- Rollout sequence: ⓪ 차트 활성 스위치·키 파일 경로(T-019, 기본 꺼짐) ① T-002 라이브 스파이크(assertion 지원·`entryCSN` 가독) ② 오류 봉투(#218 Phase 1) 병합 확인 ③ assertion 제어·`etag` 노출·`If-Match`(읽기 전용 필드 추가부터) ④ `PATCH` ⑤ 생성 보상 ⑥ 멱등 미들웨어 ⑦ OpenAPI·문서 ⑧ 프런트. 각 단계는 헤더 없는 호출의 동작이 변하지 않는 상태로 병합한다. #217 T-031은 ⑥ 이후.
- Rollback trigger and procedure: 412 급증(부수 쓰기로 인한 가짜 충돌)·보상 오삭제 의심·멱등 오재생이 확인되면 해당 단계 PR을 되돌린다. 모든 변경이 가산이라 데이터 복구가 필요 없다. 보상으로 삭제된 사용자는 같은 입력으로 다시 생성한다. 멱등 기록은 프로세스 재시작으로 즉시 비워지며 그 시점에 중단돼 있던 요청의 LDAP 효과는 복구할 수 없다(문서화). 스위치를 끄면(`ui.idempotency.enabled=false`) 키 요청은 422로 거부된다.
- Data/configuration recovery: `partial_failure`가 남긴 항목은 응답의 안내대로 비밀번호를 설정하거나 `DELETE`한다. 서버 로그 `user_create_partial request_id=…`로 찾는다.
- Compatibility or migration obligations: `/api/v1`·기존 필드·상태 코드 불변. `etag`는 선택 필드, 새 오류 코드는 #218 표 append. 구/신 UI·서버 4조합이 동작해야 한다(AC-018). `PUT` 의미 불변.

## Evidence and durable synchronization

- Evidence location/format: `docs/changes/api-conditional-writes/EVIDENCE.md`(T-022에서 생성) — 명령, 이미지 태그, 실제 출력, 실패 시도 포함. `research/README.md` 규약에 따라 기회가 될 때 측정 기록.
- Tests or checks that become durable regression controls: 헤더 파서·CSN 정규식 퍼즈, 멱등 상태기계·TTL 단위 테스트, 보호 라우트 표 주도 계약 테스트, OpenAPI 드리프트, `test-api-conditional-writes-local.py`.
- Documentation to update: `docs/api.md`(ETag 절·상태 코드·한계), `openapi.json`, `llms.txt`, `ui/README.md`(env), `charts/ldapium/README.md`(휘발·단일 복제본·복제 한계), 프런트 i18n.
- ADR/evidence/portfolio records to update: ADR 1건(D216-1·2·5·6~9), #218 코드 표(3개 코드·선택 키 2개)·#217 D217-9 연결(T-031), `IMPLEMENTATION-STATUS` 항목.

### 추적 매트릭스 (REQ → AC → Task)

| REQ | AC | Task |
|---|---|---|
| `REQ-001` | `AC-001`, `AC-015` | `T-001`, `T-004`, `T-011`, `T-020` |
| `REQ-002` | `AC-002` | `T-001`, `T-011`, `T-020`, `T-021` |
| `REQ-003` | `AC-003`, `AC-004`, `AC-005` | `T-010`, `T-011`, `T-020`, `T-021` |
| `REQ-004` | `AC-003`, `AC-004`, `AC-005` | `T-002`, `T-010`, `T-021` |
| `REQ-005` | `AC-001`, `AC-006` | `T-012`, `T-020`, `T-021` |
| `REQ-006` | `AC-007`, `AC-008`, `AC-022` | `T-002`, `T-013`, `T-020`, `T-021` |
| `REQ-007` | `AC-009`, `AC-010`, `AC-013`, `AC-021` | `T-014`, `T-020`, `T-021` |
| `REQ-008` | `AC-011` | `T-014`, `T-020`, `T-021` |
| `REQ-009` | `AC-009`, `AC-012`, `AC-021` | `T-014`, `T-020`, `T-021` |
| `REQ-010` | `AC-014` | `T-003`, `T-016`, `T-033` |
| `REQ-011` | `AC-003`, `AC-008`, `AC-016` | `T-015`, `T-020`, `T-033`(#218 표 행 추가 포함) |
| `REQ-012` | `AC-001`, `AC-017` | `T-012`(기존 단언 갱신), `T-017`, `T-020`, `T-030` |
| `REQ-013` | `AC-018` | `T-018`, `T-020`, `T-021` |
| `REQ-014` | `AC-019`, `AC-022` | `T-002`, `T-021`, `T-022` |
| `REQ-015` | `AC-017`, `AC-019` | `T-030`, `T-032` |
| `REQ-016` | `AC-020` | `T-019`, `T-020`, `T-024` |
| `REQ-017` | `AC-023` | `T-014`, `T-016`, `T-019`, `T-020` |

## Review record

- Accepted scope/requirements: REQ-001–REQ-017, AC-001–AC-023, D216-1–D216-15(D216-9a·9b 포함). 유지보수자 지시로 수용, 2026-10-06.
- Material changes after acceptance and re-review: 독립 비평(Codex) 반영 개정 — ① 보상을 `entryUUID`+`entryCSN` 신원에 결속(D216-5, AC-022; Post-Read는 go-ldap Add가 응답 제어를 버려 불가) ② 처리 중 기록의 시간 만료 제거·`outcome_unknown`(D216-8, AC-021) ③ 상한 시 새 키 거부·미만료 기록 비축출(D216-9, AC-013) ④ 배포 전제 정정과 활성 스위치·차트(D216-9a, REQ-016, AC-020) ⑤ `partial_failure`·`outcome_unknown` 저장 및 “바인드 불가” 주장 삭제(D216-5·8, AC-008) ⑥ 지문 키 영속·`key_id`·회전(D216-9b, REQ-017, AC-023) ⑦ `PATCH`로 깨지는 정확 `Allow` 단언 목록(AC-001, T-012) ⑧ 오류 코드 3개 추가와 #218 표 행 추가.
- Open questions or blockers:

**해소된 질문(유지보수자 결정 반영)**

| ID | 질문 | 결정 |
|---|---|---|
| `Q1` | `If-Match` 필수화 플래그를 이 릴리스에 포함할지 | 포함하지 않는다. 이 릴리스는 옵트인만(D216-3). 필수화는 UI가 전 편집에 `If-Match`를 보낸 릴리스 이후 별도 패키지 |
| `Q2` | 생성 시 비밀번호를 단일 Add에 넣는 모드 | 후속 작업. 해싱·정책 검증 뒤에만 검토(D216-5), 이 릴리스는 두 단계 + 신원 결속 보상 |

남은 유지보수자 결정 사항은 없다. 그 외 열린 질문은 권고대로 해소했다

**검증하지 못한 사실(모두 구현 전 T-002에서 확인)**

> 갱신(Part A 스파이크·구현, 2026-10-06): 1·2·5는 확인됨, 3은 부분 확인(실패/성공 바인드·lastbind·memberOf·refint), 7·8은 구현으로 확인, 6은 2노드 실측으로 D216-1a 서술과 일치. 4·9·10·11은 미확인. 결과와 명령은 [EVIDENCE.md](EVIDENCE.md).

1. 이 이미지의 slapd가 assertion control(`1.3.6.1.1.12`)을 Modify/Delete/ModifyDN에서 지원하는지(rootDSE `supportedControl`, 실제 거동). 작성 시 Docker를 쓰지 않아 미확인.
2. 비루트 일반 바인드(및 SSO 서비스 계정)가 `entryCSN`·`entryUUID`·`creatorsName`을 읽고 필터 평가에 쓸 수 있는지(못 읽으면 보상은 항상 `partial`로 수렴). 저장소에서 이 속성들에 대한 별도 ACL은 찾지 못했다(`01-cn-config.ldif:90`은 `userPassword,shadowLastChange`만 다룸).
3. `memberof` 오버레이의 `memberOf` 갱신, ppolicy의 `pwdFailureTime`·`pwdChangedTime` 쓰기가 사용자 `entryCSN`을 바꾸는지(가짜 412 빈도).
4. 이 이미지에서 `userPassword`가 든 Add가 `olcPPolicyHashCleartext`로 해시되고 ppm 검사를 받는지(D216-5 대안의 사실 확인).
5. assertion 실패의 정확한 결과 코드(122)와 `go-ldap`이 이를 `*ldap.Error`로 돌려주는 형태.
6. 다중 provider 두 노드에서의 `If-Match` 거동(D216-1a의 서술은 AGENTS.md의 LWW 설명과 코드 읽기에 근거하며 실측하지 않음).
7. Echo의 `PATCH` 라우팅과 #230의 `Allow` 목록 자동 반영, 본문 재읽기(미들웨어 버퍼링 후 핸들러 `Bind`) 동작.
8. slapd의 RFC 4527 Post-Read 지원은 확인하지 않았다(go-ldap `Add`가 응답 제어를 노출하지 않아 어차피 쓸 수 없음, D216-5). 같은 바인드 DN의 동시 삭제·재생성이 Add와 직후 검색 사이에 끼는 경쟁은 설계상 잔여(실측 안 함).
9. 쓰기 연산 중 연결 유실이 go-ldap에서 항상 `ErrorNetwork`(200)로 나타나는지, 그리고 LDAP 호출에 연산 타임아웃이 없을 때(`dial.go`에 없음) 멈춘 호출의 거동.
10. 차트: `ui.replicaCount`·`strategy` 조합 렌더(`ui-deployment.yaml:4,12,59-63`는 읽어 확인했으나 `helm template`로 실행하지 않음), 백업 PVC 경로에 키 파일을 두는 방식(`ui.backups` 볼륨 마운트 경로 미확인).
11. `config/secrets.go`의 `loadOrGenerateSecret`을 지문 키 파일(두 키·회전)에 재사용할 수 있는지(현재 단일 값 형식).
