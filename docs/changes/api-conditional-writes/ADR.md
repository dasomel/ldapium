# ADR: 조건부 쓰기와 멱등 규약 (D216-1, 2, 5, 6-9)

- Status: `Accepted` — [CHANGE.md](CHANGE.md)의 결정을 승격한 기록이다. CHANGE.md는 2026-10-06 유지보수자 지시로 수용되었고 구현은 #235(part A), #241(part B)로 `main`에 병합되었다.
- Owner: 미지정(CHANGE.md와 같음)
- Related issue: [#216](https://github.com/dasomel/ldapium/issues/216) (문서 후속: [#252](https://github.com/dasomel/ldapium/issues/252))
- 위치 규약: 이 저장소에는 별도 ADR 디렉터리가 없다. 변경 패키지 안의 `ADR.md`로 둔다(`docs/changes/<package>/`, T-031). 근거·대안·검증 증거의 전문은 [CHANGE.md](CHANGE.md)와 [EVIDENCE.md](EVIDENCE.md)에 있고, 이 문서는 되돌리기 어려운 결정과 탈출구만 요약한다.
- 정본 계약: [docs/api.md](../../api.md)의 "ETag / If-Match", "Idempotency-Key". 운영 절차: [docs/ui-operations.md](../../ui-operations.md).

## Context

사용자·그룹 쓰기는 읽기-수정-쓰기 사이의 변경을 덮어쓸 수 있었고(`PUT`은 생략한 선택 필드를 지운다), 응답이 유실된 재시도는 요청을 두 번 실행했다. 사용자 생성은 두 개의 디렉터리 연산(Add, 비밀번호 설정)이라 두 번째가 실패하면 비밀번호 없는 항목이 남을 수 있었다. 공용 멱등 규약은 #217(백업)도 의존한다. 외부 계약(`etag`, 헤더, `PATCH`)과 디렉터리 쓰기 의미는 되돌리기 어렵다(ADR threshold: `required`).

## Decisions

### D216-1 — 리비전은 `entryCSN` 강한 ETag다

- 사용자·그룹 목록 항목의 `etag` 필드와 `GET /api/entry`의 `ETag` 헤더가 항목의 `entryCSN`(따옴표 포함)이다. 읽을 수 없으면(ACL) 생략한다. 쓰기 응답은 새 태그를 싣지 않는다(재조회).
- 이유: `entryCSN`은 모든 항목이 가진 복제 대상 속성이고 수정마다 바뀌며, 등가 비교가 가능해 assertion 필터에 그대로 들어간다. `modifyTimestamp`(1초 해상도), `entryUUID`(편집으로 안 변함), 속성 해시(읽기 선행이 필요해 경쟁 창이 생김)는 기각했다.
- 비용: 부수 쓰기도 `entryCSN`을 올려 불필요한 412와 재조회가 생긴다. 측정 결과(EVIDENCE.md (c), 이 목록이 정본): 실패한 바인드(ppolicy의 `pwdFailureTime`), 실패를 지우는 다음 성공 바인드, 비밀번호 변경, `LDAP_LASTBIND_ENABLED=true`의 성공 바인드는 올린다. `memberOf` 유지와 refint의 멤버 삭제는 올리지 않는다. 유실은 아니다.
- 보장하지 않는 것: 복제 provider 간 선형화. 조건은 쓰기를 받은 노드에서만 평가된다(노드 로컬).
- 탈출구: 가짜 충돌이 문제면 Post-Read(RFC 4527)와 속성 해시를 후속 변경으로 검토한다.

### D216-2 — 원자성은 RFC 4528 assertion control이다

- 제어 `1.3.6.1.1.12`를 critical로, 필터 `(entryCSN=<태그>)`로 Modify(`PUT`·`PATCH`·lock·unlock·멤버 추가/제거), Delete, ModifyDN에 붙인다. 태그는 CSN 정규식을 통과해야만 필터에 들어간다. 결과 122는 412 `revision_conflict`, `unavailableCriticalExtension`(12)은 500 `internal`(쓰기 없음)이다.
- 읽기-비교-쓰기 폴백은 두지 않는다(조용한 경쟁 창 방지). 비밀번호 확장 연산은 제어를 실을 수 없어 `If-Match`를 지원하지 않는다(400).
- 근거 증거: slapd 122와 12 응답을 라이브로 확인했다([EVIDENCE.md](EVIDENCE.md) (a)).
- 탈출구: 서버가 assertion을 지원하지 않으면 노드 로컬 읽기-비교-쓰기와 문서화된 경쟁 창으로 개정하고 재검토한다.

### D216-5 — 사용자 생성 보상은 신원에 묶인다

- 순서: Add(비밀번호 없이) → Add 직후 `entryUUID`·`entryCSN`·`creatorsName`을 읽어 신원을 확인 → Password Modify → 실패 시 `(&(entryUUID=u)(entryCSN=c0))` assertion Delete. `creatorsName`이 바인드 DN과 같을 때만 신원을 인정한다. 신원 읽기는 `modifiersName`과 `modifyTimestamp == createTimestamp`도 요구한다.
- 응답(구현은 CHANGE.md 초안과 다르다, [EVIDENCE.md](EVIDENCE.md) "Where Part A differs from the package text"): 삭제 성공은 별도 `state` 없이 평범한 오류 봉투이고 문구가 `user not created`로 시작한다(`state: rolled_back` 키는 없다). 삭제하지 못한 경우는 500 `partial_failure`와 `state: partial`·`unknown`·`identity_changed`와 `dn`이다(`unknown`은 보상 삭제의 응답이 유실된 경우, `identity_changed`는 신원을 증명하지 못해 비밀번호를 설정하지도 삭제하지도 않은 경우). `partial`에는 비밀번호 유무에 대한 보장을 하지 않는다.
- 이유: 삭제가 이 요청이 만든 바로 그 항목(UUID)의 직후 상태(CSN)에만 묶여 남의 항목을 지우지 않는다. RFC 4527 Post-Read는 go-ldap v3.4.14의 `Add`가 응답 제어를 버려 쓸 수 없다.
- 남는 경쟁: 신원 확인과 Password Modify 사이는 닫을 수 없다. 같은 바인드 DN을 쓰는 다른 세션의 수정은 `modifiersName`으로 구별되지 않는다.
- 탈출구: go-ldap이 Add 응답 제어를 노출하면 Post-Read로 교체한다. 단일 Add에 비밀번호를 넣는 모드는 후속이다.

### D216-6 — 멱등 규약 헤더

- `Idempotency-Key`: 헤더 하나, 16-128자, `[A-Za-z0-9._~:-]`. 위반·중복·빈 값은 400 `invalid_request`. 재생 응답에는 `Idempotent-Replayed: true`. 적용 오퍼레이션만 문서화되고 그 밖의 라우트·`GET`/`HEAD`/`OPTIONS`에서는 무시된다.
- 기능이 꺼져 있으면(D216-9a) 키가 붙은 쓰기를 조용히 무시하지 않고 422 `idempotency_unsupported`로 거부한다. 호출자가 보호받는다고 오해하지 않게 하기 위해서다.

### D216-7 — 범위와 지문

- 범위는 (요청한 신원, 키)다. 기록 키에는 DN 원문이 아니라 `SHA-256(DN‖0x00‖키)`만 쓴다. 다른 신원의 같은 키는 독립이라 존재 여부가 새지 않는다.
- 지문은 `HMAC-SHA256(fk, method‖경로 템플릿+정렬한 쿼리‖정규화한 본문)`이고 `If-Match`·`Origin`·쿠키는 넣지 않는다. 비밀번호는 HMAC 입력에는 들어가지만 저장되는 것은 HMAC 값과 `key_id`뿐이라 기록 유출로 사전 대입이 불가능하다.
- 본문은 정규화할 수 있어야 한다: 키가 붙은 요청의 본문이 64KiB를 넘거나(413이 아니라 400), 뒤따르는 데이터·잘못된 JSON·중복 필드명이 있으면 핸들러 전에 400 `invalid_request`다(리뷰 반영 D216-22).

### D216-8 — 상태기계와 재생

- 기록은 `in_flight` → `completed`다. 같은 키 + 같은 지문이 처리 중이면 409 `idempotency_key_conflict`(`retryable`), 다른 지문이면 422 `idempotency_key_reused`, 완료되었으면 최초의 상태·본문·`Location`을 재생한다. `in_flight`는 시간·연결 종료·패닉으로 지우지 않는다. 요청 컨텍스트가 취소돼도 연산은 끝까지 수행되고 결과가 기록된다.
- 결과를 판정할 수 없으면(전송 뒤 네트워크 오류, 패닉) `idempotency_outcome_unknown`을 기록하고 같은 키 재시도에 같은 응답을 재생한다. 판정은 보수적이다: 서버가 돌려준 결과 코드를 가진 타입 있는 LDAP 오류만 "적용되지 않음"의 증거이고 그 밖의 오류는 불확정이다(D216-20).
- 저장하는 결과는 2xx, `partial_failure`, `idempotency_outcome_unknown`뿐이고(본문 4KiB 이하) 그 외 4xx·일반 5xx는 기록을 지워 같은 키로 재시도할 수 있다. 요청 본문, 비밀번호, `generatedPassword`, 쿠키, 요청자 DN은 저장하지 않는다.
- 비용: LDAP 호출이 멈추면 그 키는 재시작까지 `in_flight`로 남아 같은 키 요청이 409가 된다(안전하지만 새 키가 필요).

### D216-9 — 저장소는 프로세스 메모리(단일 복제본 전제)다

- 기본 TTL 24h(`UI_IDEMPOTENCY_TTL`, 1m-7d), 전체 10,000건·신원당 1,000건. 상한에 도달하면 새 키만 503 `idempotency_capacity`(`Retry-After`)로 거부하고 만료되지 않은 기록은 어떤 이유로도 쫓아내지 않는다. 재생 보증이 곧 계약이기 때문이다.
- 활성 스위치(D216-9a): `UI_IDEMPOTENCY_ENABLED`(기본 `false`, 차트 `ui.idempotency.enabled`). 기록이 재시작·복제본 간에 유지되지 않으므로 차트는 `ui.replicaCount`가 1일 때만 `true`로 렌더하고 `strategy: Recreate`를 쓴다. 복제본이 2 이상이면 `false`로 남고 `NOTES.txt`가 경고한다. 기본 롤링 업데이트에서는 두 프로세스가 겹쳐 같은 키가 둘 다 실행될 수 있다.
- 백업 시작은 예외다. 키를 영속 job 기록에 둔다(키 해시·지문·`key_id`만, D216-16/17). 지문 키는 `UI_IDEMPOTENCY_KEY_FILE`의 배포 단위 영속 비밀에서 파생되고(D216-9b) 회전할 수 있다.
- 탈출구: 영속 저장소를 도입하면 활성 조건을 완화한다(별도 변경).

## Consequences

- 헤더 없는 호출의 동작은 변하지 않는다(`PUT`은 여전히 생략한 선택 필드를 지운다). 보호는 옵트인이며 필수화 플래그는 만들지 않았다(D216-3).
- 복제된 디렉터리에서 `If-Match`는 낙관적 보호이지 합의가 아니다: 같은 태그로 두 노드에 동시에 쓰면 둘 다 통과하고 `entryCSN` 시각 last-write-wins로 한쪽이 조용히 사라질 수 있다(AGENTS.md "Multi-provider replication").
- UI는 아직 `If-Match`·`Idempotency-Key`를 보내지 않는다(REQ-013 미완). API 소비자용이다.

## Compatibility and rollback

- 새 `etag` 필드·`ETag` 헤더·`PATCH`는 가산이다. 롤백은 커밋 revert이며 저장된 상태는 메모리 기록(재시작에 사라짐)과 백업 job 기록의 키 필드뿐이다. 옛 버전은 `backup-jobs.json`을 읽지 않는다.

## Not verified

- 요청 중 소켓 유실 뒤 같은 키 재시도, `partial_failure`를 만드는 실제 보상 거부, `ppolicy` lastbind와 `If-Match`, SSO 모드는 라이브로 확인하지 못했다([EVIDENCE.md](EVIDENCE.md) "Not verified"). close-out 감사가 제안한 후속 이슈의 범위다([CLOSE-OUT-2026-10.md](../CLOSE-OUT-2026-10.md), #216 절).
