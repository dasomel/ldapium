# Evidence (API): 커서 페이지네이션

[EVIDENCE.md](EVIDENCE.md)는 이미지·차트(`LDAP_PAGED_TOTAL_LIMIT`)의 스파이크(1절)와 리뷰 반영(2절)을 담는다. 이 파일은
API 쪽 증거다: 키셋 스캔·취소·인터리브 스파이크, 12000/50000건 라이브, 리뷰 반영(M2/L1). 모든 값은 작업 트리에서 빌드한
`l3-ldap:1`/`l3-ui:1`로 측정했다(macOS + Colima, 로컬 단일 노드). 라이브 단계는 `LDAP_PAGED_TOTAL_LIMIT`가 있는
이미지(이미지 PR)가 필요하다.

## 2. 스파이크 — 키셋 스캔·취소·인터리브 (T-002 (3)-(6), AC-007·AC-009·AC-013)

같은 12001건 디렉터리(`ou=people`), 일반 사용자는 `size.prtotal=unlimited`가 켜진 상태. 클라이언트는
go-ldap v3.4.14를 직접 쓰는 일회용 Go 프로그램(저장소에 커밋하지 않음)이고, 서버는 위 이미지.

### (3) `uid`/`cn` ORDERING 규칙 부재, `entryUUID` OR 필터

```
$ ldapsearch -x -D cn=admin,... -b ou=people,dc=example,dc=org '(uid>=bench000011990)' dn
# numResponses: 1          <- 0건: 부등호 필터가 정의되지 않음(서버 키 범위 필터 불가)
```

→ 서버측 키 범위 `(uid>last)`는 쓸 수 없고 키셋은 클라이언트에서 거른다는 CHANGE.md 전제 확인.
`(|(entryUUID=…)×100)` 전체 속성 조회는 아래 (d)에서 1.3-1.6 ms.

### (d) 키셋 스캔의 실제 비용 (12001건; 50k는 6절)

```
[d] admin phase1 keys-only scan: entries=12001 pages=25 total=71ms perPage p50=3ms max=5ms err=<nil>
[d] admin phase1 keys-only scan: entries=12001 pages=25 total=65ms perPage p50=2ms max=4ms err=<nil>
[d] admin phase1 keys-only scan: entries=12001 pages=25 total=64ms perPage p50=2ms max=5ms err=<nil>
[d] admin phase2 100-UUID OR fetch: got=100 in 1.406ms err=<nil>
[d] admin phase2 100-UUID OR fetch: got=100 in 1.604ms err=<nil>
[d] admin phase2 100-UUID OR fetch: got=100 in 1.33ms err=<nil>
[d] admin q="bench0000005" phase1 matched=100 in 7ms
[d] admin q="zzzz-nomatch" phase1 matched=0 in 6ms
[d] user  phase1 keys-only scan: entries=12001 pages=25 total=71ms perPage p50=3ms max=4ms err=<nil>
[d] user  phase1 keys-only scan: entries=12001 pages=25 total=66ms perPage p50=2ms max=4ms err=<nil>
[d] user  phase1 keys-only scan: entries=12001 pages=25 total=61ms perPage p50=2ms max=3ms err=<nil>
[d] user  phase2 100-UUID OR fetch: got=100 in 1.545ms err=<nil>
[d] user  phase2 100-UUID OR fetch: got=100 in 1.609ms err=<nil>
[d] user  phase2 100-UUID OR fetch: got=100 in 1.551ms err=<nil>
[d] user  q="bench0000005" phase1 matched=100 in 9ms
[d] user  q="zzzz-nomatch" phase1 matched=0 in 8ms
```

→ 키(uid+entryUUID)만 요청한 전체 스캔이 12001건에 약 65 ms(25페이지), phase 2의 100개 UUID 조회는 ~1.5 ms.
관리자와 일반 사용자의 차이 없음. D215-9 예산(p95 ≤ 1 s @10k)의 약 1/10.

### (e) `SearchAsync` 취소 뒤 공유 연결 · (f) 인터리브 · (g) 페이지 사이 뮤텍스 해제

```
[e] round 0: read 0 entries then cancel; next ops ok=true err1=<nil> err2=<nil> (2ms) closing=false
[e] round 1: read 1 entries then cancel; next ops ok=true err1=<nil> err2=<nil> (2ms) closing=false
[e] round 2: read 10 entries then cancel; next ops ok=true err1=<nil> err2=<nil> (1ms) closing=false
[e] round 3: read 100 entries then cancel; next ops ok=true err1=<nil> err2=<nil> (1ms) closing=false
[e] round 4: read 400 entries then cancel; next ops ok=true err1=<nil> err2=<nil> (1ms) closing=false
[e] timeout round 0: got 232 entries, resp.Err=<nil> ctx.Err=context deadline exceeded, whoami err=<nil>
[e] timeout round 1: got 103 entries, resp.Err=<nil> ctx.Err=context deadline exceeded, whoami err=<nil>
[e] timeout round 2: got 223 entries, resp.Err=<nil> ctx.Err=context deadline exceeded, whoami err=<nil>
[e] after 40 cancelled chunks: fresh full paged scan on SAME conn: entries=12001 pages=25 err=<nil> closing=false failures=0
[f1] two paged searches interleaved page-by-page on one conn: A=1000 B=500 err=B: LDAP Result Code 53 "Unwilling To Perform": paged results cookie is invalid or old
[f2] paged scan with non-paged ops between every page: entries=12001 err=<nil>
[f3] A page1=500; new full paged search B=12001 err=<nil>; then resume A's cookie: +0 err=LDAP Result Code 2 "Protocol Error": paged results cookie is invalid
[f4] 4 concurrent full paged scans on ONE conn (no app mutex): map[0:n=500 err=LDAP Result Code 53 "Unwilling To Perform": paged results cookie is invalid or old 1:n=1000 err=LDAP Result Code 53 "Unwilling To Perform": paged results cookie is invalid or old 2:n=12001 err=<nil> 3:n=500 err=LDAP Result Code 53 "Unwilling To Perform": paged results cookie is invalid or old] in 81ms
[g] per-chunk mutex: 9 parallel whoami probes during full scan: p50=7.124ms p95=7.58ms max=7.68ms
```

- **(e) 확인**: 30번의 취소(엔트리 0/1/10/100/400건 수신 후 취소)와 10번의 2 ms deadline 취소 직후에 같은
  연결로 `Search`·`WhoAmI`가 모두 성공했고, 이어서 빈 쿠키로 시작한 전체 페이지 스캔이 12001건을 정상 반환했다
  (`closing=false failures=0`). 취소된 청크의 늦은 패킷은 go-ldap가 `setError`로 기록만 하고 연결을 오염시키지
  않는다. D215-13의 전제(공유 연결 유지, 폴백 "연결 닫고 재로그인" 불필요)가 성립한다.
- **(f) 부분 반증 — 설계 보완 필요**: 페이징 **없는** 오퍼레이션(`Search`, `WhoAmI`)은 페이지 사이에 끼어도 문제없다
  (f2: 12001건 완전). 그러나 **paged search 두 개는 한 연결에서 서로를 무효화한다**: slapd는 연결당 paged-search
  상태를 하나만 가지므로 두 번째 검색이 시작되면 첫 번째의 쿠키가 죽는다(f1·f3·f4:
  `Unwilling To Perform: paged results cookie is invalid or old` / `Protocol Error: paged results cookie is invalid`).
  패키지의 `scanMu`(세션당 동시 스캔 1개) 가정은 **필요하다**는 것이 확인됐고, 추가로 레거시
  `ListUsers`/`ListGroups`/감사 로그 읽기도 같은 연결에서 paged search를 하므로 청크 사이에 끼어들면 키셋 쿠키를
  깨뜨린다. 구현 대응(D215-16): ① 세션당 단일 스캔 슬롯 `scanSem`, ② 쿠키 무효 오류를 감지하면 스캔을 처음부터
  **최대 2회 재시작**(키셋 스캔은 어차피 페이지마다 전체를 훑으므로 재시작이 값싸다), 초과 시 503 `unavailable`
  (retryable). 레거시 읽기 경로는 수정하지 않았다(범위 밖). 실제 UI는 로그인 세션마다 별도 연결을 쓰므로 이 충돌은
  **같은 세션 쿠키로 레거시 목록과 커서 목록을 동시에** 부르는 경우에만 생긴다.
- **(g) 확인**: 청크마다 뮤텍스를 잡는 구조에서 병렬 `WhoAmI` 프로브의 대기는 p50 7 ms(500건 페이지 하나분).
  서비스 단위 증거는 6절(프록시로 지연 주입).

## 3. 라이브 — 실제 이미지(`l3-ldap:1`, `l3-ui:1`)로 12000 users + 12000 groups

`scripts/test/test-api-cursor-pagination-local.py` (`LDAPIUM_COUNT=12000`, 환경: macOS + Colima, 로컬 단일 노드,
`bench-load.sh`와 같은 방식의 오프라인 `slapadd` 적재, 대소문자 혼합·`uid` 없음·`uid` 다중값/중복·비ASCII cn·`userPassword`
가진 사용자 포함). 전체 출력:

```
loaded 12000 users + 12000 groups in 62.8s
ok: admin users traversal (limit=200) -- 12001 entries == ldapsearch ground truth, 0 duplicates, strictly increasing (smallest uid, DN)
ok: admin users pages -- no userPassword / hash in 61 pages
ok: admin groups traversal (limit=200) -- 12000 entries == ldapsearch ground truth, 0 duplicates, strictly increasing (smallest cn, DN)
ok: admin groups pages -- no userPassword / hash in 60 pages
ok: non-root ldapsearch on the default config -- rc=4 (4=sizeLimitExceeded) after 10000 entries
ok: non-root legacy GET /api/users (default config) -- 200, keys {users,truncated}, 5000 entries, truncated=true (unchanged)
ok: non-root cursor mode on the default config -- 422 size_limit_exceeded, retryable=false, no users/nextCursor in the body, message names q / exempt identity / LDAP_PAGED_TOTAL_LIMIT
ok: non-root narrowed by q=user0123 -- 10 entries returned with the same identity that got 422 without q
ok: concurrent changes between pages (a)-(f) -- (a)=0; (b)=1; (c)=0; (d)=1; (e)=0; (f)=2 -- all match the documented table; every stable entry exactly once
ok: non-root users traversal, LDAP_PAGED_TOTAL_LIMIT=unlimited (limit=200) -- 12001 entries == ldapsearch ground truth, 0 duplicates, strictly increasing (smallest uid, DN)
ok: non-root groups traversal, LDAP_PAGED_TOTAL_LIMIT=unlimited (limit=200) -- 12000 entries == ldapsearch ground truth, 0 duplicates, strictly increasing (smallest cn, DN)
ok: non-root pages -- no userPassword / hash in 121 pages
ok: cursor misuse -- tamper/truncate/other resource/other q/oversized/re-login -> 400 cursor_invalid; bad limit/sort/q -> 422 validation_failed; same-session cursor still valid
ok: latency @12000 entries -- admin    users  limit=50  pages=30 p50=    72ms p95=    91ms p99=    91ms
ok: latency @12000 entries -- admin    users  limit=200 pages=30 p50=    74ms p95=   102ms p99=   105ms
ok: latency @12000 entries -- admin    groups limit=50  pages=30 p50=    71ms p95=    88ms p99=    96ms
ok: latency @12000 entries -- admin    groups limit=200 pages=30 p50=    75ms p95=    99ms p99=   101ms
ok: latency @12000 entries -- admin    users  full traversal limit=200: 12001 entries, 61 pages in 4.9s
ok: latency @12000 entries -- admin    legacy GET /api/users (5000 cap): 200 in 46ms
ok: latency @12000 entries -- non-root users  limit=50  pages=30 p50=    73ms p95=    95ms p99=    96ms
ok: latency @12000 entries -- non-root users  limit=200 pages=30 p50=    79ms p95=    99ms p99=   102ms
ok: latency @12000 entries -- non-root groups limit=50  pages=30 p50=    74ms p95=   105ms p99=   114ms
ok: latency @12000 entries -- non-root groups limit=200 pages=30 p50=    75ms p95=   112ms p99=   115ms
ok: latency @12000 entries -- non-root users  full traversal limit=200: 12001 entries, 61 pages in 4.8s
ok: latency @12000 entries -- non-root legacy GET /api/users (5000 cap): 200 in 44ms
ok: probe baseline /api/entry (LDAP read, proxy 150ms/read) -- p50=152ms max=153ms
ok: same-session probes during ONE slow cursor page (10.4s) -- /api/entry n=15 p50=710ms max=855ms; /api/me n=15 max=5ms; non-200=[] -- bounded by ~one chunk, not the page
ok: same-session probes during the LEGACY listing (5.0s) -- /api/entry n=1 p50=5146ms max=5146ms -- the legacy scan holds the connection for the whole listing (contrast)
ok: request deadline -- 503 scan_timeout after 30.0s (30s deadline + at most one in-flight chunk), no users in the body
ok: connection after a cancelled chunk -- same session: /api/entry 200 in 1576ms, then a q-narrowed cursor request 200 with 1 group(s) (SearchAsync cancellation left the shared connection healthy)
PASS: 30 checks
```

- 관리자·일반 사용자 모두 **ldapsearch 기준 집합과 시퀀스가 정확히 일치**(누락 0, 중복 0, `(키, DN)` 엄격 증가).
  비교 대상은 같은 신원의 `ldapsearch -E pr=500/noprompt` 출력을 파이썬에서 같은 전순서로 정렬한 것이다.
- 기본 설정의 일반 사용자: 레거시는 5000건 + `truncated:true`(키 집합 `{users,truncated}` 불변), 커서 모드는
  422 `size_limit_exceeded`이며 본문에 `users`/`nextCursor`가 없다(부분 페이지 없음). `q`로 좁히면 같은 신원이 성공.
- `LDAP_PAGED_TOTAL_LIMIT=unlimited`로 **기존 볼륨에서 재기동**(reconcile) 후 같은 일반 사용자가 12001/12000건을 순회.
- 동시 변경 표 (a)–(f)는 문서화된 값과 일치: (a)=0 (b)=1 (c)=0 (d)=1 (e)=0 (f)=2, 영향 없는 엔트리는 정확히 1회.
- 지연: 12000건 기준 `limit=50/200` 페이지 p50 ≈ 72-79 ms, p95 ≈ 88-112 ms, 전체 순회(61페이지) ≈ 4.8-4.9 s,
  레거시 목록 44-46 ms. D215-9 예산(p95 ≤ 1 s @10k, 10k 전체 순회 ≤ 60 s) 이내.
- 같은 세션 기아 없음(150 ms/read 지연 프록시): 느린 페이지(10.4 s) 동안 같은 세션의 `/api/entry`(LDAP 읽기)는
  p50 710 ms·max 855 ms(청크 하나 몫), `/api/me` max 5 ms. **대조**: 레거시 목록(5.0 s) 중에는 같은 읽기가 5146 ms
  (목록 전체)를 기다렸다.
- 요청 deadline: 1.5 s/read 프록시에서 503 `scan_timeout`을 **정확히 30.0 s**에 반환, 이어서 **같은 세션**의
  `/api/entry`가 200, `q`로 좁힌 커서 요청도 200 — 실제 취소된 청크 뒤에도 공유 연결이 건강하다.

### 비프로덕션 이음새(`betweenPhases`)로 두 단계 사이에 실제 변경을 가한 라이브 테스트

`go test -tags live ./internal/ldapclient/` (`page_live_test.go`), 실제 slapd에서 phase 1과 2 사이에 삭제·modrdn·
키 속성 수정·비키 속성 수정·ACL 추가(`cn=admin,cn=config`로 `olcAccess` 삽입 후 제거)·선택 전체 삭제를 수행:

```
--- PASS: TestLiveChangesBetweenPhases (0.62s)
    --- PASS: (a) selected entry deleted
    --- PASS: (b) selected entry renamed (DN changes)
    --- PASS: (c) sort key attribute modified
    --- PASS: (d) non-key attribute modified: emitted with the new value
    --- PASS: (e) hidden by an ACL change for a non-root reader
    --- PASS: (f) every selected entry deleted: empty page, cursor advances
--- PASS: TestLiveCancelledChunkLeavesConnectionHealthy       # 20/20 목록이 도중 취소, 같은 연결 정상
--- PASS: TestLiveListingSurvivesConcurrentLegacyPagedSearches  # 레거시 paged 검색과 경합 중 15/15 동일 페이지
```

(마지막 테스트는 레거시 목록을 1초 간격으로 병행한다. 쉬지 않는 레거시 검색 루프에서는 키셋 스캔이 쿠키를 계속
빼앗겨 재시작 한도(2회)를 넘어 503 `unavailable`(retryable)로 끝났다 — 잘못된 페이지는 없었다. 위험 절 참조.)

### 비공허성 증명 (깨뜨리면 테스트가 실패한다)

| 깨뜨린 것 | 결과 |
|---|---|
| `decodeCursor`의 HMAC 비교를 항상 통과시킴 | `TestCursorRejectsEveryOneByteTamper`, `…EveryTruncation`, `…Misuse`, `…KeyIsSeparatedFromTheSessionSecret` 실패 |
| 키 스캔이 `c.mu`를 청크마다가 아니라 스캔 내내 점유 | `TestListUsersPageReleasesConnectionLockBetweenChunks` 실패: `competing request got the lock after call 6 of 6 scan chunks` |
| (구현 전) 이미지에 변수 없음 | `test-paged-total-limit.sh`의 잘못된 값 케이스 FAIL (1절) |

(첫 시도의 뮤텍스 테스트는 `got < calls`로 너무 느슨해 점유를 깨뜨려도 통과했다 — 위 표의 단언으로 고쳐 다시
깨뜨려 실패를 확인했다.)

## 6. 50000 users + 50000 groups (AC-009, T-022)

같은 스크립트, `LDAPIUM_COUNT=50000 SKIP_SLOW=1` (환경: macOS + Colima, 로컬 단일 노드, 이미지 `l3-ldap:1`/`l3-ui:1`).
관리자·일반 사용자(LDAP_PAGED_TOTAL_LIMIT=unlimited) 순회가 모두 ldapsearch 기준과 정확히 일치했다.

```
loaded 50000 users + 50000 groups in 225.9s
ok: admin users traversal (limit=200) -- 50001 entries == ldapsearch ground truth, 0 duplicates, strictly increasing (smallest uid, DN)
ok: admin users pages -- no userPassword / hash in 251 pages
ok: admin groups traversal (limit=200) -- 50000 entries == ldapsearch ground truth, 0 duplicates, strictly increasing (smallest cn, DN)
ok: admin groups pages -- no userPassword / hash in 250 pages
ok: non-root ldapsearch on the default config -- rc=4 (4=sizeLimitExceeded) after 10000 entries
ok: non-root legacy GET /api/users (default config) -- 200, keys {users,truncated}, 5000 entries, truncated=true (unchanged)
ok: non-root cursor mode on the default config -- 422 size_limit_exceeded, retryable=false, no users/nextCursor in the body, message names q / exempt identity / LDAP_PAGED_TOTAL_LIMIT
ok: non-root narrowed by q=user0123 -- 10 entries returned with the same identity that got 422 without q
ok: concurrent changes between pages (a)-(f) -- (a)=0; (b)=1; (c)=0; (d)=1; (e)=0; (f)=2 -- all match the documented table; every stable entry exactly once
ok: non-root users traversal, LDAP_PAGED_TOTAL_LIMIT=unlimited (limit=200) -- 50001 entries == ldapsearch ground truth, 0 duplicates, strictly increasing (smallest uid, DN)
ok: non-root groups traversal, LDAP_PAGED_TOTAL_LIMIT=unlimited (limit=200) -- 50000 entries == ldapsearch ground truth, 0 duplicates, strictly increasing (smallest cn, DN)
ok: non-root pages -- no userPassword / hash in 501 pages
ok: cursor misuse -- tamper/truncate/other resource/other q/oversized/re-login -> 400 cursor_invalid; bad limit/sort/q -> 422 validation_failed; same-session cursor still valid
ok: latency @50000 entries -- admin    users  limit=50  pages=30 p50=   312ms p95=   456ms p99=   540ms
ok: latency @50000 entries -- admin    users  limit=200 pages=30 p50=   326ms p95=   463ms p99=   536ms
ok: latency @50000 entries -- admin    groups limit=50  pages=30 p50=   324ms p95=   393ms p99=   414ms
ok: latency @50000 entries -- admin    groups limit=200 pages=30 p50=   322ms p95=   439ms p99=   533ms
ok: latency @50000 entries -- admin    users  full traversal limit=200: 50001 entries, 251 pages in 81.9s
ok: latency @50000 entries -- admin    legacy GET /api/users (5000 cap): 200 in 45ms
ok: latency @50000 entries -- non-root users  limit=50  pages=30 p50=   307ms p95=   403ms p99=   404ms
ok: latency @50000 entries -- non-root users  limit=200 pages=30 p50=   313ms p95=   395ms p99=   400ms
ok: latency @50000 entries -- non-root groups limit=50  pages=30 p50=   305ms p95=   446ms p99=   453ms
ok: latency @50000 entries -- non-root groups limit=200 pages=30 p50=   310ms p95=   400ms p99=   404ms
ok: latency @50000 entries -- non-root users  full traversal limit=200: 50001 entries, 251 pages in 82.4s
ok: latency @50000 entries -- non-root legacy GET /api/users (5000 cap): 200 in 54ms
PASS: 25 checks
```

D215-9 예산 대조: `limit=50` 페이지 p95 ≤ 3 s @50k → 실측 p95 ≈ 0.39-0.46 s; 10k 전체 순회 ≤ 60 s → 12000건 4.8-4.9 s,
50000건 82 s(251페이지). 페이지당 O(N) 비용이 선형으로 늘어(12000건 ≈ 72 ms → 50000건 ≈ 310 ms) 예산 이내이므로
**세션 스냅샷 탈출구(D215-9a)는 채택하지 않는다**. 전체 순회 총비용 O(N^2/limit)는 문서에 명시했다.

## 7. 재실행 (rebase 후 최종 트리) (오류 봉투 #218 병합 후)

절 3의 라이브 스크립트를 `origin/main`(오류 봉투 포함)에 올린 작업 트리로 `l3-ui:1`을 다시 빌드해 12000건으로 재실행:
**PASS: 30 checks, exit=0** (관리자·일반 사용자 순회 일치, 기본 설정 422 `size_limit_exceeded`, 동시 변경 표 (a)-(f),
커서 오용, 지연, 기아 없음 — 같은 세션의 `/api/entry`는 느린 페이지(10.3 s) 동안 max 863 ms, 레거시 목록 중에는 5092 ms —
그리고 30.0 s의 503 `scan_timeout` 뒤 같은 연결의 정상 동작). 오류 본문은 이제 공통 봉투(다섯 키)이다.

## 8. 리뷰 반영 후 증거 (M2/L1)

- M2: 요청 deadline이 연결 락 대기도 끊는다. 단위 테스트(경쟁 보유자가 deadline을 넘겨 락을 쥠 → deadline에
  `scan_timeout`, 스캔 슬롯 반환, 락 누수 없음; 수정 전에는 700 ms 뒤에 반환)와 라이브(느린 레거시 목록이 연결을
  쥔 세션에서 커서 요청이 정확히 30.0 s에 503 `scan_timeout`, 이후 같은 세션이 정상): 라이브 32 checks PASS.
- L1: 토큰 안의 CR/LF/공백이 같은 MAC으로 검증되던 문제를 재인코딩 비교로 막음(수정 전 `\n` 삽입 토큰이 통과).

- 그룹 커서 페이지의 ETag: 사용자·그룹 커서 페이지 항목의 `etag`가 `GET /api/entry`의 `ETag` 헤더 및 레거시 목록과 같은 값임을
  라이브로 확인(`ETag on cursor pages`), 단위 테스트는 `entryToGroup`의 ETag를 지우면 실패한다.
