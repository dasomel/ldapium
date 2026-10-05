# Tasks: 외부 HTTP API용 머신 주체 인증 (읽기 전용)

설계: [CHANGE.md](CHANGE.md) (Status: `Proposed / awaiting review`). 모든 항목은 미착수이며, Class D 패키지 수용 전에는
`Implement` 이후 단계를 시작하지 않는다. 구현은 기본 꺼짐 상태로 단계 병합한다. LDAP ACL·`image/entrypoint.sh` 변경이 생기면
`.agents/skills/ldapium-directory-change/SKILL.md`를 먼저 로드한다.

## Inspect and establish evidence

- [ ] `T-001` (`REQ-002`, `REQ-012`) 소스 오브 트루스 확인: `openapi.json` 오퍼레이션 집계(48/보호 40 vs 요청서 39 — Q9),
      `getMonitor`·`getServerSettings`·`listPasswordPolicies` 응답 필드(비밀·민감 정보 여부), `llms.txt` 생성 방식,
      `api_contract_test.go`가 `security`를 검사하는 범위, `httpapi.New`의 SSO 초기화 실패 시 동작(기동 실패 vs 지연), `ui.sso` Helm 검증 패턴.
- [ ] `T-002` (`AC-014`) 사전 기준선: 현재 `GET /api/users`에 bearer만 보냈을 때 401 `not logged in`임을 기록, 기존 `go test ./...`·ui-e2e 결과 캡처.
- [ ] `T-003` 다운스트림·소비자 검토: API 소비자·SDK·`docs/api.md` 사용 예, 프런트가 `securitySchemes`에 의존하는지, 포트폴리오 영향.
- [ ] `T-004` (`REQ-001`, `AC-002`) 실제 Keycloak(고정 태그)에서 확인: service account 클라이언트의 access token 클레임(`aud` 기본값과 audience mapper 필요 여부,
      `azp`, `scope` 형식, 토큰 종류 claim 이름·값, `sub`), 클라이언트 비활성화 후 토큰 거동. 결과를 CHANGE.md의 “검증 필요” 항목에 반영.
- [ ] `T-005` (`REQ-001`–`REQ-014`) 수용 선행: Owner 지정, ~~Q1–Q10 결정 기록~~(2026-10-04 완료, CHANGE.md Resolved questions), ADR 초안(신규 자격 증명 수용 경로·`auth-provider-policy` 예외), security-reviewer 검토 요청.
      **수용 표시는 유지보수자만 한다.**

## Implement

수용 이후에만 착수. 순서는 병합 단위(각 단위는 기능 꺼짐 상태에서 기존 테스트 통과).

- [ ] `T-010` (`REQ-013`, `REQ-011`) `internal/config`: 머신 인증 env 파싱·검증(기본 꺼짐, 활성 시 issuer/aud/allowed clients/bind DN 필수, `MAX_TTL`·`CLOCK_SKEW` 범위, 허용 클라이언트 문법). 단위 테스트 포함.
- [ ] `T-011` (`REQ-001`, `REQ-008`, `REQ-011`) 토큰 검증기: 기존 `go-oidc` 재사용, 순수 claim 검증 함수(`iss/aud/exp/nbf/azp/토큰 종류/alg/수명 상한`)와 JWKS 재조회 최소 간격,
      미캐시 `kid`+IdP 불가 시 503. 신규 의존성 추가 금지(필요 시 Class C로 분리). 시계는 주입 가능.
- [ ] `T-012` (`REQ-002`, `REQ-003`, `REQ-006`) 인증 선택·allowlist: 순수 `selectAuth`(헤더/쿠키 → cookie|bearer|reject|none), `operation→scope` 정적 allowlist,
      client 상한 ∩ 토큰 scope 해석, 비-GET·미등록 오퍼레이션 거부, bearer 요청 `Set-Cookie` 금지, CORS 미확장. 기존 핸들러 본문은 수정하지 않는다.
- [ ] `T-013` (`REQ-004`, `REQ-008`) 머신 실행 신원: 요청별 bind 후 종료하는 임시 `Session` 주입, bind 실패 503(root 폴백 없음),
      기동 시 머신 bind DN이 `BACKUP_ADMIN_DNS`·프로파일 관리자 DN·`LDAP_SERVICE_ACCOUNT_DN`·rootdn과 같으면 실패.
- [ ] `T-014` (`REQ-003`, `REQ-012`) OpenAPI: `securitySchemes.machineBearer`, 허용 오퍼레이션 `security`+`x-machine-scope`, 전역 기본 `cookieAuth` 유지.
      계약 테스트 확장: (a) `machineBearer` 보유 집합 == 코드 allowlist, (b) denylist 31개는 `machineBearer` 부재, (c) 비-GET에는 `machineBearer` 금지. `/api/v1/meta`에 노출 필드를 추가한다면 `TestMetaExposesOnlyDiscoveryFields` 갱신(Q7: opt-in scope는 포함하되 기본 비허용으로 결정됨).
- [ ] `T-015` (`REQ-004`, `REQ-013`) 머신 LDAP 계정 운영 가이드: 읽기 전용 ACL 예시 LDIF(`userPassword`·기타 비밀 속성 접근 거부 포함)와 점검 절차.
      계정 생성은 Q2 결정대로 운영자 수동 + 문서 LDIF 예시(`image` 변경 시 로컬 Docker 규칙 준수: `ldapium:e2e` 재빌드).
- [ ] `T-016` (`REQ-013`) Helm: `ui.machineAuth.*` 값·`required` 검증·Secret 참조(차트가 비밀을 생성·출력하지 않음), `helm template` 렌더로 기본 꺼짐과 활성 시 env 확인.
- [ ] `T-017` (`REQ-009`, `REQ-014`) 감사 이벤트: 순수 `buildMachineEvent`(actor=`azp`, `sub` fingerprint, request id, operation, result, reason 코드), 허용·거부·인증 실패 모두 기록. 토큰·`Authorization` 값 비기록.
- [ ] `T-018` (`REQ-010`) 제한: client별 token bucket(주입 `now`), client별 동시 실행 상한, IP별 인증 실패 throttling(`loginLimiter` 선례), 429+`Retry-After`.

## Verify

- [ ] `T-020` (`AC-002`–`AC-006`, `AC-009`–`AC-014`) 단위/정적: `go test ./...`(ui/backend) — claim 검증기(로컬 `httptest` JWKS, 생성 키로 서명·변조),
      `selectAuth`, scope 해석, denylist 31개 전수, config 검증, 이벤트 필드, limiter, 시계 경계, 계약 테스트. 모킹 프레임워크 도입 금지.
- [ ] `T-021` (`AC-001`–`AC-009`, `AC-011`) 라이브 e2e: Keycloak+ldapium 컨테이너, LDAP/SSO 두 모드. 정상 호출 + 음성(wrong aud, 만료, 변조, ID token, SSO client 토큰, scope 부족,
      denylist, 쿠키+bearer 혼용, JWKS 중단, bind 실패, 과권한 bind의 `userPassword` 비노출, rate limit). macOS/Colima 파일 마운트 주의 사항 준수.
- [ ] `T-022` (`AC-001`–`AC-009`) CI: [keycloak-federation-e2e.yml](../../../.github/workflows/keycloak-federation-e2e.yml) 패턴의 신규 워크플로(Keycloak 정확 태그 고정, `workflow_dispatch`, concurrency 규칙 동일).
      release 필수 체크(Q8 결정) — path 필터 없음.
- [ ] `T-023` 실패·성공·환경·명령을 증거로 기록(`research/README.md` 규약, 실패 포함). 발견된 회귀 위험은 계약/단위 테스트로 승격.

## Synchronize durable truth

- [ ] `T-030` `docs/api.md`(인증 절·머신 호출 예·오류 코드), `docs/auth-provider-policy.md`(머신 인바운드 인증 예외), `docs/audit-event-schema.md`, `ui/README.md`, `charts/ldapium/README.md`, `docs/air-gap.md`, Keycloak client 설정 가이드.
- [ ] `T-031` ADR 확정·링크, `IMPLEMENTATION-STATUS.md` 갱신.
- [ ] `T-032` 릴리스 노트, 롤백(`MACHINE_AUTH_ENABLED=false`), 호환성(기존 경로·OpenAPI additive) 기록.
- [ ] `T-033` 포트폴리오/OpenForge 상태 영향 검토 및 검증 완료 후 게시.

## Completion review

- [ ] 모든 `REQ-001`–`REQ-014`가 AC와 검증 결과에 매핑됨(CHANGE.md 추적 매트릭스 갱신).
- [ ] 수용 이후 범위 변경은 패키지에 반영·재검토됨.
- [ ] 기대 증거(단위·e2e 로그, 계약 테스트)가 첨부/링크됨.
- [ ] 미완 작업(쓰기 범위, introspection, subtree allowlist, 옵션 2/3)은 소유자와 후속 이슈가 있음. 연관 이슈는 부분 PR이면 “Related to #N (not closing yet)”.
- [ ] PR이 실제 실행한 검사와 검증하지 못한 경로를 명시함.
